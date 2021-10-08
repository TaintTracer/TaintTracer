#include "Process.h"

#include <sys/wait.h>
#include <unistd.h>
#include <cstdlib>
#include <android/log.h>
#include <iosfwd>
#include <string>
#include <sstream>
#include <sys/mman.h>
#include <sys/uio.h>
#include <fstream>
#include <vector>
#include <limits>
#include <elf.h>
#include <sys/ptrace.h>
#include <capstone/capstone.h>
#include <memory>

#include <android/logging.h>
#include <iostream>
#include <fmt/format.h>
#include "arch/aarch64.h"
#include <debugger/procfs/ProcessMapsEntry.h>
#include <debugger/memory/PhysicalMemory.h>
#include <debugger/memory/VirtualAddressSpace.h>
#include <debugger/taint/TaintEvent.h>
#include "InstructionAnalyzer.h"
#include "Debugger.h"
#include "Syscall.h"
#include <ghc/filesystem.hpp>
#include <magic_enum.hpp>
#include <debugger/taint/execution/InstructionUnit.h>
#include <debugger/vex/VEXLifter.h>
#include <android/Debugging.h>
#include <debugger/files/FileDescriptorTable.h>
#include <debugger/binder/services/BinderService.h>
#include <set>
#include <linux/prctl.h>
#include "TaintpropBreakpointOptimizer.h"
#include "Config.h"
#include <linux/seccomp.h>
#include <debugger/procfs/ProcessMapState.h>

// Taken from include/linux/errno.h (v4.14.111)
#define ERESTARTSYS	512
#define ERESTARTNOINTR	513
#define ERESTARTNOHAND	514	/* restart if no handler.. */
#define ERESTART_RESTARTBLOCK 516 /* restart by calling sys_restart_syscall */

namespace fs = ghc::filesystem;

Process::Process(Debugger& debugger, pid_t pid) : Process(debugger, pid, ProcessArchitecture::UNKNOWN,
        std::make_shared<VirtualAddressSpace>(), std::make_shared<FileDescriptorTable>()) {}

Process::Process(Process &to_clone, pid_t pid, bool clone_vm, bool clone_files)
        : Process(
                to_clone.get_debugger(),
                pid,
                to_clone.arch_,
                clone_vm ? to_clone.vspace_ : std::make_shared<VirtualAddressSpace>(to_clone.get_address_space()),
                clone_files ? to_clone.fds_ : std::make_shared<FileDescriptorTable>(to_clone.get_fds())) {}

Process::Process(Debugger& debugger, pid_t pid, ProcessArchitecture arch,
                    std::shared_ptr<VirtualAddressSpace> vspace,
                    std::shared_ptr<FileDescriptorTable> fds)
        : debugger_(debugger)
        , arch_(arch)
        , pid_(pid)
        , state(ProcessState::RUNNING)
        , regs_(pid)
        , vspace_(std::move(vspace))
        , fds_(std::move(fds)) {
    vspace_->associate_process(this);
}

Process::~Process() {
    vspace_->disassociate_process(this);
}

VirtualAddressSpace& Process::get_address_space() {
    return *vspace_;
}

std::shared_ptr<VirtualAddressSpace> Process::get_address_space_owned() {
    return vspace_;
}

FileDescriptorTable &Process::get_fds() {
    return *fds_;
}

std::shared_ptr<FileDescriptorTable> Process::get_fds_owned() {
    return fds_;
}

void Process::set_fds(std::shared_ptr<FileDescriptorTable> fds) {
    fds_ = std::move(fds);
}

void Process::set_address_space(std::shared_ptr<VirtualAddressSpace> vspace) {
    if (vspace_) {
        vspace_->disassociate_process(this);
    }
    vspace->associate_process(this);
    vspace_ = std::move(vspace);
}

void Process::cont(int signal, bool stop_on_syscall, bool preserve_ssbp_status) {
    state = ProcessState::RUNNING;
    regs_.clear();
    if (!preserve_ssbp_status) {
        single_step_breakpoint_ = false;
    }
    // Clear system call state when the process is currently in a syscall-exit state
    if (current_syscall_ && current_syscall_->state == SyscallEventState::SyscallExit) {
        current_syscall_ = std::nullopt;
    }
    // TODO: mark selective interest in syscalls using SECCOMP
    auto request = (stop_on_syscall && !Config::only_handle_whitelisted_syscalls) ? PTRACE_SYSCALL : PTRACE_CONT;
    LOGV("Continuing process %d with signal %d%s", pid_, signal, request == PTRACE_SYSCALL ? " and stopping on next syscall event" : "");
    TRYSYSFATAL(ptrace(request, pid_, 0, signal));
}

void Process::single_step(int signal) {
    state = ProcessState::RUNNING;
    regs_.clear();
    single_step_breakpoint_ = true;
    TRYSYSFATAL(ptrace(PTRACE_SINGLESTEP, pid_, 0, signal));
}

std::optional<WaitEvent> Process::single_step_blocking(int signal) {
    /*
     * To differentiate between a SIGTRAP denoting successful SIGSTEP and a raised SIGTRAP signal,
     * we compare the value of the program counter pre- and post-single-step
     * We assume that a non-successful single-step will not modify the program counter, whereas the
     * a successful execution would modify the program counter.
     */
    auto pc_pre = get_registers().get_pc();
    single_step(signal);
    auto ss_event = wait_until_stopped();
    auto pc_post = get_registers().get_pc();
    LOGV("Single step:\told pc: %" PRIx64 "\tnew pc: %" PRIx64, pc_pre, pc_post);
    if (pc_pre != pc_post) {
        if (ss_event.get_event_type() != WaitEventType::STOPPED_BY_SIGNAL || ss_event.get_stop_signal() != SIGTRAP) {
            throw std::runtime_error("Assumption violated: PC moved but raised signal wasn't a SIGTRAP");
        }
        return {};
    }
    return ss_event;
}

bool Process::pop_received_sigstop() {
    auto res = received_sigstop_;
    received_sigstop_ = false;
    return res;
}

void Process::enable_received_sigstop() {
    if (received_sigstop_) {
        throw std::runtime_error("Custom interruption signal has already been enabled. Did we receive a SIGSTOP event?");
    }
    received_sigstop_ = true;
}

void Process::forward_signal(int signal) {
    if (register_taints_.get_all().empty()) {
        cont(signal);
    } else {
        // Single-step to trace signal handler
        // TODO: Assumption: registers are untouched when entering the signal handler
        single_step(signal);
    }
}

AArch64RegisterState &Process::get_registers() {
    return regs_;
}

/**
 * Detect process architecture by testing if any of its memory maps has a mapped address larger
 * than the largest possible address of 32-bit processes
 */
void Process::detect_arch() {
    // Check last memory map, as all entries are sorted by address in ascending order
    std::string last_map_s;
    last_map_s.reserve(150);
    std::ifstream maps_file("/proc/" + std::to_string(pid_) + "/maps");
    while(getline(maps_file, last_map_s)) {
        if (maps_file.peek() == EOF) break;
    };
    ProcessMapsEntry last_map(last_map_s);
    if (last_map.addr_end > std::numeric_limits<uint32_t>::max()) {
        arch_ = ProcessArchitecture::ARM64;
        LOGD("Tracee is a 64-bit process");
    } else {
        arch_ = ProcessArchitecture::ARM;
        LOGD("Tracee is a 32-bit process");
    }
}

void Process::assert_state(ProcessState expected_state) {
    if (state != expected_state) {
        throw std::runtime_error(fmt::format("Process with pid {} has unexpected process state: {} (expected {})",
                get_pid(), magic_enum::enum_name(state), magic_enum::enum_name(expected_state)));
    }
}

void Process::handle_caught_event(WaitEvent &event) {
    if (event.get_event_type() == WaitEventType::NORMAL_TERMINATION
        || event.get_event_type() == WaitEventType::KILLED_BY_SIGNAL) {
        state = ProcessState::TERMINATED;
    } else if (event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL) {
        state = ProcessState::STOPPED;

        if (event.is_syscall_trap()) {
            print_registers();
            // We can check if a restary_syscall() is performed by checking the current system call
            // number from its system call register. We use the fact that this register is different
            // from the register holding the return value of the system call.
            // Note that if the syscall register gets modified to restart_syscall, the original value
            // will not get restored after completion of the system call.
            // If porting to another architecture, you could read the result from PTRACE_GET_SYSCALL_INFO
            // (requires Linux 5.3)

            auto syscall_number = get_registers().get_syscall_number();

            if (!current_syscall_) {
                if (syscall_number == aarch64::syscall_number::restart_syscall) {
                    LOGV("Received restart_syscall without any previously executed syscall. We are probably attached to a process that was executing a system call");
                    // TODO: If Android finally has a Linux version of at least 5.3, we can PTRACE_GET_SYSCALL_INFO
                    //       try and check the actual syscall number that was resumed
                    /*
                     * If the restart_syscall() event is the first event that gets received after attaching,
                     * we don't know which system call was executed from examining the registers.
                     */
                    auto event = SyscallEvent {
                            .syscall_number = aarch64::syscall_number ::restart_syscall,
                            .state = SyscallEventState::RestartSyscallEntry,
                            .bwr_pre = std::nullopt,
                            .retval = std::nullopt,
                    };
                    auto& args = get_registers().get_syscall_args();
                    std::copy(std::begin(args), std::end(args), std::begin(event.args));
                    current_syscall_ = std::move(event);
                } else {
                    auto event = SyscallEvent{
                            .syscall_number = syscall_number,
                            .state = SyscallEventState::SyscallEntry,
                            .bwr_pre = std::nullopt,
                            .retval = std::nullopt,
                    };
                    auto &args = get_registers().get_syscall_args();
                    std::copy(std::begin(args), std::end(args), std::begin(event.args));

                    // Set binder state before syscall
                    if (syscall_number == aarch64::syscall_number::ioctl) {
                        auto binder_dev = fs::path("/dev/binder");
                        int fd = (int) args[0];
                        auto ioctl_fd = fs::path(
                                fmt::format("/proc/{}/fd/{}", this->get_pid(), fd));
                        if (fs::exists(ioctl_fd)) {
                            if (fs::equivalent(ioctl_fd, binder_dev)) {
                                uint64_t ioctl_cmd = args[1];
                                if (ioctl_cmd == BINDER_WRITE_READ) {
                                    uint64_t bwr_tracee_ptr = args[2];
                                    auto bwr_mem = read_memory(bwr_tracee_ptr,
                                                               sizeof(binder_write_read));
                                    struct binder_write_read *bwr = (binder_write_read *) bwr_mem.data();
                                    event.bwr_pre = *bwr;
                                    if (bwr->read_consumed != 0) {
                                        LOGW("bwr_pre->read_consumed = 0x%"
                                                     PRIx64, bwr->read_consumed);
                                    }
                                    if (bwr->write_consumed != 0) {
                                        LOGW("bwr_pre->write_consumed = 0x%"
                                                     PRIx64, bwr->write_consumed);
                                    }
                                }
                            }
                        }
                    }

                    auto[mem_reads, mem_writes] = aarch64::get_syscall_memory_accesses(*this,
                                                                                       event);
                    event.mem_reads = merge_regions(mem_reads);
                    event.mem_writes = merge_regions(mem_writes);

                    current_syscall_ = std::move(event);
                }
            } else {
                // State transition
                auto old_state = current_syscall_->state;
                SyscallEventState new_state;
                if (old_state == SyscallEventState::SyscallEntry && syscall_number != current_syscall_->syscall_number &&
                    current_syscall_->syscall_number != aarch64::syscall_number::rt_sigreturn) {
                    // System call register should remain constant after syscall-exit except for rt_sigreturn,
                    // which changes all registers to its original values after executing signal handler.
                    throw std::runtime_error(fmt::format(
                            "Syscall number differs between entry ({}) and exit ({}) events",
                            magic_enum::enum_name(current_syscall_->syscall_number),
                            magic_enum::enum_name(syscall_number))
                    );
                }
                if (old_state == SyscallEventState::SyscallEntry || old_state == SyscallEventState::RestartSyscallEntry) {
                    switch(syscall_errno(get_registers().get_syscall_retval())) {
                        case ERESTARTNOHAND:
                        case ERESTARTSYS:
                        case ERESTARTNOINTR:
                        case ERESTART_RESTARTBLOCK:
                            new_state = SyscallEventState::RestartSyscallExit;
                            break;
                        default:
                            new_state = SyscallEventState::SyscallExit;
                            break;
                    }
                } else if (old_state == SyscallEventState::SyscallExit) {
                    throw std::runtime_error("Unexpected state transition from SyscallExit: current_syscall_ should be nullopt");
                } else if (old_state == SyscallEventState::RestartSyscallExit) {
                    new_state = SyscallEventState::RestartSyscallEntry;
                } else {
                    throw std::logic_error("System call state is unknown");
                }
                current_syscall_->state = new_state;
                LOGD("%s", fmt::format("System call event state transition: {} -> {}", magic_enum::enum_name(old_state), magic_enum::enum_name(new_state)).c_str());
            }

            assert(current_syscall_);
            if (current_syscall_->state == SyscallEventState::SyscallExit) {
                /*
                 * rt_sigreturn() never returns.
                 * The syscall-exit event of this system call is the event where the program counter
                 * is modified after cleaning up the signal handler stack frame.
                 */
                if (current_syscall_->syscall_number == aarch64::syscall_number::rt_sigreturn) {
                    current_syscall_->retval = 0;
                } else {
                    current_syscall_->retval = get_registers().get_syscall_retval();
                }
            }
        }
    } else {
        LOGW("Irrelevant event caught...");
    }
}

WaitEvent Process::wait_until_stopped(bool allow_process_termination) {
    assert_state(ProcessState::RUNNING);
    while(true) {
        auto event = wait_for_process_events(pid_, allow_process_termination);
        if (event.get_event_type() != WaitEventType::CONTINUED_BY_SIGNAL) {
            return event;
        }
    }
}

void Process::print_stack_trace(bool only_top, bool override_config) {
    assert_state(ProcessState::STOPPED);

    if (Config::print_stack_trace || override_config) {
    } else if (Config::print_stack_trace_after_first_taint_event && Debugger::at_least_one_taint_event) {
    } else if (Config::print_stack_trace_after_first_egid_syscall && Debugger::at_least_one_egid_syscall) {
    } else {
        return;
    }

    auto map_state = ProcessMapState(get_pid());
    auto bt = get_backtrace(map_state, only_top);

    for (int i = 0; i < bt.size(); ++i) {
        const uint64_t addr = bt[i];
        auto print_line = std::ostringstream {};

        print_line << std::left << std::setw(25) << (i == 0 ? disassemble_at_pc().to_string(0) : "");
        print_line << " IP: " << std::hex << addr << "\t";

        // Find memory map that maps addr
        if (auto map_entry = map_state.find_map(addr)) {
            auto &e = *map_entry;
            auto module_offset = e.offset + (addr - (unsigned long)e.addr_start);
            print_line << fmt::format("Module: {}+{:#x}", e.path, module_offset);
            if (e.is_file && e.path.rfind(".so") != std::string::npos) { // TODO: Check if file has magic ELF header
                if (auto symname_opt = CachedELFImageLoader::get_image(e.path).get_enclosing_symbol(module_offset)) {
                    print_line << " " << *symname_opt;
                }
            }
        } else {
            print_line << "Module: UNDEFINED!";
        }
        LOGD("%s", print_line.str().c_str());
    }
}

std::vector<uint64_t> Process::get_backtrace(ProcessMapState &map_state, bool only_top) {
    assert_state(ProcessState::STOPPED);
    auto res = std::vector<uint64_t> {};

    res.push_back(regs_.get_pc());
    res.push_back(regs_[arm64_reg::ARM64_REG_LR]);

    if (!only_top) {
        if (arch_ == ProcessArchitecture::ARM64) {
            /*
             * It appears that the shadow call stack is not used by the Android framework with my
             * device configuration. We resort to standard stack unwinding as defined by the ARM
             * procedure call standard
             */
#ifdef STACKTRACE_STRATEGY_SCS
            // SCS strategy
        /*
         * We can directly read the stack trace from the shadow call stack, referenced by `x18`.
         * `x18` points to the top of the stack, ready for a new return value to be inserted at
         * `*x18`.
         * The first saved link register on the stack is the value just below the top of the stack,
         * namely `*(x18 - 8)`.
         * https://source.android.com/devices/tech/debug/shadow-call-stack
         * https://clang.llvm.org/docs/ShadowCallStack.html
         */

        constexpr uint64_t SCS_SIZE = 8 * 1024; // https://cs.android.com/android/platform/superproject/+/android10-release:bionic/libc/private/bionic_constants.h

        uint64_t scs_ref = get_registers()[arm64_reg::ARM64_REG_X18];
        uint64_t scs_base = scs_ref & ~(SCS_SIZE - 1);
        uint64_t scs_offset = scs_ref & (SCS_SIZE - 1);
        if (scs_offset % sizeof(uint64_t) != 0) {
            throw std::runtime_error("SCS register (x18) is not 8-byte aligned");
        }
        LOGD("Found %" PRIu64 " entires on the stack", scs_offset / sizeof(uint64_t));
        // TODO: Read array of return pointers
#else
            // AArch64 PCS strategy

            /*
             * We inspect the ABI for the module with path `/system/lib64/libandroid_runtime.so`
             *
             * Procedure prologue:
             *   stp	x29, x30, [sp, #-0x10]!
             *   mov	x29, sp
             *
             * Procedure epilogue:
             *   ldp	x29, x30, [sp], #0x10
             *
             * We infer the stack layout to be as follows
             *
             *             +----------------------+
             *             |                      |
             *  sp + 0x08  | Link register (x30)  |
             *             |                      |
             *             +----------------------+
             *             |                      |
             *  sp + 0x00  |  Frame pointer (x29) |
             *             |                      |
             *             +----------------------+
             *
             * TODO: It seems that this is not the case for all functions (I think the example below
             *       might be a chunked function called from android::String16::String16(char const*, unsigned long) )
             * e.g. /system/lib64/libutils.so (offset 0x121a4)
             *     ldp     x29, x30, [sp, #0x20]
             *     ldp     x20, x19, [sp, #0x10]
             */
            struct stack_header {
                uint64_t fp;
                uint64_t lr;
            } __attribute__((packed));
            static_assert(sizeof(stack_header) == 16, "Stack header alignment mismatch");

            auto top_lr = get_registers()[arm64_reg::ARM64_REG_X30];
            auto top_fp = get_registers()[arm64_reg::ARM64_REG_X29];
            auto sp = top_fp;
            auto stack_map_opt = map_state.find_map(sp);
            if (!stack_map_opt) {
                LOGD("Stopped stack traversal: stack pointer points to an invalid memory address!");
                return res;
            }
            auto stack_map = stack_map_opt.value();
            LOGV("Stack map: %s (0x%" PRIx64 "-0x%" PRIx64")", stack_map.path.c_str(), stack_map.addr_start ,stack_map.addr_end);
            bool printed_chunked_fn = false;
            while (1) {
                if (!(stack_map.addr_start <= sp && sp < stack_map.addr_end)) {
                    LOGD("Stopped stack traversal: New stack pointer points at a different memory map");
                    break;
                }
                auto stack_mem = read_memory(sp, sizeof(stack_header));
                auto header = (stack_header *) stack_mem.data();
                if (header->fp <= sp) {
                    // Stack traversal goes up
                    LOGD("Stopped stack traversal: new stack pointer doesn't go up");
                    break;
                }
                if (header->fp - sp >= 8 * 1024 * 1024) {
                    // Distance between two stack frames shouldn't exceed e.g. 8 MB
                    LOGD("Stopped stack traversal: stack frame distance exceeds 8 MB");
                    break;
                }

                res.push_back(header->lr);
                sp = header->fp;
                // if (header->lr != top_lr && !printed_chunked_fn) {
                //     // If the function doesn't call any functions, it might not store LR,FP on the stack
                //     // If we print LR, and the function does store LR,FP on the stack, we get a duplicate 2nd stack frame.
                //     res.push_back(top_lr);
                //     printed_chunked_fn = true;
                // } else {
                //     res.push_back(header->lr);
                //     sp = header->fp;
                // }
            }
#endif
        } else {
            throw std::runtime_error("Printing stack traces for this architecture is not supported");
        }
    }
    return res;
}

void Process::print_registers(bool override_config) {
    if (!override_config && !Config::print_registers) {
        return;
    }
    android_printf("Register contents:\n");
    aarch64::print_registers(get_registers().get_gp_registers());
}

void Process::print_memory(uint64_t address, uint64_t length) {
    auto m = read_memory(address, length);
    android_hexdump(m.data(), m.size(), address);
}

void Process::print_procfs_maps() {
    LOGD("Memory maps of pid %d according to procfs:", get_pid());
    std::ifstream maps_file("/proc/" + std::to_string(get_pid()) + "/maps");
    std::string map_line;
    while(getline(maps_file, map_line)) {
        LOGD("%s", map_line.c_str());
    }
}

void Process::taint_register(MemoryRegion register_region, std::optional<TaintEvent> annotation) {
    if (annotation) {
        register_taints_.insert({register_region, std::move(*annotation)});
    } else {
        register_taints_.erase(register_region);
    }
}

std::vector<std::reference_wrapper<TaintEvent>>
Process::get_register_taints(MemoryRegion register_region) {
    return register_taints_.get_annotations(register_region);
}

std::vector<MemoryRegion> Process::get_tainted_register_regions() {
    auto ann = register_taints_.get_all();
    auto res = std::vector<MemoryRegion> {};
    res.reserve(ann.size());
    for (const auto &a : ann) {
        res.emplace_back(a.get().start_address, a.get().end_address);
    }
    return res;
}

void Process::print_tainted_registers() {
    auto regs = std::ostringstream {};
    for (auto r : get_tainted_registers()) {
        regs << " " << magic_enum::enum_name(r);
    }
    if (regs.tellp() == 0) {
        regs << " None";
    }
    LOGV("Tainted registers (pid %d):%s", get_pid(), regs.str().c_str());
}

std::vector<arm64_reg> Process::get_tainted_registers() {
    auto set_res = std::set<arm64_reg> {};
    for (const auto reg_region : get_tainted_register_regions()) {
        for (const auto reg : vex_region_to_register(reg_region)) {
            set_res.insert(reg);
        }
    }
    // Set to vector
    auto res = std::vector<arm64_reg> {};
    res.reserve(set_res.size());
    for (const auto reg : set_res) {
        res.push_back(reg);
    }
    return res;
}

unsigned long Process::register_taint_count() {
    return register_taints_.size();
}

TraceeMemory Process::read_memory(MemoryRegion region) {
    return read_memory(region.start_address, region.size());
}

#define READ_STRATEGY_PTRACE
TraceeMemory Process::read_memory(uint64_t address, size_t length) {
    assert_state(ProcessState::STOPPED);
    auto wasted_space = length % sizeof(long) == 0 ? 0 : sizeof(long) - (length % sizeof(long));
    auto *buffer = new unsigned char[length + wasted_space] ;
#ifdef READ_STRATEGY_PTRACE
    for (size_t i = 0; i * sizeof(long) < length; i++) {
        long word = ptrace(PTRACE_PEEKTEXT, pid_, address + i * sizeof(long), 0);
        if (word == -1 && errno != 0) {
            delete[] buffer;
            LOGE("Failed to read memory @ 0x%" PRIx64, address + i * sizeof(long));
            TRYSYSFATAL(word);
        }
        ((long *)buffer)[i] = word;
    }

#endif
#ifdef READ_STRATEGY_RROCESS_VM_READV
    struct iovec local {
        .iov_base = buffer,
        .iov_len = length
    };
    struct iovec remote {
        .iov_base = reinterpret_cast<void*>(address),
        .iov_len = length
    };
    LOGD("Local address: %p", local.iov_base);
    LOGD("Local length: %u", local.iov_len);
    LOGD("Remote address: %p", remote.iov_base);
    LOGD("Remote length: %u", remote.iov_len);
    TRYSYSFATAL(process_vm_readv(pid_, &local, 1, &remote, 1, 0));
#endif
    return TraceeMemory(buffer, address, length);
}

std::array<unsigned char, 4> Process::read_instruction(uint64_t address) {
    auto res = std::array<unsigned char, 4>();
    auto ins_mem = read_memory(address, 4);
    std::copy(ins_mem.data(), ins_mem.data() + 4, res.begin());
    return res;
}

void Process::write_memory(uint64_t address, const unsigned char *buf, size_t length) {
    assert_state(ProcessState::STOPPED);

#if 0
    // Assertion
    auto orig_mem = read_memory(address - 64, length + 128);
#endif

    for (size_t i = 0; i * sizeof(long) < length; i++) {
        long word;
        if (length < (i + 1) * sizeof(long)) {
            // TODO: Assume endianness of debugger?
            auto last_word = read_memory(address + i * sizeof(long), sizeof(long));
            word = *((long *)last_word.data());
            auto word_c_ptr = (unsigned char *)&word;
            for(size_t j = i * sizeof(long); j < length; j++) {
                word_c_ptr[j - i * sizeof(long)] = buf[j];
            }
        } else {
            word = ((long *) buf)[i];
        }
        LOGV("Writing to target (pid %d) @ 0x%" PRIx64, pid_, address + i * sizeof(long));
        TRYSYSFATAL(ptrace(PTRACE_POKETEXT, pid_, address + i * sizeof(long), word));
    }
#if 0
    auto after_mem = read_memory(address - 64, length + 128);
    assert(std::equal(orig_mem.data(), orig_mem.data() + 64, after_mem.data()));
    assert(std::equal(after_mem.data() + 64, after_mem.data() + 64 + length, buf));
    assert(std::equal(orig_mem.data() + length + 64, orig_mem.data() + length + 128, after_mem.data() + length + 64));
#endif
}

AnalysisResult Process::analyze_instructions(uint64_t addr, size_t size) {
    TraceeMemory ins_mem = read_memory(addr, size);
    return InstructionAnalyzer::get_instance().analyze(ins_mem.data(), ins_mem.size(), addr);
}

CapstoneAnalysisResult Process::disassemble_at_pc() {
    auto pc = get_registers().get_pc();
    TraceeMemory ins_mem = read_memory(pc, aarch64::instruction_size);
    return InstructionAnalyzer::get_instance().analyze_capstone(ins_mem.data(), ins_mem.size(), pc);
}

std::vector<MemoryToTaint>
Process::propagate_taints(AnalysisResult &ins_anal, TaintpropBreakpointOptimizer &tbo) {
    if (ins_anal.size() == 0) {
        throw std::runtime_error("Unable to propagate taints when no instructions were able to be analyzed");
    }

    if (Config::print_instructions) {
        LOGV("Propagating taints for the following block of instructions:");
        ins_anal.print_instructions();
    }

    std::vector<MemoryToTaint> mem_taint {};
    auto &irsb = ins_anal.get_irsb();

    auto propagate_regs_and_mem = [&](size_t i) {
        LOGV("Number of tainted registers before instruction: %lu", register_taint_count());
        print_tainted_registers();
        auto guest_modifications = irsb.get_guest_modifications(i, [&](Int reg_offset) {
            return get_registers().read_from_vex_offset(reg_offset);
        });

        for (auto &m : guest_modifications.rw_pairs) {
            if (m.write.target == AccessTarget::Register) {
                auto cflags = MemoryRegion(OFFSET_arm64_CC_OP, OFFSET_arm64_CC_NDEP + 8);
                if (intersects(cflags, m.write.region)) {
                    LOGV("Ignoring taint propagation for conditional flags");
                    continue; // Ignore cflags
                }
            }
            // Collect taints of reads
            std::vector<TaintEvent> taint_events {};
            for (auto &r : m.reads) {
                if (r.type != AccessType::Read) {
                    throw std::runtime_error("Instruction operand expected to be a read");
                }
                if (i != 0 && r.target == AccessTarget::Memory) {
                    throw std::runtime_error(fmt::format(
                                    "Propagating taints for an instruction {} to be executed in the future that has a memory-read operand ({})",
                                    i, r.region.str()));
                }
                if (r.target == AccessTarget::Register) {
                    for (auto& taint : register_taints_.get_annotations(r.region)) {
                        taint_events.emplace_back(taint); // Copy taint
                    }
                } else if (r.target == AccessTarget::Memory) {
                    for (auto taint : get_address_space().get_memory_taints(r.region)) {
                        taint_events.emplace_back(taint.get()); // Copy taint
                    }
                }
            }

            auto event = std::optional<TaintEvent>{};
            if (!taint_events.empty()) {
                std::array<unsigned char, 4> arr;
                auto ins_bytes = ins_anal.get_machine_bytes(i);
                std::copy(ins_bytes.first, ins_bytes.first + ins_bytes.second, arr.begin());
                event.emplace(std::move(taint_events), std::make_shared<InstructionUnit>(
                        pid_, ins_anal.instruction_address(i), arr));
            }

            if (m.write.target == AccessTarget::Register) {
                taint_register(m.write.region, event);
            } else {
                if (i != 0) {
                    throw std::runtime_error("Propagating taints for an instruction to be executed in the future that has a memory-write operand");
                }
                LOGV("Marking memory region %s as %s after taint propagation is finished", m.write.region.str().c_str(), event ? "tainted" : "clean");
                mem_taint.emplace_back(event, m.write.region);
            }
        }
        LOGV("Number of tainted registers after instruction: %lu", register_taint_count());
        print_tainted_registers();
    };

    for (size_t i = 0; i < irsb.get_ins_count(); i++) {
        LOGV("Propagating taints for instruction at 0x%" PRIx64 ": %s",
                ins_anal.instruction_address(i), ins_anal.to_string(i).c_str());
        if (i == 0) {
            /*
             * As long as tainted values are present in at least 1 register, we should put breakpoints at locations
             * that may branch, so that we can analyze the new instructions whenever a new basic block is encountered.
             */
            if (ins_anal.could_jump(i)) {
                throw std::runtime_error("Branches @ pc should be handled a caller of this method");
            }
            propagate_regs_and_mem(i);
        } else if (register_taint_count() == 0) {
            /*
             * No need to propagate taint information, as we will be called on tainted memory
             * accesses via memory breakpoints
             */
            LOGV("No tainted info in regs found. Stopping taint propagation");
            break;
        } else if (ins_anal.is_syscall(i)) {
            /**
             * Tainted info in register values and memory could affect taint propagation.
             * The debugger will resume taint propagation if any register is tainted.
             */
            LOGV("Instruction is a syscall. Stopping taint propagation.");
            break;
        } else if (ins_anal.is_breakpoint(i)) {
            /**
             * Instruction is already a breakpoint. We assume that this breakpoint will not get
             * removed until we reach it.
             * TODO: This might not hold if another thread places a temporary breakpoint and gets removed
             * before this thread reaches it
             */
            LOGV("Instruction is an existing breakpoint. Stopping taint propagation.");
            break;
        } else if (ins_anal.is_memory_access(i)) {
            /*
             * Memory accesses that do not cause a breakpoint may influence taint propagation
             * after this instruction. Consider the following
             * Tainted regs: x0
             * ldr x0, [x1] // [x1] might contain untainted data, x0 should
             * mov x2, x0
             */
            if (Config::enable_taintprop_optimizer) {
                tbo.visit_bb(ins_anal.instruction_address(i));
            } else {
                LOGV("Instruction accesses memory, setting breakpoint on it");
                insert_instruction_breakpoint(ins_anal.instruction_address(i), BreakpointReason::MEMORY_ACCESS, true, true);
            }
            break;
        } else if (ins_anal.could_jump(i)) {
            // TODO: We should clean up this breakpoint if a segfault occurs before reaching this instruction
            if (Config::enable_taintprop_optimizer) {
                tbo.visit_bb(ins_anal.instruction_address(i));
            } else {
                LOGV("Instruction could jump, setting breakpoint on it");
                insert_instruction_breakpoint(ins_anal.instruction_address(i), BreakpointReason::JUMP_INSTRUCTION, true, true);
            }
            break;
        } else if (i == irsb.get_ins_count() - 1) {
            /*
             * Set breakpoint at the last instruction if we haven't set any before it and regs
             * contain tainted information.
             */
            if (Config::enable_taintprop_optimizer) {
                tbo.visit_bb(ins_anal.instruction_address(i));
            } else {
                LOGV("Instruction is the last instruction of the analyzed block, setting breakpoint on it");
                insert_instruction_breakpoint(ins_anal.instruction_address(i), BreakpointReason::END_OF_ANALYZED_INSTRUCTION_BLOCK, true, true);
            }

        } else {
            propagate_regs_and_mem(i);
        }
    }
    LOGV("Done propagating taints for the given code block");
    return mem_taint;
}

void Process::set_arch(ProcessArchitecture arch) {
    arch_ = arch;
}


std::optional<std::reference_wrapper<InstructionBreakpoint>>
Process::get_instruction_breakpoint(uint64_t vaddr) {
    if (auto mm = get_address_space().get_memory_map(vaddr, vaddr + aarch64::breakpoint_instruction.size())) {
        auto& [map, phy_region] = *mm;
        auto found_breakpoints = map.get_physical_memory().ins_breakpoints_.get_annotations(phy_region);
        if (found_breakpoints.empty()) {
            return {};
        } else if (found_breakpoints.size() == 1) {
            return *found_breakpoints.begin();
        } else {
            throw std::runtime_error("Multiple instruction breakpoints matched at a single virtual address");
        }
    } else {
        throw std::runtime_error("Unable to find memory map at the specified virtual address");
    }
    return {};
}

std::vector<std::reference_wrapper<InstructionBreakpointEntry>>
Process::get_instruction_breakpoints(uint64_t vaddr) {
    if (auto ibp_ref_opt = get_instruction_breakpoint(vaddr)) {
        return ibp_ref_opt->get().get_breakpoints(get_pid());
    }
    return {};
}

void
Process::insert_instruction_breakpoint(uint64_t vaddr, BreakpointReason reason, bool temporary_and_this_pid_only,
                                       bool remove_at_next_stop,
                                       std::optional<std::reference_wrapper<BreakpointHandler>> handler) {
    LOGV("%s", fmt::format(
            "Inserting {} breakpoint with reason {} @ {:#x}",
            temporary_and_this_pid_only ? "temporary (for this pid only)" : "permanent (for all pids)",
            magic_enum::enum_name(reason),
            vaddr).c_str());
    insert_instruction_breakpoint(
            vaddr,
            InstructionBreakpointEntry(reason, temporary_and_this_pid_only, remove_at_next_stop, handler)
    );
}

void Process::insert_instruction_breakpoint(uint64_t vaddr, InstructionBreakpointEntry entry) {
    assert_state(ProcessState::STOPPED);
    if (get_registers().get_pc() == vaddr) {
        LOGV("Breakpoint insert request @ pc will be deferred before process will continue execution");
        if (pending_pc_breakpoint_) {
            throw std::runtime_error("Tried to insert more than one breakpoint @ pc");
        }
        pending_pc_breakpoint_.emplace(std::make_pair(vaddr, entry));
        return;
    }
    if (!get_instruction_breakpoint(vaddr)) {
        // No other breakpoints found @ vaddr. Create a new InstructionBreakpoint
        // and place it to PhysicalMemory
        size_t constexpr breakpoint_size = 4;
        static_assert(breakpoint_size == sizeof(aarch64::breakpoint_instruction), "AArch64 bp size != 4");
        std::array<unsigned char, breakpoint_size> breakpoint_ins;
        switch (arch_) {
            case ProcessArchitecture::ARM64:
                // In ARMv8-A, A64 instructions have a fixed length of 32 bits and are always little-endian.
                std::copy(
                        aarch64::breakpoint_instruction.data(),
                        aarch64::breakpoint_instruction.data() + breakpoint_size,
                        std::begin(breakpoint_ins)
                );
                break;
            case ProcessArchitecture::UNKNOWN:
                throw std::runtime_error("Attempted to insert breakpoint for unknown processing architecture");
            default:
                throw std::runtime_error("NYI: instruction breakpoints for the specified instruction is not yet supported");
        }

        // Copy original instruction at vaddr from the process
        std::array<unsigned char, breakpoint_size> orig_ins;
        {
            TraceeMemory orig_ins_mem = read_memory(vaddr, breakpoint_size);
            std::copy(orig_ins_mem.data(), orig_ins_mem.data() + breakpoint_size, std::begin(orig_ins));
        }
        auto ibp = InstructionBreakpoint(orig_ins, breakpoint_ins);
        if (!toggle_ins_breakpoint(ibp, vaddr)) {
            throw std::runtime_error("Newly created breakpoint isn't enabled");
        }

        if (auto opt_map = get_address_space().get_memory_map(vaddr, vaddr + breakpoint_size)) {
            auto [ map, phy_region ] = *opt_map;
            map.get_physical_memory().ins_breakpoints_.insert(
                    AnnotatedMemoryRegion<InstructionBreakpoint>{phy_region.start_address,phy_region.end_address, std::move(ibp)},
                    [](InstructionBreakpoint &i, MemoryRegion a, MemoryRegion b) {
                        throw std::runtime_error("Unexpected call to resize/split callback function while inserting a breakpoint. Do we have overlapping breakpoints?");
                    },
                    [](InstructionBreakpoint &i, MemoryRegion a, MemoryRegion b) -> InstructionBreakpoint {
                        throw std::runtime_error("Unexpected call to resize/split callback function while inserting a breakpoint. Do we have overlapping breakpoints?");
                    });
        } else {
            throw std::runtime_error("Unable to find memory map containing the instructions to replace with a breakpoint");
        }
    }
    auto bp_opt = get_instruction_breakpoint(vaddr);
    if (!bp_opt) {
        throw std::runtime_error(fmt::format("Could not find inserted InstructionBreakpoint @ {:#x}", vaddr));
    }
    auto &bp = bp_opt->get();
    bp.add_entry(get_pid(), entry);
    assert (!bp.is_empty());
    assert (bp.should_handle(get_pid()));
    if (entry.remove_at_next_stop) {
        temporary_breakpoints_to_remove_.emplace(vaddr);
    }
}

bool Process::remove_instruction_breakpoint(uint64_t vaddr, bool temporary_and_this_pid_only) {
    if (auto opt_map = get_address_space().get_memory_map(vaddr, vaddr + aarch64::instruction_size)) {
        auto [ map, phy_region ] = *opt_map;
        auto found_breakpoints = map.get_physical_memory().ins_breakpoints_.get_annotations(phy_region);
        if (found_breakpoints.size() != 1) {
            throw std::runtime_error(fmt::format("Found {} breakpoints @ {:#x} instead of 1 during ibp removal", found_breakpoints.size(), vaddr));
        }
        auto &ibp = found_breakpoints.begin()->get();

        if (temporary_and_this_pid_only) {
            ibp.remove_temporary_entry(get_pid());
        } else {
            ibp.remove_permanent_entry();
        }

        if (ibp.is_empty()) {
            if (ibp.is_enabled()) {
                bool new_state = toggle_ins_breakpoint(ibp, vaddr);
                assert(!new_state);
            }
            map.get_physical_memory().ins_breakpoints_.erase(phy_region,
                                                             [](InstructionBreakpoint &i, MemoryRegion a, MemoryRegion b) {
                                                                 throw std::runtime_error("Unexpected call to resize/split callback function while removing a breakpoint. Do we have overlapping breakpoints?");
                                                             },
                                                             [](InstructionBreakpoint &i, MemoryRegion a, MemoryRegion b) -> InstructionBreakpoint {
                                                                 throw std::runtime_error("Unexpected call to resize/split callback function while removing a breakpoint. Do we have overlapping breakpoints?");
                                                             });
            return true;
        } else {
            return false;
        }
    } else {
        throw std::runtime_error("Unable to find memory map containing the instructions to replace with a breakpoint");
    }
}

bool Process::toggle_ins_breakpoint(InstructionBreakpoint &ibp, uint64_t vaddr) {
    LOGV("%s instruction breakpoint @ 0x%" PRIx64, ibp.is_enabled() ? "Disabling" : "Enabling", vaddr);
    assert_state(ProcessState::STOPPED);
    // Copy current instruction @ vaddr for sanity checking current breakpoint state
    auto mem = decltype(ibp.orig_ins) {};
    {
        TraceeMemory mem_ins = read_memory(vaddr, mem.size());
        std::copy(mem_ins.data(), mem_ins.data() + mem.size(), std::begin(mem));
    }
    const decltype(mem) *to_copy;
    if (ibp.is_enabled()) {
        if (!std::equal(mem.begin(), mem.end(), ibp.bp_ins.begin())) {
            throw std::runtime_error(fmt::format(
                    "Sanity check failed while toggling instruction breakpoint: current bp state is enabled but no breakpoint instruction found @ {:#x}",
                    vaddr));
        }
        to_copy = &ibp.orig_ins;
    } else {
        if (!std::equal(mem.begin(), mem.end(), ibp.orig_ins.begin())) {
            throw std::runtime_error(fmt::format(
                    "Sanity check failed while toggling instruction breakpoint: current bp state is disabled but current instruction in memory doesn't match orig_ins @ {:#x}",
                    vaddr));
        }
        to_copy = &ibp.bp_ins;
    }
    write_memory(vaddr, to_copy->data(), to_copy->size());
    return ibp.toggle_enabled();
}

// #define WRITE_SYSCALL_INS
uint64_t Process::syscall(aarch64::syscall_number number, std::initializer_list<uint64_t> args) {
    LOGV("%s", fmt::format("Executing syscall {} in context of process {}", magic_enum::enum_name(number), pid_).c_str());
    // TODO: Stop process, handle remaining events, execute this fn as callback?
    assert_state(ProcessState::STOPPED);
    int status;
    pid_t event_pid = TRYSYSFATAL(waitpid(get_pid(), &status, WNOHANG));
    if (event_pid != 0) {
        throw std::runtime_error(fmt::format("Received unexpected event {:x} for pid {} prior to syscall preparation", status, get_pid()));
    }

    const auto orig_regs = get_registers().get_gp_registers(); // Save registers
    auto orig_syscall = current_syscall_;
#ifdef WRITE_SYSCALL_INS
    auto orig_ins = std::optional<TraceeMemory> {};
#endif
    auto syscall_regs = orig_regs;
    set_syscall_entry_regs(syscall_regs, static_cast<uint64_t>(number), args); // Prepare registers for syscall
    /*
     * If the process is in syscall entry state, but we want to execute the provided system call
     * first, we make use of the fact that the process is already in this state and thus avoid
     * the need of writing a system call instruction to memory @ pc.
     * At the end of executing the current instruction, we make sure that the process is back in a
     * syscall-entry state with its original register values.
     */
    bool syscall_entry = current_syscall_ && (current_syscall_->state == SyscallEventState::SyscallEntry ||
                                              current_syscall_->state == SyscallEventState::RestartSyscallEntry);
    if (syscall_entry) {
        LOGD("Process is in an syscall-entry state with number %d", current_syscall_->syscall_number);
    } else {
        LOGD("Process is not yet in a syscall-entry state");
    }
    if (syscall_entry && (current_syscall_->state == SyscallEventState::RestartSyscallEntry ||
                          current_syscall_->state == SyscallEventState::RestartSyscallExit)) {
        // Might work, comment out check if this happens
        throw std::runtime_error("Tried to execute syscall while the process is retrying its interrupted syscall with restart_syscall");
    }
#ifndef WRITE_SYSCALL_INS
    if (!syscall_entry)
        syscall_regs.pc = get_address_space().get_syscall_instruction_address();
#endif
    get_registers().set_gp_registers(syscall_regs); // Set registers before syscall
    if (syscall_entry) {
        /*
         * If the tracee is in a syscall-entry state, updating the general purpose register that is
         * used for system calls (x8) on AArch64 does not have an effect.
         * This is because a copy of all registers, as well as an extra copy for the system call
         * number is placed on the kernel stack. Only the former copy can be modified from userspace,
         * while the latter that is used for indexing the syscall table isn't able to be modified
         * when writing to the general purpose register struct unlike the x86 arch.
         * Layout of general purpose registers on the kernel stack: https://elixir.bootlin.com/linux/v4.14.111/source/arch/arm64/include/asm/ptrace.h#L119
         * The svc handler copies x8 to a different register (wscno a.k.a. w26) that is updated
         * after resuming the tracee from the syscall-entry sleep with the pt_regs->syscallno value
         * on the kernel stack: https://elixir.bootlin.com/linux/v4.14.111/source/arch/arm64/kernel/entry.S#L941
         * From reading the AArch64-specific kernel implementation of ptrace, we see that there is
         * a ptrace option that is exposed to userspace that we can use to set the syscallno value
         * on the kernel stack to the desired value: https://elixir.bootlin.com/linux/v4.14.111/source/arch/arm64/kernel/ptrace.c#L772
         * This allows us to override the system call number during syscall-entry, which saves
         * us from having to perform multiple context switches for each encountered system call with
         * PTRACE_SYSEMU.
         */
        get_registers().set_syscall(static_cast<int>(number));
        assert(current_syscall_);
        current_syscall_->syscall_number = number;
        // TODO: Optionally update current_syscall_->args, not useful currently
    } else {
#ifdef WRITE_SYSCALL_INS
        orig_ins.emplace(read_memory(orig_regs.pc, aarch64::syscall_instruction.size())); // Save instruction @ pc
        // TODO: Stop all processes that can access the virtual address
        write_memory(
                syscall_regs.pc,
                aarch64::syscall_instruction.data(),
                aarch64::syscall_instruction.size()
        );  // Write syscall interrupt instruction
#endif
        cont(0, true, true); // Execute system call instruction
        auto event = wait_until_stopped(); // Wait until syscall entry event
        if (!event.is_syscall_trap()) {
            throw std::runtime_error(fmt::format(
                    "Event after executing svc is not a syscall trap. Received status {:#x} instead",
                    event.status_));
        }
        if (syscall_regs.pc + 4 != get_registers().get_pc()) {
            throw std::runtime_error(fmt::format(
                    "Error while executing syscall in context of tracee: pc traveled from {:#x} to {:#x} during syscall-entry",
                    orig_regs.pc, get_registers().get_pc()));
        }
        if (auto t = event.get_ptrace_event(); t != PTraceTrapEvent::NO_EVENT) {
            throw std::runtime_error(
                    fmt::format("Received ptrace trap event instead of syscall entry: {}",
                                magic_enum::enum_name(t)));
        }
        if (auto new_number = get_registers().get_syscall_number(); new_number != number) {
            if (new_number == aarch64::syscall_number::restart_syscall) {
                throw std::runtime_error(
                        "Tried to execute a system call while another system call is being executed but interrupted with SIGSTOP");
            } else {
                throw std::runtime_error(fmt::format(
                        "System call number before ({}) and after ({}) syscall-entry is different.",
                        number, new_number));
            }
        }
    }
    assert(current_syscall_);
    assert(current_syscall_->state == SyscallEventState::SyscallEntry || current_syscall_->state == SyscallEventState::RestartSyscallEntry);
    assert(get_registers().get_syscall_number() == number);
    for (auto [i, it] = std::pair(0, args.begin()); i < args.size(); i++, it++) {
        assert(*it == get_registers().get_syscall_args()[i]);
    }
    cont(0, true, true); // Execute system call
    auto event = wait_until_stopped(); // Wait until syscall exit event
    assert(event.is_syscall_trap());
    assert(current_syscall_);
    assert(current_syscall_->state == SyscallEventState::SyscallExit || current_syscall_->state == SyscallEventState::RestartSyscallExit);
    auto retval = get_registers().get_syscall_retval(); // Retrieve return value
    if (get_registers().get_syscall_number() != number) {
        print_registers(true);
        throw std::runtime_error(
                fmt::format(
                        "System call number changed after invoking system call: changed from {} to {} ({})",
                        number, get_registers().get_syscall_number(), magic_enum::enum_name(get_registers().get_syscall_number())
                )
        );
    }

    if (syscall_entry) {
        // PC doesn't increment by 4 if the initial state was syscall entry
        if (orig_regs.pc != get_registers().get_pc()) {
            throw std::runtime_error(fmt::format("Error while executing syscall in context of tracee: pc traveled from {:#x} to {:#x} during syscall-exit", orig_regs.pc, get_registers().get_pc()));
        }
        // Instruction before original program counter value must contain a system call instruction
        uint64_t syscall_pc = orig_regs.pc - 4;
        auto syscall_pc_mem = read_memory(syscall_pc, aarch64::instruction_size);
        if (!std::equal(aarch64::syscall_instruction.begin(), aarch64::syscall_instruction.end(), syscall_pc_mem.data())) {
            throw std::runtime_error("Old pc - 4 doesn't point to a system call instruction, even though we were in a syscall-enter state on entry of this function");
        }

        // Restore original registers except for program counter that points to the syscall instruction
        auto r = orig_regs;
        r.pc = syscall_pc;
        get_registers().set_gp_registers(r);

        cont(0, true, true); // Execute syscall instruction
        auto event = wait_until_stopped(); // Wait until syscall entry event
        if (!event.is_syscall_trap()) {
            throw std::runtime_error(fmt::format("Event after executing svc is not a syscall trap. Received status {:#x} instead", event.status_));
        }
        if (orig_regs.pc != get_registers().get_pc()) {
            throw std::runtime_error(fmt::format("Failed to restore instruction pointer to previous state in syscall-entry: pc traveled from {:#x} to {:#x}", orig_regs.pc, get_registers().get_pc()));
        }
        if (auto t = event.get_ptrace_event(); t != PTraceTrapEvent::NO_EVENT) {
            throw std::runtime_error(fmt::format("Received ptrace trap event instead of syscall entry: {}", magic_enum::enum_name(t)));
        }
        if (orig_regs.regs[7] != get_registers().get_gp_registers().regs[7]) {
            throw std::runtime_error("Register x7 was modified while restoring syscall entry state");
        }
        assert(current_syscall_);
        assert(current_syscall_->state == SyscallEventState::SyscallEntry || current_syscall_->state == SyscallEventState::RestartSyscallEntry);
    } else {
        if (syscall_regs.pc + 4 != get_registers().get_pc()) {
            throw std::runtime_error(fmt::format("Error while executing syscall in context of tracee: pc traveled from {:#x} to {:#x} during syscall-exit", orig_regs.pc, get_registers().get_pc()));
        }
        get_registers().set_gp_registers(orig_regs); // Restore registers
#ifdef WRITE_SYSCALL_INS
        write_memory(orig_regs.pc, orig_ins.value().data(), aarch64::syscall_instruction.size()); // Restore instruction @ ip
        // TODO: Resume processes that were stopped before writing syscall instruction
#endif
        assert(get_registers().get_pc() == orig_regs.pc);
    }
    LOGV("%s", fmt::format("Syscall returned {}, restored original pc to {:#x}", retval, get_registers().get_pc()).c_str());
    // Restore tracked syscall state
    current_syscall_ = orig_syscall;
    return retval;
}

void Process::install_seccomp_filter(std::vector<sock_filter> instructions) {
    LOGD("Installling seccomp filter for process %d", get_pid());
    assert_state(ProcessState::STOPPED);
    // Temporarily store instructions and sock_fprog on the stack of the process
    uint64_t vaddr = get_registers().get_sp();
    uint64_t ebpf_byte_len = instructions.size() * sizeof(sock_filter);
    uint64_t size = ebpf_byte_len + sizeof(sock_fprog);
    auto orig_mem = read_memory(vaddr, size);
    auto prog = sock_fprog {
        .filter = reinterpret_cast<sock_filter *>(vaddr),
        .len = static_cast<unsigned short>(instructions.size())
    };
    write_memory(vaddr, reinterpret_cast<const unsigned char *>(instructions.data()), ebpf_byte_len);
    uint64_t vaddr_fprog = vaddr + ebpf_byte_len;
    write_memory(vaddr + ebpf_byte_len, reinterpret_cast<const unsigned char *>(&prog), sizeof(sock_fprog));
    // Avoid requirement for CAP_SYS_ADMIN
    auto sys_ret = syscall(aarch64::syscall_number::prctl, {PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0});
    auto sys_err = syscall_errno(sys_ret);
    if (sys_err) {
        throw std::runtime_error("Failed to set no new privs using prctl(): " + std::string(strerror(sys_err)));
    }
    sys_ret = syscall(aarch64::syscall_number::prctl, {PR_SET_SECCOMP, SECCOMP_MODE_FILTER, vaddr_fprog, 0, 0});
    sys_err = syscall_errno(sys_ret);
    if (sys_err) {
        throw std::runtime_error("Failed to install seccomp filter using prctl(): " + std::string(strerror(sys_err)));
    }
    // Restore original memory
    write_memory(vaddr, orig_mem.data(), orig_mem.size());
}

void Process::execute_instructions(unsigned char *data, size_t size, bool restore_registers,
                                   std::optional<uint64_t> new_pc_value) {
    LOGV("%s", fmt::format("Executing instructions in context of process {}", pid_).c_str());
    assert_state(ProcessState::STOPPED);
    if (current_syscall_ && (current_syscall_->state == SyscallEventState::SyscallEntry ||
                             current_syscall_->state == SyscallEventState::RestartSyscallEntry)) {
        throw std::runtime_error("Unable to execute instructions: process is in syscall entry state");
    }
    if (size % aarch64::instruction_size != 0) {
        throw std::runtime_error("Instruction payload size is not a multiple of the size of a single instruction");
    }
    // Total number of bytes of instructions that we modify, including the trailing breakpoint
    auto total_size = size + aarch64::breakpoint_instruction.size();
    auto orig_regs = get_registers().get_gp_registers(); // Save registers
    auto orig_pc = get_registers().get_pc();
    auto orig_ins = read_memory(orig_regs.pc, total_size); // Save instruction @ pc
    write_memory(orig_pc, data, size); // Write payload
    write_memory(
            orig_pc + size,
            aarch64::breakpoint_instruction.data(),
            aarch64::breakpoint_instruction.size()); // Write breakpoint instruction

    cont(0, true, true); // Execute newly inserted instruction
    auto event = wait_until_stopped(); // Wait until breakpoint is reached
    auto new_regs = get_registers().get_gp_registers();
    if (new_regs.pc != orig_pc + size) {
        if (Config::print_instructions) {
            LOGD("Instruction dump: ");
            android_hexdump(data, total_size);
            InstructionAnalyzer::get_instance().analyze_capstone(data, total_size, orig_pc).print_instructions();
        }
        throw std::runtime_error(fmt::format(
                "Failed to completely execute {} bytes of instructions: old pc: {:#x}, new pc: {:#x} event: {:#x}",
                size, orig_pc, new_regs.pc, event.status_));
    } else if (event.get_event_type() != WaitEventType::STOPPED_BY_SIGNAL || event.get_stop_signal() != SIGTRAP) {
        throw std::runtime_error(fmt::format(
                "Program counter reached the end of the instruction payload did not receive a SIGTRAP. Received event status {:#x} instead.",
                event.status_));
    }

    /* Restore registers if requested */
    if (restore_registers) {
        if (new_pc_value) {
            orig_regs.pc = *new_pc_value;
        }
        get_registers().set_gp_registers(orig_regs);
    } else if (new_pc_value) {
        new_regs.pc = *new_pc_value;
        get_registers().set_gp_registers(new_regs);
    }
    write_memory(orig_pc, orig_ins.data(), total_size); // Restore modified instructions
}

bool Process::get_single_step_breakpoint() const {
    return single_step_breakpoint_;
}

std::string Process::get_fd_path(int fd) {
    auto procfs_path = fs::path(fmt::format("/proc/{}/fd/{}", get_pid(), fd));
    return fs::read_symlink(procfs_path); // Read symlink that points to the file
}

const std::unique_ptr<BinderTransactionCtx> &Process::get_binder_ctx() const {
    return current_binder_ctx;
}

void Process::set_binder_ctx(std::unique_ptr<BinderTransactionCtx> current_binder_tx) {
    current_binder_ctx = std::move(current_binder_tx);
}

const std::set<uint64_t> &Process::get_temporary_breakpoints_to_remove() const {
    return temporary_breakpoints_to_remove_;
}

void Process::clear_temporary_breakpoints_to_remove() {
    temporary_breakpoints_to_remove_.clear();
}

const bool Process::has_pending_pc_breakpoint() const {
    return pending_pc_breakpoint_.has_value();
}

const std::optional<std::pair<uint64_t, InstructionBreakpointEntry>> &
Process::get_and_clear_pending_pc_breakpoint() {
    auto res = pending_pc_breakpoint_;
    pending_pc_breakpoint_.reset();
    return std::move(res);
}

const bool Process::has_last_load_linked() const {
    return last_load_linked_.has_value();
}

std::pair<std::array<unsigned char, 4>, MemoryRegion> Process::get_and_clear_last_load_linked() {
    if (!last_load_linked_) {
        throw std::runtime_error("Failed to get last load linked: optional is empty");
    }
    auto res = last_load_linked_;
    last_load_linked_.reset();
    return *res;
}

void Process::set_last_load_linked(std::array<unsigned char, 4> instruction, MemoryRegion mem_access) {
    last_load_linked_.emplace(std::make_pair(std::move(instruction), std::move(mem_access)));
}

void Process::post_attach_callback() {
    if (!executed_syscall_setup_) {
        if (Config::only_handle_whitelisted_syscalls) {
            install_seccomp_filter(compile_syscall_whitelist({
                aarch64::syscall_number::ioctl
            }));
        }
        executed_syscall_setup_ = true;
    }
}

bool Process::has_syscall() const {
    return current_syscall_.has_value();
}

const SyscallEvent &Process::get_current_syscall() const {
    if (current_syscall_) {
        return *current_syscall_;
    } else {
        throw std::runtime_error("get_current_syscall() called but syscall state is nullopt");
    }
}
