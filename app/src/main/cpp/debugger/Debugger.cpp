#include "Debugger.h"

#include <android/logging.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <string>
#include <sys/wait.h>
#include <magic_enum.hpp>
#include <fmt/format.h>
#include <sched.h>
#include <fstream>
#include <sys/mman.h>
#include <sstream>
#include <debugger/procfs/Process.h>
#include "Syscall.h"
#include "InstructionAnalyzer.h"
#include "TaintpropBreakpointOptimizer.h"
#include "Config.h"
#include <debugger/memory/VirtualAddressSpace.h>
#include <debugger/memory/MergingRegionSet.h>
#include <debugger/taint/source/NativeMethodSource.h>
#include <debugger/taint/sink/NativeMethodSink.h>
#include <debugger/taint/execution/InstructionUnit.h>
#include <debugger/breakpoint/InstructionBreakpoint.h>
#include <debugger/breakpoint/BreakpointHandler.h>
#include <sys/mman.h>
#include <debugger/vex/VEXLifter.h>
#include <android/Debugging.h>
#include <ghc/filesystem.hpp>
#include <linux/android/binder.h>
#include <debugger/binder/BinderDriver.h>
#include <linux/seccomp.h>
#include <elf.h>
#include <debugger/taint/execution/SystemCallUnit.h>
#include <unordered_set>

namespace fs = ghc::filesystem;

std::string exec_sh(const char *cmd) {
    std::array<char, 128> buf;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("Failed to spawn a new shell and read stdout from it for command " + std::string(cmd));
    }
    while (fgets(buf.data(), buf.size(), pipe.get()) != nullptr) {
        result += buf.data();
    }
    return result;
}

std::string hash_procmap(pid_t pid) {
    auto out = std::istringstream(exec_sh(fmt::format("cat /proc/{}/maps | sha256sum", pid).c_str()));
    auto digest = std::string{};
    if (!(out >> digest)) {
        throw std::runtime_error("Failed to hash smap");
    }
    return digest;
}

static std::pair<std::string, uint64_t> resolve_syscall_instruction() {
    auto libc_path = std::string("/apex/com.android.runtime/lib64/bionic/libc.so");
    ELFImage libc(libc_path);
    auto ins_region = libc.get_symbol_region("syscall");
    auto libc_offset = ins_region.start_address + 0x1c;
    if (!std::equal(aarch64::syscall_instruction.begin(), aarch64::syscall_instruction.end(), (unsigned char *)(libc.mapped_image_base() + libc_offset))) {
        throw std::runtime_error("Instruction at specified library offset is not a system call");
    }
    return std::make_pair(std::move(libc_path), libc_offset);
}

Debugger::Debugger() : syscall_instruction_location(resolve_syscall_instruction()) {}

Debugger &Debugger::get_instance() {
    static Debugger d {};
    return d;
}

bool Debugger::at_least_one_taint_event = false;
bool Debugger::at_least_one_egid_syscall = false;

void Debugger::attach_root(pid_t pid) {
    root_proc = pid;
    auto ignore_taint_tracking_file = get_data_dir(get_package_name(get_uid_of_pid(pid))) + "/disable_taint_analysis";
    track_taints = !fs::exists(ignore_taint_tracking_file);
    if (!track_taints) {
        LOGI("Taint tracking is disabled: disable_taint_analysis file present at %s", ignore_taint_tracking_file.c_str());
    }
    bool is_cooperative = true; // TODO: to be passed as arg
    auto& root_proc = attach(pid, is_cooperative);
    for (auto sub_pid : get_all_user_pids(pid, false, false)) {
        std::string cmdline;
        {
            auto fs = std::ifstream(fmt::format("/proc/{}/cmdline", sub_pid));
            fs >> cmdline;
        }
        // TODO: Alternatively we can check if executable path isn't part of the app or part of ART
        if (cmdline.rfind("lldb-server") != std::string::npos) {
            LOGW("Not attaching to lldb-server");
            continue;
        } else if (cmdline.rfind("/sbin/magisk.bin") != std::string::npos) {
            LOGW("Not attaching to /sbin/magisk.bin");
            continue;
        } else if (cmdline.rfind("/sbin/su") != std::string::npos) {
            LOGW("Not attaching to /sbin/su");
            continue;
        }
        auto state = get_proc_state(sub_pid);
        if (state == 'Z') {
            LOGW("Not attaching to zombie process");
            continue;
        }

        LOGD("Process found with same uid as the target process id: %d (%s)", pid, cmdline.c_str());
        auto &p = attach(sub_pid);
        p.set_address_space(root_proc.get_address_space_owned());
        p.set_fds(root_proc.get_fds_owned());
    }
    // Import state only when all processes have been attached to and are stopped
    // to avoid missing memory maps or open file descriptors
    root_proc.get_address_space().import_maps_from_procfs();
    root_proc.get_fds().import_fds_from_procfs(root_proc.get_pid());

    // We assume that all processes share the same address space at the start
    // TODO: Find a reliable way to check whether a process shares its vspace with another
    auto map_hash = hash_procmap(pid);
    for (auto const &p : procs_) {
        auto sub_pid = p.second.get_pid();
        if (sub_pid == pid) continue;
        if (hash_procmap(sub_pid) != map_hash) { // Unreliable check
            auto msg = fmt::format("Assumption violated: initial processes do not share the same address space! Memory maps difer between pids {} and {}", pid, sub_pid);
            throw std::runtime_error(msg);
        }
    }
}

Process& Debugger::attach(pid_t pid, bool is_cooperative, bool import_mm, bool import_fd) {
    auto [ proc_iter, inserted ] = procs_.try_emplace(pid, *this, pid);
    if (!inserted) {
        throw std::runtime_error("Attaching to an already-attached process with pid " + std::to_string(pid));
    }
    auto& proc = proc_iter->second;
    LOGD("Attaching to process %d ...", pid);
    TRYSYSFATAL(ptrace(PTRACE_ATTACH, pid, 0, 0));
    LOGD("Attached. Waiting for process to be suspended");
    proc.state = ProcessState::RUNNING;
    /*
     * If the process is using trace_me, which spawns a debugger as its child process and suspends
     * itself by raising SIGSTOP on itself, we have to do the following to resume execution:
     * 1) Use PTRACE_CONT after initial attach such that the process calls SIGSTOP, which will
     *    suspend the process and notify us using waitpid
     * 2) Send the SIGCONT signal to the process, which will be handled upon resumption of the process
     * 3) Use PTRACE_CONT to wake up the process and resume execution
     * We skip step 3) in Process::attach, which allows clients to modify the process before executing
     */
    WaitEvent stop_reason = proc.wait_until_stopped();
    assert(stop_reason.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
    assert(stop_reason.get_stop_signal() == SIGSTOP); // Caused by PTRACE_ATTACH
    LOGD("Process suspended for the first time after attaching");
    TRYSYSFATAL(ptrace(PTRACE_SETOPTIONS, pid, 0, 0
                      | PTRACE_O_EXITKILL
                      | PTRACE_O_TRACESYSGOOD /* Allows us to distinguish between a SIGTRAP signal and
                                                 an a system call trap */
                      // | PTRACE_O_TRACEEXEC     // Needed to track when the pid's vspace is destroyed
                      | PTRACE_O_TRACEFORK     // Automatically trace forked processes
                      | PTRACE_O_TRACECLONE    // Automatically trace cloned processes
                      | PTRACE_O_TRACEVFORK    // Automatically trace vforked processes
                      | (Config::only_handle_whitelisted_syscalls ? PTRACE_O_TRACESECCOMP : 0)
    ));
    proc.detect_arch(); // Get architecture of process
    if (!VirtualAddressSpace::MemoryBreakpointManager::watchpoint_count_determined()) {
        VirtualAddressSpace::MemoryBreakpointManager::set_watchpoint_count(pid);
    }
    if (is_cooperative) {
        LOGD("Process is cooperative: continuing process");
        proc.cont(0, false);
        stop_reason = proc.wait_until_stopped();
        assert(stop_reason.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
        assert(stop_reason.get_stop_signal() == SIGSTOP); // Caused by process sending SIGSTOP it itself
        LOGD("Process is cooperative: Got SIGSTOP event that got raised by the process voluntarily. Sending SIGCONT...");
        syscall(__NR_tkill, pid, SIGCONT); // Must be sent before unsuspending
        LOGD("Process is cooperative: Waiting for SIGCONT event...");
        proc.cont(0, false);
        stop_reason = proc.wait_until_stopped();
        LOGV("Got event after sending SIGCONT: %d", stop_reason.status_);
        assert(stop_reason.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
        assert(stop_reason.get_stop_signal() == SIGCONT);
    } else {
        LOGD("Process is not cooperative: not sending SIGCONT to tracee");
    }
    auto ins = proc.read_instruction(proc.get_registers().get_pc());
    if (std::equal(aarch64::syscall_instruction.data(), aarch64::syscall_instruction.data() + aarch64::syscall_instruction.size(), ins.data())
        && proc.get_registers().get_syscall_number() == aarch64::syscall_number::restart_syscall) {
        LOGD("Attaching to a process in the middle of a syscall execution, which will be retried with restart_syscall");
        // post_attach_callback will be called as soon as the syscall has been executed
    } else {
        proc.post_attach_callback();
    }
    if (import_mm)
        proc.get_address_space().import_maps_from_procfs();
    if (import_fd)
        proc.get_fds().import_fds_from_procfs(proc.get_pid());
    return proc;
}

pid_t Debugger::get_root_pid() {
    return root_proc.value();
}

void Debugger::clean_and_detach() {
    LOGW("Detaching from all processes!");
    for (auto it = procs_.begin(); it != procs_.end(); it = procs_.begin()) {
        auto &proc = it->second;
        if (proc.state == ProcessState::RUNNING) {
            LOGV("Pid %d is running, so we try to stop it with SIGSTOP", proc.get_pid());
            syscall(__NR_tkill, proc.get_pid(), SIGSTOP);
            while (proc.wait_until_stopped().status_ != 0x137f) {
                proc.cont();
            }
        }
        auto &va = proc.get_address_space();
        LOGV("Removing all instruction breakpoints and memory breakpoints");
        va.remove_all_ibp_and_mm_bkpts();
        for (auto va_proc_ref : va.get_processes()) {
            // proc is now invalid at this point
            auto &va_proc = va_proc_ref.get();
            auto pid = va_proc.get_pid();
            LOGV("Detaching from pid %d", pid);
            if (va_proc.state == ProcessState::RUNNING) {
                LOGV("Pid %d is running, so we try to stop it with SIGSTOP", pid);
                syscall(__NR_tkill, pid, SIGSTOP);
                while (va_proc.wait_until_stopped().status_ != 0x137f) {
                    va_proc.cont();
                }
            }
            LOGV("Pid stopped! Sending PTRACE_DETACH");
            TRYSYSFATAL(ptrace(PTRACE_DETACH, pid, 0, 0));
            auto state = get_proc_state(pid);
            if (state == 't' /* traced */ || state == 'T' /* stopped */) {
                throw std::runtime_error(fmt::format("Process with pid {} has unexpected procfs state: {}", pid, state));
            }
            auto num_erased = procs_.erase(pid);
            if (num_erased != 1) {
                throw std::runtime_error("Failed to clean up detached process!");
            }
        }
    }
}

void Debugger::cont_all() {
    for (auto& p : procs_) {
        p.second.cont();
    }
}

void Debugger::stop_process(Process &p) {
    auto pid = p.get_pid();

    // Custom wait functions that allow events that we otherwise don't allow when calling
    // Process::wait_until_stopped
    auto wait_async = [&] () -> std::optional<WaitEvent> {
        p.assert_state(ProcessState::RUNNING);
        int status;
        pid_t event_pid = TRYSYSFATAL(waitpid(pid, &status, WNOHANG));
        if (event_pid == 0) {
            return std::nullopt;
        }
        auto event = WaitEvent(status, event_pid);
        if (event.get_event_type() == WaitEventType::KILLED_BY_SIGNAL) {
            throw std::runtime_error("Failed to stop process: received kill signal");
        } else {
            p.handle_caught_event(event);
            if (event.get_event_type() != WaitEventType::CONTINUED_BY_SIGNAL) {
                return event;
            } else {
                return std::nullopt;
            }
        }
    };

    if (pending_events_.has_event_for_pid(pid)) {
        // We infer from the presence of a pending event that a process has already been stopped
        LOGV("Process %d stopped: an event of the process is already pending", p.get_pid());
        p.assert_state(ProcessState::STOPPED);
        return;
    } else if (auto event = wait_async()) {
        // Check if the kernel has reported any new events
        LOGV("Process %d stopped: Got new event 0x%" PRIx32 " without sending custom signal", p.get_pid(), event->status_);
        pending_events_.enqueue(*event);
        return;
    } else {
        // No events in queue or internal kernel queue...
        /**
         * When the process is being traced by ptrace(), sending a SIGSTOP via tgkill() will
         * only cause the specific thread to stop instead of the entire thread group.
         * Sending kill(pid, SIGSTOP) to any member of the thread group will stop all processes, even
         * when members are traced using ptrace().
         * See `test/ptrace-test.cpp` for a test that demonstrates this.
         */
        LOGV("Trying to stop process %d: sending SIGSTOP via tgkill", p.get_pid());
        syscall(__NR_tkill, pid, SIGSTOP);
        auto new_event = p.wait_until_stopped(true);
        p.enable_received_sigstop();
        pending_events_.enqueue(new_event);
        assert(p.state == ProcessState::STOPPED);
        if (new_event.get_event_type() != WaitEventType::STOPPED_BY_SIGNAL || new_event.get_stop_signal() != SIGSTOP) {
            LOGW("%s", fmt::format(
                    "Caught event with status {:#x} instead of the interruption signal. A different event has been received in the meanwhile.",
                    new_event.status_).c_str());
        }
    }
}

void Debugger::stop_reachable_process_except(Process &proc, MemoryRegion vaddr) {
    LOGV("Stopping all processes that can access %s except for pid %d", vaddr.str().c_str(), proc.get_pid());
    auto reachable_procs = proc.get_address_space().get_mapping_processes(vaddr);
    int encountered_self = 0;
    for (auto p_ref : reachable_procs) {
        auto &p = p_ref.get();
        if (p.get_pid() == proc.get_pid()) {
            encountered_self++;
        } else {
            stop_process(p);
        }
    }
    if (encountered_self != 1) {
        throw std::runtime_error(fmt::format("Found {} instead of 1 match of the current process in VAS::get_mapping_process", encountered_self));
    }
}

std::optional<std::reference_wrapper<Process>> Debugger::get_process(pid_t pid) {
    auto it = procs_.find(pid);
    if (it == procs_.end()) {
        return {};
    }
    return it->second;
}

void Debugger::add_native_method_source(std::string image_path, std::string symbol_name,
        TaintValues taint_values) {
    if (!procs_.empty()) {
        throw std::runtime_error("NYI: Adding native methods mid-execution. Add sources before attaching for now.");
    }
    auto& image = CachedELFImageLoader::get_image(image_path);
    image_breakpoints_.emplace(std::piecewise_construct,
            std::forward_as_tuple(image_path),
            std::forward_as_tuple(std::make_unique<NativeMethodSource> (
                    image, symbol_name, taint_values))
    );
}

void Debugger::add_native_method_sink(std::string image_path, std::string symbol_name,
                                      TaintValues taint_values) {
    if (!procs_.empty()) {
        throw std::runtime_error("NYI: Adding native methods mid-execution. Add sinks before attaching for now.");
    }
    auto& image = CachedELFImageLoader::get_image(image_path);
    image_breakpoints_.emplace(std::piecewise_construct,
                               std::forward_as_tuple(image_path),
                               std::forward_as_tuple(std::make_unique<NativeMethodSink> (
                                       image, symbol_name, taint_values))
    );
}

std::vector<std::reference_wrapper<ImageBreakpoints>>
Debugger::get_image_breakpoints(const std::string &image_path) {
    auto res = std::vector<std::reference_wrapper<ImageBreakpoints>> {};
    auto range = image_breakpoints_.equal_range(image_path);
    for (auto it = range.first; it != range.second; it++) {
        res.emplace_back(*it->second);
    }
    return res;
}

TaintEvent& Debugger::add_data_leak(TaintEvent sink_event) {
    return data_leaks_.emplace_back(std::move(sink_event));
}

const std::list<TaintEvent> &Debugger::get_data_leaks() {
    return data_leaks_;
}

WaitEvent Debugger::wait_for_event() {
    auto pid_opt = priority_process_;
    if (pid_opt) {
        LOGV("Waiting for events of priority process with pid %d", *pid_opt);
    } else {
        LOGV("Waiting for events of any traced process");
    }
    if (auto event_opt = pending_events_.dequeue(pid_opt)) {
        return *event_opt;
    } else {
        // Wait for events of priority process if any, otherwise wait for event
        return wait_for_process_events(pid_opt ? *pid_opt : -1, true);
    }
}

void Debugger::handle_event(WaitEvent event) {
    auto event_type = event.get_event_type();
    auto pid = event.get_pid();
    LOGV("Event received of pid %d with status %#08x", pid, event.status_);
    if (Config::print_waiting_procs) {
        auto pending_pids = std::vector<pid_t> {};
        for (const auto &traced_proc : procs_) {
            auto pending_pid = traced_proc.first;
            if (pid != pending_pid && get_proc_state(pending_pid) == 't') {
                pending_pids.push_back(pending_pid);
            }
        }
        if (!pending_pids.empty()) {
            LOGD("Other pending pids waiting to be handled: %s", fmt::format("{}", fmt::join(pending_pids, ", ")).c_str());
        }
    }
    auto process_opt = get_process(pid);
    /*
     * Creation of new processes (via e.g. clone()) makes sure that the created process is traced,
     * and thus inserted in the process list.
     */
    if (!process_opt) {
        throw std::runtime_error("Event received of an unknown process!");
    }
    auto& proc = process_opt->get();

    if (event_type == WaitEventType::NORMAL_TERMINATION) {
        LOGD("Process with pid %d terminated itself with exit code %d", pid, event.get_exit_code());
        if (procs_.erase(pid) != 1) {
            throw std::runtime_error("Unable to free resources of terminated process");
        };
    } else if (event_type == WaitEventType::KILLED_BY_SIGNAL) {
        LOGD("Process with pid %d killed with signal %d", pid, event.get_killed_signal());
        if (procs_.erase(pid) != 1) {
            throw std::runtime_error("Unable to free resources of killed process");
        };
    } else if (event_type == WaitEventType::CONTINUED_BY_SIGNAL) {
        LOGD("Process with pid %d resumed by delivery of SIGCONT", pid);
    } else if (event_type == WaitEventType::STOPPED_BY_SIGNAL) {
        proc.state = ProcessState::STOPPED;
        LOGD("Process stopped @ 0x%" PRIx64, proc.get_registers().get_pc());
        if (event.is_syscall_trap()) {
            auto syscall_event = proc.get_current_syscall();
            auto syscall_name = magic_enum::enum_name(syscall_event.syscall_number);
            if (syscall_event.state == SyscallEventState::RestartSyscallEntry ||
                syscall_event.state == SyscallEventState::RestartSyscallExit) {
                LOGD("Continuing process that will execute restart_syscall()");
                proc.cont();
                return;
            } else {
                proc.post_attach_callback();
            }
            if (syscall_event.syscall_number == aarch64::syscall_number::exit) {
                assert(syscall_event.state == SyscallEventState::SyscallEntry);
                LOGD("Process called exit(): %s (pid %d)", get_comm(pid).c_str(), pid);
            } else if (syscall_event.syscall_number == aarch64::syscall_number::exit_group) {
                assert(syscall_event.state == SyscallEventState::SyscallEntry);
                LOGD("Process called exit_group(): %s (pid %d)", get_comm(pid).c_str(), pid);
            } else {
                proc.print_stack_trace();
            }
            if (syscall_event.state == SyscallEventState::SyscallEntry) {
                LOGD("System call entry (pid %d): %.*s (syscallno: %d)", pid, (int)syscall_name.size(), syscall_name.data(), syscall_event.syscall_number);
                /*
                 * Handle process creation events before executing the system call.
                 * We wait for the process to raise a SIGSTOP (as requested by PTRACE_O_TRACECLONE
                 * and its variants) in a deterministic order to avoid unpredictable ordering of
                 *  - System call exit event
                 *  - SIGSTOP event of the created child process
                 */
                // On AArch64, there is no fork() or vfork(), they are all special cases of clone()
                if (syscall_event.syscall_number == aarch64::syscall_number::clone) {
                    auto& args = syscall_event.args;
                    /*
                     * Flags of clone() system call are passed via the first system call register,
                     * even though libc's clone() method passes the flags via the third register.
                     * sys_clone handler: https://elixir.bootlin.com/linux/v4.14.111/source/kernel/fork.c#L2146
                     * __bionic_clone: https://android.googlesource.com/platform/bionic/+/011e111/libc/arch-arm64/bionic/__bionic_clone.S
                     */
                    auto flags = (int)args[0];
                    PTraceTrapEvent expected_event;
                    if (flags & CLONE_VFORK) {
                        expected_event = PTraceTrapEvent::VFORK;
                        LOGD("clone() called with type VFORK");
                    } else if ((flags & CSIGNAL) != SIGCHLD) {
                        expected_event = PTraceTrapEvent::CLONE;
                        LOGD("clone() called with type CLONE");
                    } else {
                        expected_event = PTraceTrapEvent::FORK;
                        LOGD("clone() called with type FORK");
                    }
                    // Wait for PTRACE_EVENT_CLONE/VFORK/FORK event
                    proc.cont();
                    event = wait_for_process_events(proc.get_pid());
                    if (event.get_ptrace_event() != expected_event) {
                        throw std::runtime_error(
                                fmt::format(
                                        "Expected PTRACE_EVENT_CLONE or PTRACE_EVENT_VFORK but received status {:#x} instead",
                                        event.status_)
                        );
                    }

                    // A new child process has been created
                    pid_t child_pid;
                    TRYSYSFATAL(ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid));
                    Process *child_proc;
                    LOGD("Cloned process %d -> %d with %s vspace and %s file descriptors", proc.get_pid(), child_pid, (flags & CLONE_VM) ? "shared" : "copied", (flags & CLONE_FILES) ? "shared" : "copied");
                    auto [ proc_iter, inserted ] = procs_.try_emplace(child_pid, proc, child_pid, CLONE_VM & flags, CLONE_FILES & flags);
                    if (!inserted) {
                        throw std::runtime_error("Child process with pid " + std::to_string(child_pid) + " already exists");
                    }
                    child_proc = &proc_iter->second;

                    // Wait for the process to spawn and raise SIGSTOP
                    auto child_event = wait_for_process_events(child_pid);
                    if (child_event.get_event_type() != WaitEventType::STOPPED_BY_SIGNAL ||
                        child_event.get_stop_signal() != SIGSTOP) {
                        throw std::runtime_error(
                                fmt::format(
                                        "Expected SIGSTOP event of child but received status {:#x} instead",
                                        child_event.status_)
                        );
                    }
                    child_proc->cont();
                    // We already obtained the process id of the cloned process, so we don't
                    // need to handle sycall-exit event to get result of clone()
                } else if (syscall_event.syscall_number == aarch64::syscall_number::clone3) {
                    throw std::runtime_error("NYI: clone3()");
                } else if (syscall_event.syscall_number == aarch64::syscall_number::mremap) {
                    auto old_address = syscall_event.args[0];
                    auto old_size = syscall_event.args[1];

                    if (old_size == 0) {
                        throw std::runtime_error("NYI: old_size == 0");
                        // Check if first page contains breakpoint, if so, temporarily remove it,
                        // execute the syscall, restore permissions (old region still valid).
                        // Otherwise, the entire new region would have flag PROT_NONE.
                    } else {
                        auto old_region = MemoryRegion::from_start_and_size(old_address, old_size);
                        // mremap() expects the region to move to contain no differences in protection flags,
                        // as that wold create a different vm_area_struct
                        if (proc.get_address_space().has_memory_breakpoint(old_region)) {
                            // We don't track which memory breakpoints have been enabled or not,
                            // so we can set the entire region to the original permission flags
                            // with 1 syscall to mprotect()
                            auto orig_prot = 0;
                            // Only query the first byte of the old range, as it is possible that
                            // we have multiple MemoryMap objects tracking the same underlying
                            // physical memory region
                            if (auto mm_opt = proc.get_address_space().get_memory_map(old_address, old_address + 1)) {
                                orig_prot = mm_opt->first.prot_;
                            } else {
                                throw std::runtime_error(fmt::format("Failed to remove memory breakpoints for memory region to move: {}", old_region.str()));
                            }
                            auto sys_ret = proc.syscall(aarch64::syscall_number::mprotect, {old_region.start_address, old_region.size(), (uint64_t)orig_prot});
                            auto sys_err = syscall_errno(sys_ret);
                            if (sys_err) {
                                throw std::runtime_error("Failed to disable memory breakpoints before mremap() using mprotect(): " + std::string(strerror(sys_err)));
                            }
                        }
                    }
                }

                // TODO: Create generic syscall handler list
                auto accessed_pages = std::vector<MemoryRegion> {};
                {
                    MergingRegionSet s;
                    for (const auto r : syscall_event.mem_reads) {
                        s.insert(r.page_aligned());
                    }
                    for (const auto r : syscall_event.mem_writes) {
                        s.insert(r.page_aligned());
                    }
                    accessed_pages = s.get_all();
                }
                // Ignore memory pages that have been unmapped in the meantime
                auto mapped_and_accessed_pages = std::vector<MemoryRegion> {};
                {
                    MergingRegionSet s;
                    auto &vas = proc.get_address_space();
                    for (const auto pages : accessed_pages) {
                        auto mapped_pages = merge_regions(vas.intersect_mapped(pages));
                        if (mapped_pages.size() != 1 || (mapped_pages.size() == 1 && mapped_pages[0] != pages)) {
                            LOGW("Part of memory region %s referenced by system call arguments is not mapped anymore. Ignoring unmapped parts.", pages.str().c_str());
                        }
                        for (const auto p : mapped_pages) {
                            s.insert(p);
                        }
                    }
                    mapped_and_accessed_pages = s.get_all();
                }
                // Disable memory breakpoints for accessed memory by syscall to avoid EFAULT
                auto pages_to_disable = std::vector<MemoryRegion> {};
                {
                    MergingRegionSet s;
                    for (const auto page_aligned_mem : mapped_and_accessed_pages) {
                        for (const auto mem_bkpt : proc.get_address_space().intersect_with_taints(page_aligned_mem)) {
                            LOGV("System call accesses tainted memory: %s", mem_bkpt.str().c_str());
                            // mem_bkpt is the fine-grained tainted region and isn't page-aligned
                            s.insert(mem_bkpt.page_aligned());
                        }
                    }
                    pages_to_disable = s.get_all();
                }

                // Require all memory pages referenced by system calls to not contain memory breakpoints
                // but instead transform these breakpoints to hardware-based memory breakpoints,
                // such that other processes can still execute during execution of a system call.
                // TODO: Only do this for futex() instead of all system calls?
                proc.get_address_space()
                        .get_memory_breakpoint_manager()
                        .override_impl_rc(pages_to_disable,
                                          BreakpointImplPreference::WATCHPOINT_ONLY);

                proc.overridden_mem_bp_impl = std::move(pages_to_disable);

                proc.cont(); // Process will stop after syscall execution
            } else {
                LOGD("System call exit (pid %d): %.*s", pid, (int)syscall_name.size(), syscall_name.data());

                // Restore overriden memory breakpoint implementation type
                proc.get_address_space()
                    .get_memory_breakpoint_manager()
                    .override_impl_rc(proc.overridden_mem_bp_impl, {});
                proc.overridden_mem_bp_impl.clear();

                auto& args = syscall_event.args;
                auto retval = *syscall_event.retval;

                int sys_errno = syscall_errno(retval);
                if (sys_errno) {
                    LOGE("System call error: %s", strerror(sys_errno));
                    // Clear tainted info of syscall result register
                    proc.taint_register(MemoryRegion::from_start_and_size(aarch64::syscall_result_reg_offset, aarch64::register_size), {});

                    if (sys_errno == EFAULT) {
                        if (Debugger::at_least_one_taint_event) {
                            proc.print_registers();
                            auto constexpr msg = "System call failed due to bad memory access. Did we temporarily disable a temporary breakpoint?";
#ifdef PROD
                            LOGW(msg);
#else
                            throw std::runtime_error(msg);
#endif
                        } else {
                            LOGW("System call failed due to to bad memory access. Ignoring error since we have not marked any data as tainted yet");
                        }
                    }

                    if ((syscall_event.syscall_number == aarch64::syscall_number::write ||
                         syscall_event.syscall_number == aarch64::syscall_number::writev) &&
                        Config::print_write_payload) {
                        auto [reads, writes] = aarch64::get_syscall_memory_accesses(proc, syscall_event);
                        LOGV("write() payload dump:");
                        for (const auto read : reads) {
                            LOGV("Base %lx Len %lx", read.start_address, read.size());
                            auto payload = proc.read_memory(read);
                            android_hexdump(payload.data(), payload.size());
                        }
                    }
                } else {
                    LOGD("System call return value: 0x%" PRIx64, retval);

                    /* Process sink events */
                    {
                        auto &vas = proc.get_address_space();
                        std::vector<TaintEvent> accessed_taints;
                        for (const auto r : syscall_event.mem_reads) {
                            auto mapped_regions = merge_regions(vas.intersect_mapped(r));
                            if ((mapped_regions.size() != 1) ||
                                (mapped_regions.size() == 1 && mapped_regions[0] != r)) {
                                LOGW("A part of memory region %s is not valid on syscall-exit event when determining memory sink events. Ignoring sink events for unmapped regions.", r.str().c_str());
                            }
                            for (const auto mapped_r : mapped_regions) {
                                auto taints = proc.get_address_space().get_memory_taints(mapped_r);
                                if (!taints.empty()) {
                                    LOGI("Memory sink event for region %s", mapped_r.str().c_str());
                                    for (auto t : taints) {
                                        accessed_taints.push_back(t.get());
                                    }
                                }
                            }
                        }
                        if (!accessed_taints.empty()) {
                            add_data_leak(TaintEvent(std::move(accessed_taints), std::make_shared<SystemCallUnit>(pid, syscall_event.syscall_number, syscall_event.args)));
                        }
                    }

                    switch (syscall_event.syscall_number) {
                        case aarch64::syscall_number::mmap:
                        {
                            auto start_addr = retval;
                            auto len = (size_t) args[1];
                            auto prot = (int) args[2];
                            auto flags = (int) args[3];
                            auto fd = (int) args[4];
                            auto offset = (size_t) args[5];

                            LOGD("Handling mmap: start 0x%" PRIx64 " len 0x%" PRIx64, start_addr, len);

                            bool is_shared = (flags & MAP_SHARED) || (flags & MAP_SHARED_VALIDATE);
                            bool maps_file = !(flags & (MAP_ANONYMOUS | MAP_ANON));
                            std::optional<std::string> mapped_file_path{};
                            if (maps_file) {
                                mapped_file_path = proc.get_fd_path(fd);
                            }
                            /*
                             * If length is not page-aligned, memory accesses are still allowed for writes
                             * to address start + offset with offset > length
                             * The end address is rounded up to the nearest page boundary to track taints
                             * for such memory accesses
                             */
                            auto effective_end = round_to_page_boundary(start_addr + len); // Assumption: host PAGE_SIZE == target PAGE_SIZE
                            proc.get_address_space().add_memory_map(start_addr, effective_end, is_shared, prot, mapped_file_path);
                        }
                            break;
                        case aarch64::syscall_number::munmap:
                        {
                            auto start_addr = args[0];
                            auto len = args[1];
                            auto effective_end = round_to_page_boundary(start_addr + len);

                            LOGD("Handling unmap: start 0x%" PRIx64 " len 0x%" PRIx64, start_addr, len);
                            proc.get_address_space().remove_memory_map(start_addr, effective_end);
                        }
                            break;
                        case aarch64::syscall_number::mremap:
                        {
                            auto old_address = args[0];
                            auto old_size = args[1];
                            auto new_size = args[2];
                            int flags = (int) args[3];
                            /*
                             * Memory region to move is allowed to have PROT_NONE access flags.
                             * The region needs to be of the same "type".
                             * Optional argument: new address, which we ignore as the return value
                             * of the system call contains the pointer to the new virtual memory area
                             */
                            auto new_address = retval;

                            assert(old_address % PAGE_SIZE == 0);
                            assert(new_address % PAGE_SIZE == 0);
                            // Round up sizes to page boundaries
                            // https://elixir.bootlin.com/linux/v4.14.111/source/mm/mremap.c#L541
                            old_size = round_to_page_boundary(old_size);
                            new_size = round_to_page_boundary(new_size);

                            LOGD("Handling mremap: old_address 0x%" PRIx64 " old_size 0x%" PRIx64 " new_address 0x%" PRIx64 " new size 0x%" PRIx64,
                                    old_address, old_size, new_address, new_size);
                            proc.get_address_space().remap_memory_maps(old_address, old_size, new_address, new_size);
                        }
                            break;
                        case aarch64::syscall_number::mprotect:
                        {
                            if (retval != 0) {
                                // If errno is not set, mprotect() should return 0
                                throw std::runtime_error("mprotect() didn't return an error code and didn't return 0");
                            }
                            auto start = args[0];
                            auto len = (size_t) args[1];
                            auto prot = (int) args[2];
                            LOGD("Handling mprotect: start 0x%" PRIx64 " len %" PRIx64 " prot %d", start, len, prot);
                            if (start % PAGE_SIZE != 0) {
                                throw std::runtime_error(fmt::format("mprotect() didn't fail but user supplied start address {:#x} that isn't page-aligned!"));
                            }
                            auto region = MemoryRegion::from_start_and_size(start, len).page_aligned();
                            auto mapped_region = merge_regions(proc.get_address_space().intersect_mapped(region));
                            if (mapped_region.size() != 1 || (mapped_region.size() == 1 && mapped_region[0] != region)) {
                                LOGW("Part of memory region %s referenced by mmap() syscall is not mapped anymore. Ignoring updates to the unmapped regions", region.str().c_str());
                            }
                            for (const auto r : mapped_region) {
                                proc.get_address_space().set_protection_flag(r, prot);
                            }
                        }
                            break;
                        case aarch64::syscall_number::pkey_mprotect:
                        {
                            throw std::runtime_error("NYI: pkey_mprotect()");
                        }
                            break;
                        case aarch64::syscall_number::execve:
                        {
                            throw std::runtime_error("NYI: execve()");
                            auto filename = args[0];
                            auto argv = args[1];
                            auto envp = args[2];
                            // TODO: We don't know the length of the filename, we can just read the
                            //       path from profs
                            auto filename_mem = proc.read_memory(filename, 20);
                            LOGD("Handling execve(%.20s)", filename_mem.data());
                            // TODO: All threads in thread group are terminated
                        }
                            break;
                        case aarch64::syscall_number::getegid:
                        {
                            auto magic = args[0];
                            if (magic == 0xF00DCAFE) {
                                // We (ab)use unused system call arguments to allow the traced
                                // executable to mark a region of memory as tainted.
                                // This is particularly useful for benchmarks to assess the run-time
                                // performance.
                                auto tainted_data = MemoryRegion::from_start_and_size(args[1], args[2]);
                                LOGD("getegid() called with 0xF00DCAFE: Marking memory region (0x%llx-0x%llx) as tainted", tainted_data.start_address, tainted_data.end_address);
                                static auto source = TaintSource("Manual taint source with getegid()");
                                proc.get_address_space().set_memory_taint(TaintEvent(source, std::make_shared<InstructionUnit>(proc)), tainted_data);
                            } else {
                                at_least_one_egid_syscall = true; // Used to trigger extensive logging
                            }
                        }
                            break;
                        default:
                            break;
                    }
                    if (syscall_could_reference_fd(syscall_event.syscall_number)) {
                        proc.get_fds().on_syscall_exit(proc, syscall_event);
                    }
                }
                // TODO: Set memory/regs as tainted as a result of successful syscall execution for relevant syscalls

                if (proc.register_taint_count() > 0) {
                    handle_stop_signal(proc, event.get_stop_signal()); // Handles process continuation
                } else {
                    proc.cont();
                }
            }
        } else if (event.get_ptrace_event() != PTraceTrapEvent::NO_EVENT) {
            /**
             * Process creation syscall events set by PTRACE_O_* will stop execution of the
             * parent process after the new process has been already created.
             * The debugger process can receive the process creation event by the parent or
             * the process stop event of the created process in any order.
             * We examine the flags like all the other system calls, to examine system call
             * arguments e.g. CLONE_VM
             */
            switch (event.get_ptrace_event()) {
                case PTraceTrapEvent::CLONE:
                    // Already handled
                    break;
                case PTraceTrapEvent::FORK:
                case PTraceTrapEvent::VFORK:
                    throw std::runtime_error("(v)fork() syscall needs to be handled explicitly on this platform");
                case PTraceTrapEvent::EXEC:
                    throw std::runtime_error("NYI: exec()");
                default:
                    throw std::runtime_error("NYI: ptrace event " + std::to_string((int)(event.get_ptrace_event())));
            }
            proc.cont();
        } else {
            int signal = event.get_stop_signal();
            LOGD("Process with pid %d stopped due to signal %d", pid, signal);
            proc.post_attach_callback();
            if (signal == SIGCONT) {
#ifdef PROD
                LOGW("Process was stopped because of SIGCONT? Forwarding signal");
#else
                throw std::runtime_error("Process was stopped because of SIGCONT");
#endif
                proc.cont(signal);
                return;
            }
            // Do not return SIGSTOP event if we intentionally sent the signal to stop a particular process
            if (event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL && event.get_stop_signal() == SIGSTOP && proc.pop_received_sigstop()) {
                LOGD("Received SIGSTOP, as previously sent via the tracer. Resuming process...");
                proc.cont(0, true, true); // TODO: last arg SSBP?
                return;
            }
            handle_stop_signal(proc, signal);
        }
    }
}

void Debugger::handle_event_notaint(WaitEvent event) {
    auto event_type = event.get_event_type();
    auto pid = event.get_pid();
    LOGV("Event received of pid %d with status %#08x", pid, event.status_);
    auto process_opt = get_process(pid);
    /*
     * Creation of new processes (via e.g. clone()) makes sure that the created process is traced,
     * and thus inserted in the process list.
     */
    if (!process_opt) {
        throw std::runtime_error("Event received of an unknown process!");
    }
    auto& proc = process_opt->get();

    if (event_type == WaitEventType::NORMAL_TERMINATION) {
        LOGD("Process with pid %d terminated itself with exit code %d", pid, event.get_exit_code());
        if (procs_.erase(pid) != 1) {
            throw std::runtime_error("Unable to free resources of terminated process");
        };
    } else if (event_type == WaitEventType::KILLED_BY_SIGNAL) {
        LOGD("Process with pid %d killed with signal %d", pid, event.get_killed_signal());
        if (procs_.erase(pid) != 1) {
            throw std::runtime_error("Unable to free resources of killed process");
        };
    } else if (event_type == WaitEventType::CONTINUED_BY_SIGNAL) {
        LOGD("Process with pid %d resumed by delivery of SIGCONT", pid);
    } else if (event_type == WaitEventType::STOPPED_BY_SIGNAL) {
        proc.state = ProcessState::STOPPED;
        LOGD("Process stopped @ 0x%" PRIx64, proc.get_registers().get_pc());
        if (event.is_syscall_trap()) {
            auto syscall_event = proc.get_current_syscall();
            auto syscall_name = magic_enum::enum_name(syscall_event.syscall_number);
            if (syscall_event.state == SyscallEventState::RestartSyscallEntry ||
                syscall_event.state == SyscallEventState::RestartSyscallExit) {
                LOGD("Continuing process that will execute restart_syscall()");
                proc.cont();
                return;
            }
            if (syscall_event.syscall_number == aarch64::syscall_number::exit) {
                assert(syscall_event.state == SyscallEventState::SyscallEntry);
                LOGD("Process called exit(): %s (pid %d)", get_comm(pid).c_str(), pid);
            } else if (syscall_event.syscall_number == aarch64::syscall_number::exit_group) {
                assert(syscall_event.state == SyscallEventState::SyscallEntry);
                LOGD("Process called exit_group(): %s (pid %d)", get_comm(pid).c_str(), pid);
            } else {
                proc.print_stack_trace(true);
            }

            if (syscall_event.state == SyscallEventState::SyscallEntry) {
                LOGD("System call entry (pid %d): %.*s (syscallno: %d)", pid, (int)syscall_name.size(), syscall_name.data(), syscall_event.syscall_number);
                /*
                 * Handle process creation events before executing the system call.
                 * We wait for the process to raise a SIGSTOP (as requested by PTRACE_O_TRACECLONE
                 * and its variants) in a deterministic order to avoid unpredictable ordering of
                 *  - System call exit event
                 *  - SIGSTOP event of the created child process
                 */
                // On AArch64, there is no fork() or vfork(), they are all special cases of clone()
                if (syscall_event.syscall_number == aarch64::syscall_number::clone) {
                    auto& args = syscall_event.args;
                    /*
                     * Flags of clone() system call are passed via the first system call register,
                     * even though libc's clone() method passes the flags via the third register.
                     * sys_clone handler: https://elixir.bootlin.com/linux/v4.14.111/source/kernel/fork.c#L2146
                     * __bionic_clone: https://android.googlesource.com/platform/bionic/+/011e111/libc/arch-arm64/bionic/__bionic_clone.S
                     */
                    auto flags = (int)args[0];
                    PTraceTrapEvent expected_event;
                    if (flags & CLONE_VFORK) {
                        expected_event = PTraceTrapEvent::VFORK;
                        LOGD("clone() called with type VFORK");
                    } else if ((flags & CSIGNAL) != SIGCHLD) {
                        expected_event = PTraceTrapEvent::CLONE;
                        LOGD("clone() called with type CLONE");
                    } else {
                        expected_event = PTraceTrapEvent::FORK;
                        LOGD("clone() called with type FORK");
                    }
                    // Wait for PTRACE_EVENT_CLONE/VFORK/FORK event
                    proc.cont();
                    event = wait_for_process_events(proc.get_pid());
                    if (event.get_ptrace_event() != expected_event) {
                        throw std::runtime_error(
                                fmt::format(
                                        "Expected PTRACE_EVENT_CLONE or PTRACE_EVENT_VFORK but received status {:#x} instead",
                                        event.status_)
                        );
                    }

                    // A new child process has been created
                    pid_t child_pid;
                    TRYSYSFATAL(ptrace(PTRACE_GETEVENTMSG, pid, 0, &child_pid));
                    Process *child_proc;
                    LOGD("Cloned process %d -> %d with %s vspace and %s file descriptors", proc.get_pid(), child_pid, (flags & CLONE_VM) ? "shared" : "copied", (flags & CLONE_FILES) ? "shared" : "copied");
                    auto [ proc_iter, inserted ] = procs_.try_emplace(child_pid, proc, child_pid, CLONE_VM & flags, CLONE_FILES & flags);
                    if (!inserted) {
                        throw std::runtime_error("Child process with pid " + std::to_string(child_pid) + " already exists");
                    }
                    child_proc = &proc_iter->second;

                    // Wait for the process to spawn and raise SIGSTOP
                    auto child_event = wait_for_process_events(child_pid);
                    if (child_event.get_event_type() != WaitEventType::STOPPED_BY_SIGNAL ||
                        child_event.get_stop_signal() != SIGSTOP) {
                        throw std::runtime_error(
                                fmt::format(
                                        "Expected SIGSTOP event of child but received status {:#x} instead",
                                        child_event.status_)
                        );
                    }
                    child_proc->cont();
                    // We already obtained the process id of the cloned process, so we don't
                    // need to handle sycall-exit event to get result of clone()
                }
                proc.cont(); // Process will stop after syscall execution
            } else {
                LOGD("System call exit (pid %d): %.*s", pid, (int)syscall_name.size(), syscall_name.data());

                auto& args = syscall_event.args;
                auto retval = *syscall_event.retval;

                int sys_errno = syscall_errno(retval);
                if (sys_errno) {
                    LOGE("System call error: %s", strerror(sys_errno));

                    if (sys_errno == EFAULT) {
                        auto constexpr msg = "System call failed due to bad memory access. Did we temporarily disable a temporary breakpoint?";
                        throw std::runtime_error(msg);
                    }
                } else {
                    LOGD("System call return value: 0x%" PRIx64, retval);
                }
                proc.cont();
            }
        } else if (event.get_ptrace_event() != PTraceTrapEvent::NO_EVENT) {
            proc.cont();
        } else {
            int signal = event.get_stop_signal();
            LOGD("Process with pid %d stopped due to signal %d", pid, signal);
            proc.cont(signal);
        }
    }
}

void Debugger::handle_event_noop(WaitEvent event) {
    auto event_type = event.get_event_type();
    auto pid = event.get_pid();
    LOGV("Event received of pid %d with status %#08x", pid, event.status_);
    if (event_type == WaitEventType::NORMAL_TERMINATION) {
        LOGD("Process with pid %d terminated itself with exit code %d", pid, event.get_exit_code());
    } else if (event_type == WaitEventType::KILLED_BY_SIGNAL) {
        LOGD("Process with pid %d killed with signal %d", pid, event.get_killed_signal());
    } else if (event_type == WaitEventType::CONTINUED_BY_SIGNAL) {
        LOGD("Process with pid %d resumed by delivery of SIGCONT", pid);
    } else if (event_type == WaitEventType::STOPPED_BY_SIGNAL) {
        user_pt_regs regs;
        struct iovec io {
                .iov_base = &regs,
                .iov_len = sizeof(regs)
        };
        TRYSYSFATAL(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io));
        LOGD("Process with pid %d stopped @ 0x%" PRIx64, pid, regs.pc);
        if (event.is_syscall_trap()) {
            TRYSYSFATAL(ptrace(PTRACE_SYSCALL, pid, 0, 0));
        } else if (event.get_ptrace_event() != PTraceTrapEvent::NO_EVENT) {
            TRYSYSFATAL(ptrace(PTRACE_SYSCALL, pid, 0, 0));
        } else {
            auto signal = event.get_stop_signal();
            LOGD("Process with pid %d stopped due to signal %d", pid, signal);
            TRYSYSFATAL(ptrace(PTRACE_SYSCALL, pid, 0, signal));
        }
    }
}

void Debugger::handle_stop_signal(Process &proc, int signal) {
    // The program counter points to the faulted instruction
    auto ins_addr = proc.get_registers().get_pc();
    auto ins_anal = proc.analyze_instructions(ins_addr, aarch64::instruction_size * 1);
    // Determines if we need to restore the breakpoint if non-temporary
    std::optional<std::reference_wrapper<InstructionBreakpoint>> restored_instruction_from_bp {};
    // Fine-grained memory region that is accessed at the current instruction
    std::optional<MemoryRegion> memory_access {};
    // Breakpoint entries that have been removed to allow the process to execute the current instruction
    // without segmentation fault
    VirtualAddressSpace::MemoryBreakpointManager::breakpoint_collection removed_breakpoints;
    // If the memory access is allowed by the original process (ignoring memory breakpoints inserted by us)
    std::optional<bool> authorized_memory_access = false;
    bool access_tainted_memory = false; // If the current instruction accessed tainted information
    bool skip_taint_propagation = false; // If taint propagation should be skipped
    // If the process should resume execution after restoring IBP and PTE. Value denotes signal to forward
    std::optional<int> should_resume = 0;
    // Memory to taint after executing the current instruction
    std::vector<MemoryToTaint> mem_to_taint {};

    // TODO: Check assumption if ins_addr is valid for SEGFAULT or single step: does it point to the next instruction?

    /*
     * We must analyze memory accesses of the original instruction. Therefore, we restore the
     * original instruction first.
     * We don't check if the received signal is a SIGTRAP, because a breakpoint might be placed
     * while a segmentation fault event is in the queue to be handled.
     */
    if (ins_anal.is_breakpoint(0)) {
        auto ins_bp_opt = proc.get_instruction_breakpoint(ins_addr);
        if (ins_bp_opt) {
            /*
             * Single-step breakpoints may move the program counter to an instruction with a breakpoint
             * We restore the breakpoint in that case as well
             */
            auto &bp = ins_bp_opt->get();
            if (!proc.get_single_step_breakpoint()) {
                skip_taint_propagation = !bp.should_handle(proc.get_pid());
            }
            // Restore original instruction @ pc
            bool new_state = proc.toggle_ins_breakpoint(bp, ins_addr);
            if (new_state) {
                throw std::runtime_error(fmt::format("Error while toggling breakpoint in SIGTRAP handler: breakpoint @ {:#x} is now enabled instead of disabled", ins_addr));
            }
            // Disassemble restored instruction
            ins_anal = proc.analyze_instructions(ins_addr, aarch64::instruction_size * 1);
            restored_instruction_from_bp = bp;
        } else {
            // Breakpoint instruction was found by examining memory of tracee, but we haven't
            // placed a breakpoint there.
            // That's pretty suspicious... Is the tracee checking if we're debugging it?
            LOGW("Breakpoint instruction found by examining memory of tracee, but tracer didn't place a breakpoint");
            constexpr auto msg = "A software breakpoint is found @ pc that we haven't placed. Forwarding signal to process.";
#ifdef PROD
            LOGE("%s", msg);
#else
            LOGE("%s", msg);
            proc.print_stack_trace();
            throw std::runtime_error(msg);
#endif
            proc.forward_signal(signal);
            return;
        }
    }

    proc.print_stack_trace(); // Print after restoring original instruction
    auto llsc_kind = ins_anal.get_irsb().get_llsc_kind(0);

    auto ins_array = std::array<unsigned char, 4> {};
    auto [ins_ptr, size] = ins_anal.get_machine_bytes(0);
    std::memcpy(ins_array.data(), ins_ptr, size);
    assert(size == 4);
    uint32_t current_instruction = *(uint32_t *)ins_ptr;

    if (auto memory_guest_access = ins_anal.memory_accesses(0, proc.get_registers())) {
        /*
         * We need to restore the original PTE permissions if the instruction @ pc accesses memory
         * in a memory page whose permissions for this virtual address space has been set to
         * PROT_NONE to act as a memory breakpoint.
         * This can happen if
         *  (1) a breakpoint has been set with a memory region that intersects with the memory that
         *      is being accessed.
         *  (2) a breakpoint has been set and the current instruction accesses memory that lies
         *      within in the same page as the memory with a breakpoint on it
         */
        memory_access = memory_guest_access->region;
        proc.print_registers();

        if (auto mm = proc.get_address_space().get_memory_map(memory_access->start_address, memory_access->start_address + 1))  {
            auto prot = mm->first.prot_;
            authorized_memory_access = (memory_guest_access->type == AccessType::Read && (prot & PROT_READ)) ||
                    (memory_guest_access->type == AccessType::Write && (prot & PROT_WRITE));
            if (proc.get_address_space().has_memory_breakpoint(*memory_access)) {
                access_tainted_memory = true;
                LOGD("Instruction @ pc tried to access tainted memory at %s", memory_access->str().c_str());
            } else {
                LOGD("Instruction @ pc tried to access clean memory at %s", memory_access->str().c_str());
            }

            if (Config::print_memory_region_on_mem_access) {
                auto mem_addr = memory_access->start_address;
                if (mem_addr % PAGE_SIZE > 0) {
                    auto size = (mem_addr % PAGE_SIZE) < 0x20 ? (mem_addr % PAGE_SIZE) : 0x20;
                    if (size > 0) {
                        LOGV("Context before mem access:");
                        proc.print_memory(mem_addr - size, size);
                    }
                }
                LOGV("Context at mem access:");
                proc.print_memory(memory_access->start_address, 0x40);
            }

            auto memory_breakpoint_access_page = proc.get_address_space().get_memory_breakpoint_pages(memory_access.value());
            if (memory_breakpoint_access_page) {
                if (Config::stop_reachable_threads) {
                    stop_reachable_process_except(proc, *memory_access);
                }
                removed_breakpoints = proc.get_address_space().get_memory_breakpoint_manager().remove_memory_breakpoint(memory_breakpoint_access_page.value());

                if (llsc_kind && *llsc_kind == LLSC_Kind::LOAD_LINKED) {
                    // Make sure that only events of this process are handled until we reach
                    // a store-conditional or clrex
                    if (priority_process_ && *priority_process_ != proc.get_pid()) {
                        throw std::runtime_error(fmt::format("Tried to set priority process to pid {}, but was already set to {}", proc.get_pid(), *priority_process_));
                    }
                    priority_process_ = proc.get_pid();
                }
            }
        } else if (llsc_kind && *llsc_kind == LLSC_Kind::LOAD_LINKED) {
            priority_process_.reset();
        }
    }

    if (memory_access && !authorized_memory_access.value()) {
        if (signal != SIGSEGV && signal != SIGTRAP) {
            throw std::runtime_error("Received unexpected signal while handling unauthorized memory access");
        }
        if (!removed_breakpoints.empty()) {
            throw std::runtime_error("Instruction access an unauthorized memory page with a memory breakpoint placed on the same page. "
                                     "This could theoretically happen, but it is likely a bug in our implementation");
        } else {
            // Segmentation fault was not caused by placing a breakpoint on the accessed memory region
            should_resume = SIGSEGV; // Forward signal
            if (Config::throw_on_app_segfault) {
                throw std::runtime_error(fmt::format("Process has insufficient access permissions or attempted to access memory that is not mapped at {}", memory_access->str()));
            } else {
                LOGW("Process has insufficient access permissions or attempted to access memory that is not mapped at %s. Forwarding SIGSEGV to process.", memory_access->str().c_str());
            }
        }
    }

    if (signal == SIGSEGV) {
        if (!memory_access) {
            throw std::runtime_error("SIGSEGV caught but no memory access found @ pc");
        }
        if (!access_tainted_memory) {
            /*
             * Segmentation fault was caused by a memory access on a page with a memory breakpoint
             * but it didn't access any tainted information
             */
            skip_taint_propagation = true;
            LOGV("Segmentation fault event received without tainted memory read");
        }
    }

    if (llsc_kind && *llsc_kind == LLSC_Kind::LOAD_LINKED) {
        LOGV("Tracking load-linked instruction");
        // Track load-linked instructions not only for segmentation violation but also
        // for breakpoints (e.g. those placed by TaintpropBreakpointOptimizer)
        if (!memory_access) {
            throw std::runtime_error("Load-linked instruction doesn't access memory");
        }
        proc.set_last_load_linked(ins_array, *memory_access);
    }


    const bool propagate_taints = !skip_taint_propagation || proc.register_taint_count() > 0;
    /*
     * Clear temporary breakpoints that are marked for removal.
     * We only perform the breakpoint removal if we plan to propagate taints, to avoid removal
     * for irrelevant events e.g. clean memory read on page guard
     * We clear them before taint propagation because taint propagation might set new breakpoints
     * at the same location as one of the breakpoints marked for removal.
     */
    if (propagate_taints) {
        LOGV("Removing temporary breakpoints");
        for (auto vaddr : proc.get_temporary_breakpoints_to_remove()) {
            // Don't remove breakpoint at the current instruction, as it will be handled later
            if (restored_instruction_from_bp && ins_addr == vaddr) continue;
            LOGV("Removing temporary breakpoint that we didn't break on @ 0x%" PRIx64, vaddr);
            proc.remove_instruction_breakpoint(vaddr, true);
        }
        proc.clear_temporary_breakpoints_to_remove();
    } else {
        LOGV("Not removing temporary breakpoints as we are not propagating taints");
    }

    // Disassemble instructions after potentially restoring original instruction on breakpoint

    /* Program counter apparently does not point to the next instruction if it wasn't successful,
     * so we don't need to manually roll back pc on breakpoint
     * TODO: Clean up if not necessary anymore
    // Retry execution of the last instruction if it wasn't successful due to any breakpoints
    if (restored_instruction_from_bp || memory_breakpoint_access_page) {
        // Let pc point to the trapped instruction instead of the instruction after it
        auto regs = proc.get_registers().get_gp_registers();
        regs.pc = ins_addr;
        proc.get_registers().set_gp_registers(regs);
    }
    */

    // Execute breakpoint handlers for taint sources
    if (restored_instruction_from_bp) {
        for (const auto &bpe : restored_instruction_from_bp->get().get_breakpoints(proc.get_pid())) {
            if (auto handler_opt = bpe.get().handler) {
                LOGD("Executing breakpoint handler");
                handler_opt->get().on_breakpoint(*this, proc);
            }
        }
    }

    /**
     * Stopping the process between load-linked and store-conditional instructions
     * causes the store-conditional instruction to fail.
     * When the process is stopped at a store-conditional instruction, we execute the following
     * instructions in absence of memory breakpoints to allow the instruction to complete
     * successfully:
     *   (1) clrex to restore the monitor state of the previously-executed load-linked
     *   (2) The previous load-linked instruction with its destination operands set to the
     *       zero-register, but with the same read address
     *   (3) The store-conditional instruction that the process is currently stopped at
     */
    {
        auto sc_instruction = std::optional<uint32_t> {};
        auto sc_addr = ins_addr;
        auto sc_memory_access = std::optional<MemoryRegion> {};
        bool sc_succeeded = false;
        if (llsc_kind && *llsc_kind == LLSC_Kind::STORE_CONDITIONAL) {
            LOGV("Current instruction is a store conditional");
            sc_instruction = current_instruction;
            sc_memory_access = memory_access;
            priority_process_.reset();
        } else if (llsc_kind && *llsc_kind == LLSC_Kind::CLEAR_EXCLUSIVE) {
            priority_process_.reset();
        } else if (restored_instruction_from_bp &&
                   restored_instruction_from_bp->get().should_handle(proc.get_pid())
                   == BreakpointReason::TAINTPROP_BREAKPOINT_OPTIMIZER_STORE_CONDITIONAL) {
            LOGV("Handling breakpoint set after a store conditional");
            sc_addr = ins_addr - aarch64::instruction_size;
            auto sc_mem = proc.read_memory(sc_addr, aarch64::instruction_size);
            auto sc_anal = proc.analyze_instructions(sc_addr, aarch64::instruction_size);
            sc_instruction = *(uint32_t *)sc_anal.get_machine_bytes(0).first;
            if (auto sc_guest_access = sc_anal.memory_accesses(0, proc.get_registers())) {
                sc_memory_access = sc_guest_access->region;
            }
            sc_anal.print_instructions();
            auto sc_status_reg = aarch64::get_store_conditional_status_register(*sc_instruction);
            if (sc_status_reg && proc.get_registers()[*sc_status_reg] == 0) {
                LOGV("Store conditional already succeeded");
                sc_succeeded = true;
            } else {
                LOGV("Store conditional was not successful without manual intervention");
            }
            priority_process_.reset();
        }

        if (sc_instruction && !sc_succeeded) {
            if (!proc.has_last_load_linked()) {
                constexpr auto msg = "Process stopped on store-conditional without ever having stopped at a load-conditional instruction before";
#ifdef PROD
                LOGW(msg);
#else
                throw std::runtime_error(msg);
#endif
            }
            assert(aarch64::is_store_conditional(*sc_instruction));

            auto [ll, ll_memory_access] = proc.get_and_clear_last_load_linked();

            if (!sc_memory_access) {
                throw std::runtime_error("Store-conditional instruction doesn't access memory");
            }
            if (*sc_memory_access != ll_memory_access) {
                throw std::runtime_error(fmt::format(
                        "Memory access address of store-conditional ({}) differs from previously saved load-linked instruction ({})",
                        sc_memory_access->str(), ll_memory_access.str()));
            }
            auto payload = std::array<unsigned char, 3 * aarch64::instruction_size> {};
            auto *payload_ptr = payload.data();

            // Copy clrex instruction
            std::copy(aarch64::clear_exclusive_instruction.begin(), aarch64::clear_exclusive_instruction.end(), payload.begin());
            payload_ptr += aarch64::clear_exclusive_instruction.size();

            // Copy modified load-linked instruction, whose transfer register is set to xzr
            assert(ll.size() == 4 && "Instruction size mismatch");
            uint32_t llsc_modified = aarch64::set_load_linked_transfer_registers(*(uint32_t *)ll.data());
            LOGV("Transformed LL instruction: old: 0x%08" PRIx32 " new: 0x%08" PRIx32, *(uint32_t *)ll.data(), llsc_modified);
            assert(payload_ptr + 4 <= payload.data() + payload.size());
            std::memcpy(payload_ptr, &llsc_modified, 4);
            payload_ptr += 4;

            // Copy store conditional instruction @ pc to payload
            assert(payload_ptr + 4 <= payload.data() + payload.size());
            std::memcpy(payload_ptr, &(*sc_instruction), sizeof(*sc_instruction));
            auto sc_status_reg = aarch64::get_store_conditional_status_register(*sc_instruction);

            // Execute clrex, ll, sc instructions and set program counter to instruction after
            // the original sc instruction
            LOGD("Executing clex, ll, sc and incrementing program counter by 4");
            stop_reachable_process_except(proc, sc_memory_access.value());
            proc.execute_instructions(payload.data(), payload.size(), false, sc_addr + 4);

            // Check if the store conditional was successful
            // and retry if it failed, possibly due to ctx switches from the Linux scheduler?
            if (sc_status_reg) {
                bool succ = false;
                for (int i = 1; i <= 5; i++) {
                    LOGW("Store conditional attempt number %d", i);
                    auto status = proc.get_registers()[*sc_status_reg];
                    if (status == 0) {
                        LOGV("Store conditional successful");
                        succ = true;
                        break;
                    } else if (status == 1) {
                        proc.execute_instructions(payload.data(), payload.size(), false, sc_addr + 4);
                    } else {
                        throw std::runtime_error(fmt::format("Unexpected store conditional failure: received status {:#x} instead of 0 or 1", status));
                    }
                }
                if (!succ) {
                    throw std::runtime_error("Store conditional instruction failed to write to memory");
                }
            } else {
                LOGW("Ignoring success or failure of store conditional: status written to wzr");
            }
        }
    }

    /*
     * We step over branch instructions and break on the instruction that is executed after it,
     * to analyze the new instructions
     */
    if (ins_anal.could_jump(0)) {
        LOGV("Instruction can jump. We single step such that we can analyze the next basic block for taint propagation");
        if (memory_access) {
            throw std::runtime_error("Assumption violated: memory read on branch instruction");
        }
        if (signal != SIGTRAP) {
            throw std::runtime_error(fmt::format("Expected SIGTRAP on branch instruction but got stop signal {} instead", signal));
        }
        auto ss_failure = proc.single_step_blocking();
        if (ss_failure) {
            throw std::runtime_error(fmt::format("Instruction that could jump raised an exception with status {:#x}", ss_failure->status_));
        }

        pending_events_.enqueue(WaitEvent(0x57f, proc.get_pid()));
        should_resume.reset(); // Handle single-step breakpoint without continuing
    } else {
        // Handle breakpoint
        if (propagate_taints) {
            // TODO: resuse ins_anal?
            auto ins_mem = proc.read_memory(ins_addr, 32 * aarch64::instruction_size);
            unsigned char curr_ins_bytes [aarch64::instruction_size];
            std::memcpy(curr_ins_bytes, ins_mem.data(), sizeof(curr_ins_bytes));
            ins_anal = InstructionAnalyzer::get_instance().analyze(ins_mem.data(),
                                                                   ins_mem.size(), ins_addr);
            // Taint propagation might analyze code blocks that will be executed in the future,
            // which will invalidate the analyzed LibVEX instructions
            auto tbo = TaintpropBreakpointOptimizer(proc);
            tbo.add_code_block(std::move(ins_mem));
            mem_to_taint = proc.propagate_taints(ins_anal, tbo);

            // Re-analyze current instruction
            ins_anal = InstructionAnalyzer::get_instance().analyze(curr_ins_bytes, sizeof(curr_ins_bytes), ins_addr);
        }

        /*
         * We need to single step the current instruction if the normal execution behavior is dependent
         * on the restored PTE permissions or original instructions, as they will be reinstated after
         * the current instruction.
         * Note: We don't single-step if we already modified the program counter due to e.g.
         *       stepping over a store-conditional instruction
         * Taint propagation may also place memory breakpoints at memory that will be accessed by the
         * to-be-executed instruction. We thus set the memory breakpoint in `mem_to_taint` after
         * single-stepping over the current instruction.
         * If the current instruction is a branch instruction, and the process has tainted information
         * in its registers, we single step to analyze the new target after branching.
         * Breakpoints placed at the current program counter value of the process should be inserted
         * after single stepping over it.
         */
        // Check if changed pc is caused by store-conditional instruction
        assert(proc.get_registers().get_pc() == ins_addr || (llsc_kind && *llsc_kind == LLSC_Kind::STORE_CONDITIONAL));
        if (proc.get_registers().get_pc() == ins_addr &&
             (restored_instruction_from_bp || !removed_breakpoints.empty() || !mem_to_taint.empty()
             || proc.has_pending_pc_breakpoint())
             ) {
            if (auto ss_failure = proc.single_step_blocking()) {
#ifdef PROD
                LOGE("Single stepped over an instruction before reinstating instruction or memory breakpoint with unexpected status %#08x", ss_failure->status_);
#else
                throw std::runtime_error(fmt::format("Single stepped over an instruction before reinstating instruction or memory breakpoint with unexpected status {:#x}", ss_failure->status_));
#endif
                if (ss_failure->get_event_type() == WaitEventType::STOPPED_BY_SIGNAL) {
                    /*
                     * The signal could be handled by an installed signal handler, or the standard
                     * behavior as marked in `man 7 signal` would be performed.
                     * We forward the signal with a single step such that we have control over
                     * the executed instructions when tainted information is stored in the
                     * registers of the process
                     */
                    // TODO: We can parse SigCgt in procfs to double check if a signal handler is present
                    auto pre_pc = proc.get_registers().get_pc();
                    ss_failure = proc.single_step_blocking(ss_failure->get_stop_signal());
                    if (ss_failure) {
                        throw std::runtime_error(fmt::format(
                                "Failed to transfer control to signal handler: received status {:x}",
                                ss_failure->status_));
                    } else if (proc.get_registers().get_pc() == pre_pc) {
                        throw std::runtime_error(
                                "Program counter didn't change after forwarding stop signal to process");
                    } else if (proc.get_registers().get_pc() == pre_pc + aarch64::instruction_size) {
                        LOGW("Program counter didn't jump to a signal handler after forwarding stop signal to process");
                    }
                    // Break on first instruction of the handler. TODO: only break when at least 1 reg is tainted to increase perf.
                    pending_events_.enqueue(WaitEvent(0x57f, proc.get_pid()));
                    should_resume.reset(); // We already have an event to process in backlog, keep process in stopped status
                } else {
                    LOGW("Received status after signal step wasn't a stop signal. Adding wait status to backlog");
                    pending_events_.enqueue(*ss_failure);
                    should_resume.reset(); // Process wasn't stopped
                }
            }
        }
    }

    /* Restore IBP and PTE perms */

    // Re-enable breakpoint if it's not a temporary breakpoint, or if the pid wasn't the handler
    if (restored_instruction_from_bp) {
        auto& bp = restored_instruction_from_bp->get();
        bool removed = false; // True implies `bp` is now an invalid reference
        if (bp.contains_temporary_entry_for_pid(proc.get_pid())) {
            // Temporary breakpoint entry has been handled, and should be removed from the list of
            // temporary breakpoints for the process.
            LOGV("Removing temporary breakpoint entry that we broke on @ 0x%" PRIx64, ins_addr);
            removed = proc.remove_instruction_breakpoint(ins_addr, true);
            // Another process might have a breakpoint enabled at the same instruction address,
            // or a permanent breakpoint could be present at the address.
        }
        if (!removed && !bp.is_empty()) {
            // Re-enable breakpoint if at least one process has a temporary breakpoint on it, or
            // if it is a permanent breakpoint
            bool new_state = proc.toggle_ins_breakpoint(bp, ins_addr);
            if (!new_state) {
                throw std::runtime_error(fmt::format("Error while enabling breakpoint: breakpoint @ {:#x} is now disabled instead of enabled", ins_addr));
            }
        }
    }

    // Set breakpoint @ pc if previously requested
    if (auto pending_bp = proc.get_and_clear_pending_pc_breakpoint()) {
        LOGD("Installing deferred instruction breakpoint");
        auto [vaddr, bp] = *pending_bp;
        // We should have single stepped by now
        if (proc.get_registers().get_pc() == vaddr) {
            throw std::runtime_error("Unable to set pending breakpoint: program counter hasn't changed since breakpoint insert request");
        }
        proc.insert_instruction_breakpoint(vaddr, std::move(bp));
    }

    // Restore page permissions for this virtual address space
    if (!removed_breakpoints.empty()) {
        proc.get_address_space().get_memory_breakpoint_manager().set_memory_breakpoint(removed_breakpoints);
    }

    // Merge consecutive regions to avoid as much syscall overhead as possible
    for (const auto &m : mem_to_taint) {
        proc.get_address_space().set_memory_taint(m.taint_tag, m.memory_region);
    }

    /* Resume execution of process if not yet explicitly handled */

    if (should_resume) {
        proc.cont(*should_resume);
    }
}

void Debugger::debug_trace() {
    LOGD("Printing reference execution trace without taint tracking");
    assert(procs_.size() == 1);
    procs_.begin()->second.single_step(0);
    for (;;) {
        assert(procs_.size() == 1);
        auto event = wait_for_process_events(-1); // Wait for an event of any traced process
        auto pid = event.get_pid();
        auto process_opt = get_process(pid);
        if (!process_opt) {
            throw std::runtime_error("Event received of an unknown process!");
        }
        auto &proc = process_opt->get();
        if (event.get_event_type() == WaitEventType::KILLED_BY_SIGNAL ||
            event.get_event_type() == WaitEventType::NORMAL_TERMINATION) {
            LOGD("Process stopped with status %#08x", event.status_);
            return;
        } else if (event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL) {
            proc.state = ProcessState::STOPPED;
        }
        proc.print_stack_trace(true);
        proc.single_step();
    }
}

size_t Debugger::data_leak_count() {
    return data_leaks_.size();
}

void Debugger::log_taint_size() {
    std::unordered_set<VirtualAddressSpace*> vspaces;
    for (auto &[_, p] : procs_) {
        vspaces.insert(&p.get_address_space());
    }
    uint64_t demand_sum = 0, watch_sum = 0;
    for (const auto &vs : vspaces) {
        demand_sum += vs->get_memory_breakpoint_manager().get_demand_size();
        watch_sum += vs->get_memory_breakpoint_manager().get_watch_size();
    }
    LOGD("Tainted memory size (counting multiple times if shared): %" PRIu64 " B", demand_sum);
    LOGD("Watched memory size (counting multiple times if shared): %" PRIu64 " B", watch_sum);
}

WaitEvent wait_for_process_events(pid_t pid, bool allow_process_termination) {
    int status;
    pid_t event_pid = TRYSYSFATAL(waitpid(pid, &status, 0));
    assert(pid <= 0 || pid == event_pid);
    auto event = WaitEvent(status, event_pid);
    if (auto p_opt = Debugger::get_instance().get_process(event_pid); p_opt) {
        auto &p = p_opt.value().get();
        if (!allow_process_termination && event.get_event_type() == WaitEventType::KILLED_BY_SIGNAL) {
            throw std::runtime_error(fmt::format("Process with pid {} unexpectedly terminated (status {:#x}) while waiting for it to stop", event_pid, event.status_));
        }
        LOGD("Received new event for pid %d and status 0x%" PRIx32, event_pid, status);
        p.handle_caught_event(event);
        if (event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL && event.get_stop_signal() == SIGSTOP && p.pop_received_sigstop()) {
            LOGD("Ignoring SIGSTOP and continuing the process since we sent SIGSTOP in the past");
            p.cont(0, true, true); // TODO: SSBP
            return wait_for_process_events(pid, allow_process_termination);
        }
    } else if (event.is_syscall_trap()) {
        // We must keep Process::current_syscall_ in sync with current state
        throw std::runtime_error("System call event caught for pid that has no Process instance");
    }
    return event;
}

std::vector<sock_filter> compile_syscall_whitelist(std::vector<aarch64::syscall_number> syscalls) {
    if (syscalls.size() > std::numeric_limits<__u8>::max()) {
        throw std::runtime_error(
                fmt::format("Too many syscalls to whitelist: provided {} instead of the maximum {}",
                            syscalls.size(), std::numeric_limits<__u8>::max()));
    }
    auto res = std::vector<sock_filter> {};
    res.reserve(1 + 2 *syscalls.size() + 1);
    /**
     * Good resource about BPF instructions: https://www.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+4.7-RELEASE
     */
    // A <- syscall number
    res.emplace_back(sock_filter BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(seccomp_data, nr)));
    for (int i = 0; i < syscalls.size(); ++i) {
        // Jump to last instruction if A == syscalls[i], otherwise handle the next syscall
        res.emplace_back(sock_filter BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (__u32) syscalls[i], (__u8) (syscalls.size() - i), 0));
    }
    res.emplace_back(sock_filter BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)); // No comparison was true, continue process
    res.emplace_back(sock_filter BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)); // Inform tracer
    return res;
}

