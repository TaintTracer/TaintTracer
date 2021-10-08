#pragma once

#include <sys/types.h>
#include <functional>
#include <linux/auxvec.h>
#include <array>
#include <list>
#include <debugger/taint/TaintEvent.h>
#include <debugger/vex/IRSBResult.h>
#include "arch/aarch64.h"
#include "WaitEvent.h"
#include "breakpoint/InstructionBreakpoint.h"
#include "InstructionAnalyzer.h"
#include <debugger/vex/IRSBResult.h>
#include <debugger/taint/MemoryToTaint.h>
#include <linux/android/binder.h>
#include <set>
#include <linux/filter.h>
#include <debugger/procfs/ProcessMapState.h>
#include <debugger/memory/VirtualAddressSpace.h>

class Debugger;
class VirtualAddressSpace;
class FileDescriptorTable;
struct MemoryMap;
class InstructionBreakpoint;
class BreakpointHandler;
class BinderTransactionCtx;
class TaintpropBreakpointOptimizer;

enum class ProcessState {
    RUNNING,
    STOPPED,
    TERMINATED
};

enum class ProcessArchitecture {
    UNKNOWN,
    ARM64,
    ARM
};

struct TraceeMemory {
public:
    TraceeMemory(const unsigned char *contents, uint64_t tracee_address, size_t length)
                : contents_(contents), tracee_address_(tracee_address), length_(length) {};
    TraceeMemory(const TraceeMemory&) = delete;
    TraceeMemory& operator=(const TraceeMemory&) = delete;
    TraceeMemory(TraceeMemory&& other) : contents_(other.contents_), tracee_address_(other.tracee_address_), length_(other.length_){
        other.contents_ = nullptr;
    }
    ~TraceeMemory(){ delete[] contents_; }
    const unsigned char *data() const { return contents_; }
    uint64_t tracee_address() const { return tracee_address_; }
    size_t size() { return length_; }
    const unsigned char operator[] (size_t idx) { return contents_[idx]; }
private:
    const unsigned char *contents_;
    uint64_t tracee_address_;
    size_t length_;
};

enum class SyscallEventState {
    SyscallEntry, ///< System call entry
    SyscallExit, ///< System call exit, will not restart
    RestartSyscallEntry, ///< System call restart entry
    RestartSyscallExit ///< System call restart exit, will restart in the future
};

struct SyscallEvent {
    aarch64::syscall_number syscall_number; ///< System call number. Can be restart_syscall when original system call entry
                                                           ///< was not observed when attaching during system call restart
    SyscallEventState state;
    std::array<uint64_t,6> args; ///< System call arguments. Also valid if is_entry is false, args are copied.
    std::optional<uint64_t> retval; ///< Return value on syscall-exit.

    std::optional<binder_write_read> bwr_pre; ///< Binder read write state before syscall, used to determine number of bytes tx/rx'd
    std::vector<MemoryRegion> mem_reads; ///< Address ranges that are potentially read by the system call
    std::vector<MemoryRegion> mem_writes; ///< Address ranges that are potentially written by the system call
};

/**
 * Represents a traced process.
 *
 * VirtualAddressSpace refers to Process instances, which may be killed and thus destroyed at any time.
 * We let Process be uniquely owned by a Debugger instance with a shared_pointer, to allow weak references
 * from VirtualAddressSpace to Process.
 */
class Process {
private:
    Debugger& debugger_;
    pid_t pid_;
    ProcessArchitecture arch_;
    AnnotatedAddressSpace<TaintEvent> register_taints_;  ///< Track register taints in a flat address space
    AArch64RegisterState regs_;
    std::shared_ptr<VirtualAddressSpace> vspace_;
    std::shared_ptr<FileDescriptorTable> fds_;

    /**
     * Tracing system calls using PTRACE_SYSCALL or PTRACE_SYSEMU will cause syscall-entry-stop,
     * meaning that the process will stop before executing the system call (to allow examination of
     * system call number and arguments), and after executing the system call (to allow examination
     * of return values).
     * The two events are indistinguishable for the debugger, so we keep state.
     * This field is set after a syscall trap event has been triggered.
     * If a syscall trap is triggered, and this field is equivalent to std::nullopt, the process
     * has stopped before executing the system call. Otherwise, the process has stopped after
     * executing the system call.
     */
    std::optional<SyscallEvent> current_syscall_;

    /**
     * Whether any system calls that need to be executed after attaching (e.g. setting up seccomp)
     * has been performed.
     */
    bool executed_syscall_setup_ = false;

    /**
     * Whether a virtual instruction breakpoint for the next instruction has been set for this process.
     */
    bool single_step_breakpoint_ = false;

    /**
     * Context info of a request of which a reply is yet to be processed
     */
    std::unique_ptr<BinderTransactionCtx> current_binder_ctx;

    /**
     * List of addresses of breakpoints that should be removed when the process is stopped
     */
    std::set<uint64_t> temporary_breakpoints_to_remove_;

    /**
     * Breakpoint to be inserted at the current program counter.
     * This breakpoint is not immediately inserted, because this would lead to the same instruction
     * being trapped, and potentially restoring the breakpoint and repeating taint propagation.
     */
    std::optional<std::pair<uint64_t, InstructionBreakpointEntry>> pending_pc_breakpoint_;

    /**
     * Last encountered load linked instruction
     */
    std::optional<std::pair<std::array<unsigned char, 4>, MemoryRegion>> last_load_linked_;

    /**
     * Whether the process has been stopped using the custom signal.
     * The next time that a stop event for that signal is received, we just continue the process
     * and not forward it to the tracee.
     */
    bool received_sigstop_ = false;

public:
    ProcessState state;
    /**
     * Memory breakpoint ranges for which we changed the implementation preference type prior to
     * executing a system call. The implementation types should be restored after system call
     * completion.
     */
    std::vector<MemoryRegion> overridden_mem_bp_impl;

    /**
     * Create a new process with an empty address space.
     * This constructor should be used when the debugger attaches to a process for the first time
     * @param debugger Debugger instance that owns this process
     * @param pid Process id
     */
    Process(Debugger& debugger, pid_t pid);

    /**
     * Create a new process with a deep copy of the provided virtual address space
     * @param debugger Debugger instance that owns this process
     * @param pid Process id
     * @param vspace Virtual address space to copy
     */
    Process(Debugger& debugger, pid_t pid, const VirtualAddressSpace& vspace);

    /**
     * Create a new process with an existing virtual address space.
     * The provided address space must be the same as its parent if clone() system call with
     * the CLONE_VM flag was executed. Otherwise, a copy of the address space must be provided.
     * @param debugger Debugger instance that owns this process
     * @param pid Process id
     * @param vspace Virtual address space to share with this process
     * @param fds A file descriptor table, potentially shared by other processes
     */
    Process(Debugger& debugger, pid_t pid, ProcessArchitecture arch,
            std::shared_ptr<VirtualAddressSpace> vspace,
            std::shared_ptr<FileDescriptorTable> fds);

    Process(Process &to_clone, pid_t new_pid, bool clone_vm, bool clone_files);
    /**
     * VirtualAddressSpace refers to the associated Process instances via raw pointer.
     * We avoid copying and assignment for this reason.
     */
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;

    ~Process();

    Debugger& get_debugger() {
        return debugger_;
    };

    pid_t get_pid() const {
        return pid_;
    }

    VirtualAddressSpace& get_address_space();
    std::shared_ptr<VirtualAddressSpace> get_address_space_owned();

    FileDescriptorTable& get_fds();
    std::shared_ptr<FileDescriptorTable> get_fds_owned();
    void set_fds(std::shared_ptr<FileDescriptorTable> fds);

    /**
     * Replace the virtual address space of a process.
     * This may be used for when a process replaces its address space with `execve`.
     * @param vspace Virtual address space to set
     */
    void set_address_space(std::shared_ptr<VirtualAddressSpace> vspace);

    /**
     * Set the architecture of the process. This may change when the process loads a binary with
     * a different architecture in its address space using `execve`.
     * @param arch New architecture of the process
     */
    void set_arch(ProcessArchitecture arch);

    void detect_arch();
    void assert_state(ProcessState expected_state);
    void cont(int signal = 0, bool stop_on_syscall = true, bool preserve_ssbp_status = false);
    void single_step(int signal = 0);
    std::optional<WaitEvent> single_step_blocking(int signal = 0);
    bool pop_received_sigstop();
    void enable_received_sigstop();
    void forward_signal(int signal);
    /**
     * Sanity check event and handle internal events
     * @param event Event to handle
     */
    void handle_caught_event(WaitEvent &event);
    WaitEvent wait_until_stopped(bool allow_process_termination = false);
    AArch64RegisterState& get_registers();
    TraceeMemory read_memory(MemoryRegion region);
    TraceeMemory read_memory(uint64_t address, size_t length);
    std::array<unsigned char, 4> read_instruction(uint64_t address);
    void write_memory(uint64_t address, const unsigned char *buf, size_t length);
    AnalysisResult analyze_instructions(uint64_t addr, size_t size);
    CapstoneAnalysisResult disassemble_at_pc();

    bool has_syscall() const;
    const SyscallEvent &get_current_syscall() const;

    /**
     * Execute a system call in the context of the process
     * @param number System call number
     * @param args System call arguments
     * @return System call return value
     */
    uint64_t syscall(aarch64::syscall_number number, std::initializer_list<uint64_t> args);

    /**
     * Install a seccomp BPF filter for this process.
     * New processes spawned from this process will inherit the filter, as it is implemented via
     * PR_SET_NO_NEW_PRIVS
     * @param instructions List of seccomp eBPF instructions to install
     */
    void install_seccomp_filter(std::vector<sock_filter> instructions);

    /**
     * Execute a block of instructions in the context of the process
     * @param data Instruction payload
     * @param size Size of instructions in bytes
     * @param restore_registers Whether to restore the values of all registers after execution of
     * the code block to the values before execution
     * @param new_pc_value Program counter value to set after executing the provided code block. If
     * `restore_registers` is true, all registers will be restored to values before the execution,
     * with the exception of the overridden program counter value if the provided address is not
     * std::nullopt
     */
    void execute_instructions(unsigned char *data, size_t size, bool restore_registers = false,
            std::optional<uint64_t> new_pc_value = std::nullopt);

    /**
     * Print stack frame
     * @param only_top Only print the first stack frame
     * @param override_config Print stack trace even when disabled by the global configuration
     */
    void print_stack_trace(bool only_top = false, bool override_config = false);

    /**
     * Get backtrace of the current process
     * @param only_top Only get the current stack frame
     * @return List of program counter values, each corresponding to a stack frame
     */
    std::vector<uint64_t> get_backtrace(ProcessMapState &map_state, bool only_top = false);

    void print_registers(bool override_config = false);

    void print_memory(uint64_t address, uint64_t length);

    /**
     * Print memory maps according to procfs.
     * Useful for debugging memory map tracking.
     */
    void print_procfs_maps();

    void taint_register(MemoryRegion register_region, std::optional<TaintEvent> annotation);

    std::vector<std::reference_wrapper<TaintEvent>>
    get_register_taints(MemoryRegion register_region);

    std::vector<MemoryRegion> get_tainted_register_regions();

    void print_tainted_registers();

    /**
     * List all tainted registers at register-granularity instead of byte-granularity
     */
    std::vector<arm64_reg> get_tainted_registers();

    /**
     * Return a number of tainted register regions.
     * Note that 1 register may contain multiple taints, each associated with byte-granular taint info
     */
    unsigned long register_taint_count();

    /**
     * Propagate taints from the current instruction.
     * TODO: Finish doc after impl
     * @param ins_anal Disassembly of the instructions starting from the instruction on which we
     * placed a breakpoint
     */
    std::vector<MemoryToTaint> propagate_taints(AnalysisResult& ins_anal, TaintpropBreakpointOptimizer &tbo);

    /**
     * Get the instruction breakpoint at a specified address
     * @param vaddr Virtual address
     * @return Reference to the found breakpoint, std::nullopt if no breakpoint was found
     */
    std::optional<std::reference_wrapper<InstructionBreakpoint>> get_instruction_breakpoint(uint64_t vaddr);

    std::vector<std::reference_wrapper<InstructionBreakpointEntry>> get_instruction_breakpoints(uint64_t vaddr);

    const bool has_pending_pc_breakpoint() const;

    const std::optional<std::pair<uint64_t, InstructionBreakpointEntry>> &
    get_and_clear_pending_pc_breakpoint();

    const bool has_last_load_linked() const;

    std::pair<std::array<unsigned char, 4>, MemoryRegion> get_and_clear_last_load_linked();

    void set_last_load_linked(std::array<unsigned char, 4> instruction, MemoryRegion mem_access);


    /**
     * Insert an instruction breakpoint at a given virtual address.
     * Any process that executes the instruction at that address will raise a SIGTRAP signal.
     * @param reason Breakpoint metadata
     * @param temporary_and_this_pid_only Whether SIGTRAP events raised by this process of the inserted breakpoint
     * should only be handled.
     * The breakpoint will be ignored if this flag is set and another process hits this breakpoint.
     * Additionally, the breakpoint should only be triggered once instead of having
     * effect every time the breakpoint is executed
     * @param remove_at_next_stop Mark the breakpoint for removal when the process is stopped again
     * @param vaddr Where to insert in virtual address space
     * @param handler Handler to be invoked when the breakpoint is triggered
     */
    void insert_instruction_breakpoint(uint64_t vaddr,
                                       BreakpointReason reason,
                                       bool temporary_and_this_pid_only,
                                       bool remove_at_next_stop,
                                       std::optional<std::reference_wrapper<BreakpointHandler>> handler = {});

    /**
     * Insert an instruction breakpoint at the given virtual address.
     * @param vaddr Where to insert in virtual address space
     * @param e Breakpoint entry to add at the given virtual address
     */
    void insert_instruction_breakpoint(uint64_t vaddr, InstructionBreakpointEntry entry);

    /**
     * Disables and removes an instruction breakpoint
     * Note that removal of a temporary or permanent breakpoint does not imply removal of the
     * breakpoint. Only when all temporary breakpoints and the permanent breakpoint are removed will
     * the software breakpoint be removed from memory.
     * @param vaddr Virtual address of the instruction breakpoint to remove
     * @param temporary_and_this_pid_only If set to true, only remove the temporary breakpoint set
     * for this process id. Otherwise, the permanent breakpoint will be removed.
     * @return True if all breakpoints at vaddr have been removed, meaning that the reference to
     * the corresponding InstructionBreakpoint is now invalid.
     */
    bool remove_instruction_breakpoint(uint64_t vaddr, bool temporary_and_this_pid_only);

    /**
     * Toggle an instruction breakpoint breakpoint on/off
     * @param ibp Instruction breakpoint
     * @param vaddr Virtual address of where to place the breakpoint, or where to restore the original
     * instruction
     * @return True if the breakpoint has been enabled, false if the original instructions have been
     * restored
     */
    bool toggle_ins_breakpoint(InstructionBreakpoint& ibp, uint64_t vaddr);

    bool get_single_step_breakpoint() const;

    const std::set<uint64_t> &get_temporary_breakpoints_to_remove() const;

    void clear_temporary_breakpoints_to_remove();

    /**
     * Get the absolute path of a file that is opened by this process
     * @param fd File descriptor of the file of this process
     * @return Canonical file path of the file
     */
    std::string get_fd_path(int fd);

    const std::unique_ptr<BinderTransactionCtx> &get_binder_ctx() const;

    void set_binder_ctx(std::unique_ptr<BinderTransactionCtx> current_binder_tx);

    /**
     * Callback executed after attaching, and after making sure that the process is not stopped at
     * a restart_syscall() syscall-entry event.
     */
    void post_attach_callback();
};
