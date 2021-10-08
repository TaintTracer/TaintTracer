#pragma once

#include <map>
#include <queue>
#include <vector>
#include "Process.h"
#include <debugger/taint/source/NativeMethodSource.h>
#include "ELFImage.h"
#include "WaitEvent.h"
#include "PendingProcessEvents.h"
#include <linux/filter.h>

class Debugger {
private:
    std::map<pid_t, Process> procs_;

    /**
     * Pending events that need to be handled before calling wait() for another event
     * This contains e.g. events raised after restoring original instructions and PTE permissions
     * for memory and software breakpoints.
     */
    PendingProcessEvents pending_events_;

    /**
     * Restores original page permissions and instructions if a process has been stopped because
     * of the inserted memory or instruction breakpoints.
     * Performs taint propagation when needed.
     * @param proc Process that was stopped due to the delivery of a signal
     * @param signal Stop signal
     */
    void handle_stop_signal(Process &proc, int signal);

    /**
     * Breakpoints to be added whenever the associated image is loaded into memory at runtime
     */
    std::multimap<std::string, std::unique_ptr<ImageBreakpoints>> image_breakpoints_;

    /**
     * Data flow events that flow from source to sink
     */
    std::list<TaintEvent> data_leaks_;

    /**
     * Process whose events we must handle exclusively
     * Used for handling events between load-linked and store-conditional instructions
     */
    std::optional<pid_t> priority_process_;

    /**
     * Process id of first process we are attached to
     */
    std::optional<pid_t> root_proc;

public:
    Debugger(); //< Directly used by test runner
    static Debugger &get_instance();

    /**
     * Path to a shared library and offset of a system call instruction, used to invoke system calls
     * in context of a process without writing the system call instruction to process memory.
     * We assume that the shared library (e.g. libc.so) is mapped by each tracee.
     */
    const std::pair<std::string, uint64_t> syscall_instruction_location;

    /**
     * If set to true, do not track taints, but continue tracing executed system calls to log
     * heuristics to compare behavior of app with taint tracking disabled and enabled.
     */
    bool track_taints = true;

    /**
     * Attach to the provided process and all descendants, excluding the debugger process itself.
     * It will attempt to figure out which processes share the same address space based on
     * /proc/pid/{status,smaps}
     * After attaching, membership of address spaces of new processes is known from intercepting
     * clone() and fork() system calls.
     * TODO: It would be ideal if the address of mm_struct can be retrieved from kernel memory...
     * @param pid The process ID to which to attach and its descendants
     */
    void attach_root(pid_t pid);

    /**
     * Attach a single process ID. The attached process will remain in a stopped state.
     * @param pid Process id to trace
     * @param is_cooperative Must be set to true if the process to trace is launched with trace_me,
     * which raised a SIGSTOP signal to itself
     * @param import_mm Whether to import memory maps from procfs
     * @param import_mm Whether to import open file handles from procfs
     * @return Attached process
     */
    Process& attach(pid_t pid, bool is_cooperative = false, bool import_mm = false, bool import_fd = false);

    pid_t get_root_pid();

    /**
     * Remove all instruction and memory breakpoints, followed by detaching from all processes
     */
    void clean_and_detach();

    /**
     * Resume all processes.
     * This method is usually called after attach_root and setting breakpoints at taint sources.
     */
    void cont_all();

    void stop_process(Process &p);

    /**
     * Stop all processes that can reach a given region of memory except for the provided process
     * @param p Process that should not be stopped
     * @param vaddr Virtual address relative to the given process
     */
    void stop_reachable_process_except(Process &proc, MemoryRegion vaddr);

    std::optional<std::reference_wrapper<Process>> get_process(pid_t);

    std::vector<std::reference_wrapper<ImageBreakpoints>> get_image_breakpoints(
            const std::string &image_path);

    /**
     * Add a native method of an executable image as a taint source
     * @param image_path Path to an ELF object
     * @param symbol_name Symbol name of the method
     */
    void add_native_method_source(std::string image_path, std::string symbol_name,
                                TaintValues taint_values);

    void add_native_method_sink(std::string image_path, std::string symbol_name,
                                TaintValues taint_values);

    void add_all_taint_sources();

    TaintEvent& add_data_leak(TaintEvent sink_event);

    const std::list<TaintEvent>& get_data_leaks();

    /**
     * Wait for and returns an event from any traced process
     */
    WaitEvent wait_for_event();

    /**
     * Handle an event
     */
    void handle_event(WaitEvent event);

    /*
     * Handle an event without tracking tainted data
     */
    void handle_event_notaint(WaitEvent event);

    /**
     * Handle event and forward signal without performing any other action.
     * Useful for debugging.
     */
    void handle_event_noop(WaitEvent event);

    /**
     * Print an execution trace of a single process without tracking taints.
     * For debugging purposes: useful to compare original execution trace to ensure correctness
     */
    void debug_trace();

    /**
     * Get the number of data flow events from a source that reached a sink
     */
    size_t data_leak_count();

    /**
     * Log statistics about size of tainted memory region and memory breakpoints for debugging
     */
    void log_taint_size();

    /// For debugging
    static bool at_least_one_taint_event;
    static bool at_least_one_egid_syscall;
};

/**
 * Wait for state changes of one or more processes
 * @param pid Wait for events of a particular process, -1 to wait for events of all traced processes
 * @param allow_process_termination Whether process termination events are expected.
 *        Throws on process termination events if set to false.
 * @return State change event of the process
 */
WaitEvent wait_for_process_events(pid_t pid = -1, bool allow_process_termination = false);

std::vector<sock_filter> compile_syscall_whitelist(std::vector<aarch64::syscall_number> syscalls);