#pragma once

// #define MEASURE_EVENT_TIME

class Config {
public:
    /**
     * Skip over blocks that don't access tainted registers
     */
    static constexpr bool enable_taintprop_optimizer = true;

    /**
     * Stop other processes/threads that can access tainted memory, to avoid taint propagation that
     * we would miss while the memory breakpoint is temporarily disabled
     */
    static constexpr bool stop_reachable_threads = false;

    /**
     * Avoid context switches for system calls that we haven't whitelisted by installing a
     * seccomp BPF filter
     * TODO: Finish implementation, make rest of the code work nicely with ptrace seccomp events
     */
    static constexpr bool only_handle_whitelisted_syscalls = false;

    static constexpr bool set_breakpoint_after_store_conditional = true;


    /* DEBUG OPTIONS */

    /**
     * Block until a debugger has been attached to our debugger
     */
    static constexpr bool wait_lldb = false;

    /**
     * Do not launch tracer, but let LLDB attach to the process before user code will be
     * executed.
     */
    static constexpr bool wait_lldb_without_tracing = false;

    /**
     * Write to log file in sandbox of attached app in addition to the logcat messages.
     * Not all messages are printed properly to logcat, so it is recommended to leave this on
     * while debugging.
     */
    static constexpr bool log_to_file = true;

    /**
     * Write logfile to /data/local/tmp/ instead of inside application data directory whose contents
     * could be erased while the app is running (e.g. com.waze)
     */
    static constexpr bool log_write_to_tmpdir = true;

    /**
     * Write log entries to logcat buffer.
     * Writing to logcat too quickly may cause a read error when reading the logcat buffer from
     * the connected machine.
     */
    static constexpr bool log_to_logcat = false;

    /**
     * Throw a runtime exception when a process accesses invalid memory that is not caused by
     * placing a memory breakpoint. Some applications might catch null-pointer or array
     * out-of-bounds exceptions.
     */
    static constexpr bool throw_on_app_segfault = false;

    /**
     * Print stack trace on received events
     * This slows down the traced application significantly. Only use when debugging.
     */
    static constexpr bool print_stack_trace = false;

    static constexpr bool print_stack_trace_after_first_taint_event = false;

    static constexpr bool print_stack_trace_after_first_egid_syscall = true;

    /**
     * Print instructions and IRSB blocks after disassembly and IR lifting
     */
    static constexpr bool print_instructions = false;

    static constexpr bool print_memory_region_on_mem_access = false;

    static constexpr bool print_registers = false;

    /**
     * Print sent binder payload data
     */
    static constexpr bool print_binder_payload = true;

    /**
     * Print received binder payload data
     */
    static constexpr bool print_binder_received_data = true;

    static constexpr bool print_write_payload = false;

    static constexpr bool print_waiting_procs = false;

    /**
     * Print memory contents of memory ranges watched by MMU and HW breakpoints
     */
    static constexpr bool print_watched_memory = false;

    // Logging macros can be tweaked by setting the desired log level in android/logging.h

};
