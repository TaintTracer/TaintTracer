#pragma once

#include <sys/types.h>

enum class WaitEventType {
    NORMAL_TERMINATION, ///< Process exited normally with an exit code 0-255
    KILLED_BY_SIGNAL,   ///< Process was killed by a signal
    STOPPED_BY_SIGNAL,  ///< Process was stopped, but not terminated, by a signal
    CONTINUED_BY_SIGNAL ///< Process was resumed by delivery of SIGCONT
};

/**
 * PTrace events caused by setting the corresponding PTRACE_O_TRACE_* options
 */
enum class PTraceTrapEvent {
    NO_EVENT = 0,
    FORK,
    VFORK,
    CLONE,
    EXEC,
    VFORK_DONE,
    EXIT,       ///< Exit, exit status can be retrieved via GETEVENTMSG
    SECCOMP,
    STOP        ///< If tracee stopped, induced by PTRACE_INTERRUPT, group-stop or if PTRACE_SEIZE was used
};

class WaitEvent {
public:
    WaitEvent(int status, pid_t pid);
    pid_t get_pid() const;
    WaitEventType get_event_type() const;
    int get_exit_code() const;
    int get_stop_signal() const;
    /**
     * Whether or not the event has been caused by executing a system call.
     * Note that system calls that we asked ptrace to notify us about using PTRACE_O_* will not
     * cause this function to return true. Use get_ptrace_event() to handle those cases instead.
     */
    bool is_syscall_trap() const;
    int get_killed_signal() const;
    /**
     * Get syscall type, which we explicitly asked to trace using PTRACE_O_* via PTRACE_SETOPTIONS
     * The termination signal for these events is SIGTRAP instead of (SIGTRAP | 0x80), even with
     * PTRACE_O_SYSGOOD
     * @return System call type, otherwise NO_EVENT
     */
    PTraceTrapEvent get_ptrace_event() const;

    int status_;
private:
    pid_t pid_;
    WaitEventType event_;
};
