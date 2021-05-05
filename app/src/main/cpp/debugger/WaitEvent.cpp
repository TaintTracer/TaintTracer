#include "WaitEvent.h"

#include <sys/wait.h>
#include <stdexcept>
#include <linux/ptrace.h>

WaitEvent::WaitEvent(int status, pid_t pid) : status_(status), pid_(pid){
    if (WIFEXITED(status_)) {
        event_ = WaitEventType::NORMAL_TERMINATION;
    } else if (WIFSTOPPED(status_)) {
        event_ = WaitEventType::STOPPED_BY_SIGNAL;
    } else if (WIFSIGNALED(status_)) {
        event_ = WaitEventType::KILLED_BY_SIGNAL;
    } else if (WIFCONTINUED(status_)) {
        event_ = WaitEventType::CONTINUED_BY_SIGNAL;
    } else {
        throw std::runtime_error("Unable to determine wait status type");
    }
}

pid_t WaitEvent::get_pid() const {
    return pid_;
}

WaitEventType WaitEvent::get_event_type() const {
    return event_;
}

int WaitEvent::get_exit_code() const {
    if (get_event_type() != WaitEventType::NORMAL_TERMINATION) {
        throw std::runtime_error("Attempted to get exit code for a process that was not exited normally");
    }
    return WEXITSTATUS(status_);
}


int WaitEvent::get_stop_signal() const {
    if (get_event_type() != WaitEventType::STOPPED_BY_SIGNAL) {
        throw std::runtime_error("Attempted to get signal that caused the process to stop for a process that was not stopped");
    }
    return WSTOPSIG(status_);
}

bool WaitEvent::is_syscall_trap() const {
    return get_event_type() == WaitEventType::STOPPED_BY_SIGNAL && (WSTOPSIG(status_) == (SIGTRAP | 0x80));
}

int WaitEvent::get_killed_signal() const {
    if (get_event_type() != WaitEventType::KILLED_BY_SIGNAL) {
        throw std::runtime_error("Attempted to get termination signal for a non-signalled state change");
    }
    return WTERMSIG(status_);
};

PTraceTrapEvent WaitEvent::get_ptrace_event() const {
    int pt_event = (status_ & 0xff0000) >> 16;
    if(get_event_type() == WaitEventType::STOPPED_BY_SIGNAL
        && (WSTOPSIG(status_) == SIGTRAP || WSTOPSIG(status_) == (SIGTRAP | 0x80))
        && pt_event) {
        switch (pt_event) {
            case PTRACE_EVENT_CLONE:
                return PTraceTrapEvent::CLONE;
            case PTRACE_EVENT_EXEC:
                return PTraceTrapEvent::EXEC;
            case PTRACE_EVENT_EXIT:
                return PTraceTrapEvent::EXIT;
            case PTRACE_EVENT_FORK:
                return PTraceTrapEvent::FORK;
            case PTRACE_EVENT_VFORK:
                return PTraceTrapEvent::VFORK;
            case PTRACE_EVENT_VFORK_DONE:
                return PTraceTrapEvent::VFORK_DONE;
            case PTRACE_EVENT_STOP:
                return PTraceTrapEvent::STOP;
            case PTRACE_EVENT_SECCOMP:
                return PTraceTrapEvent::SECCOMP;
            default:
                throw std::runtime_error("SIGTRAP with additional bits set, but no matching ptrace event found");
        }
    } else {
        return PTraceTrapEvent::NO_EVENT;
    }
}
