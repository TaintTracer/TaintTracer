#if 1
#include <catch2/catch.hpp>
#include <unistd.h>
#include <sys/ptrace.h>
#include <android/logging.h>
#include <debugger/Debugger.h>
#include <sys/wait.h>
#include <sys/syscall.h>

static int worker_thread(void*) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
    while(1) {
        LOGW("I am doing some work");
        usleep(1000);
    }
#pragma clang diagnostic pop
}

TEST_CASE("ptrace stopping single threads using custom signal") {
    int pid = fork();
    if (pid == 0) {
        worker_thread(nullptr);
    }
    LOGD("ptrace behavior test: spawned child %d", pid);
    REQUIRE(pid > 0);
    TRYSYSFATAL(ptrace(PTRACE_ATTACH, pid, 0, 0));
    auto event = wait_for_process_events(-1);
    REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
    REQUIRE(event.get_stop_signal() == SIGSTOP);

    // waitpid causes event to be considered as handled by the kernel, and will not return
    // the same status, even though the process hasn't resumed
    int status;
    REQUIRE(0 == waitpid(-1, &status, WNOHANG));
    REQUIRE(0 == waitpid(pid, &status, WNOHANG));

    // Unblock SIGUSR1 signal, which we will use to stop a single thread
    sigset_t t;
    TRYSYSFATAL(ptrace(PTRACE_GETSIGMASK, pid, sizeof(t), &t));
    REQUIRE(sigismember(&t, SIGUSR1));
    sigdelset(&t, SIGUSR1);
    TRYSYSFATAL(ptrace(PTRACE_SETSIGMASK, pid, sizeof(t), &t));

    TRYSYSFATAL(ptrace(PTRACE_CONT, pid, 0, 0));

    // Interrupt the process without causing the process to enter a signal handler
    syscall(__NR_tkill, pid, SIGUSR1);
    event = wait_for_process_events(-1);
    REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
    REQUIRE(event.get_stop_signal() == SIGUSR1);
    REQUIRE(0 == waitpid(pid, &status, WNOHANG));

    TRYSYSFATAL(ptrace(PTRACE_CONT, pid, 0, 0)); // Don't forward SIGUSR1
    REQUIRE(0 == waitpid(pid, &status, WNOHANG));
    kill(pid, SIGKILL);
    event = wait_for_process_events(-1);
    REQUIRE(event.get_event_type() == WaitEventType::KILLED_BY_SIGNAL);
    REQUIRE(event.get_killed_signal() == SIGKILL);
}

int cloning_worker(void*) {
    constexpr int stack_size = 65536;
    char *stacks = new char[stack_size];
    int child_pid = clone(worker_thread, stacks + stack_size, CLONE_VM | CLONE_SIGHAND | CLONE_THREAD,
                          nullptr);
    LOGD("Wohoo created subchild %d", child_pid);
    TRYSYSFATAL(child_pid);
    worker_thread(nullptr);
    return 0;
}

/*
TEST_CASE("tgkill(..., SIGSTOP) without ptrace stops the entire thread group") {
    int child = fork();
    TRYSYSFATAL(child);
    if (child == 0) {
        cloning_worker(nullptr);
    }
    syscall(__NR_tkill, child, SIGSTOP);
    usleep(999999999); // Manually inspect /proc/
    // Clean up child and grandchild
    kill(child, SIGKILL);
}
*/

TEST_CASE("tgkill(..., SIGSTOP) with ptrace stops single thread") {
    int child = fork();
    TRYSYSFATAL(child);
    if (child == 0) {
        raise(SIGSTOP);
        cloning_worker(nullptr);
    }
    LOGD("SIGSTOP test: spawned child %d", child);
    TRYSYSFATAL(ptrace(PTRACE_ATTACH, child, 0, 0));
    auto event = wait_for_process_events(child);
    REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
    REQUIRE(event.get_stop_signal() == SIGSTOP);
    TRYSYSFATAL(ptrace(PTRACE_SETOPTIONS, child, 0, 0
                        | PTRACE_O_TRACECLONE    // Automatically trace cloned processes
    ));
    TRYSYSFATAL(ptrace(PTRACE_CONT, child, 0, 0));
    event = wait_for_process_events(child);
    REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
    REQUIRE(event.get_stop_signal() == SIGSTOP);
    syscall(__NR_tkill, child, SIGCONT); // Must be sent before unsuspending
    TRYSYSFATAL(ptrace(PTRACE_CONT, child, 0, 0));
    event = wait_for_process_events(child);
    REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
    REQUIRE(event.get_stop_signal() == SIGCONT);
    TRYSYSFATAL(ptrace(PTRACE_CONT, child, 0, 0));

    event = wait_for_process_events(child);
    REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
    REQUIRE(event.get_ptrace_event() == PTraceTrapEvent::CLONE);
    TRYSYSFATAL(ptrace(PTRACE_CONT, child, 0, 0));

    event = wait_for_process_events(-1);
    int subchild = event.get_pid();
    REQUIRE(subchild != child);
    LOGD("Got grandchild pid %d", subchild);
    TRYSYSFATAL(ptrace(PTRACE_CONT, subchild, 0, 0));

    // Try to suspend only the child without grandchild
    // A regular kill() would completely stop the thread group with process state `T (stopped)`
    syscall(__NR_tkill, child, SIGSTOP);
    int status;
    event = wait_for_process_events(child);
    REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
    REQUIRE(event.get_stop_signal() == SIGSTOP);
    // At this point, the tracee has a process state of t (tracing stop)
    constexpr bool cont_with_sigstop = false;
    if (cont_with_sigstop) {
        // Sending SIGSTOP via PTRACE_CONT causes wait() to return SIGSTOP
        // The process that is SIGSTOPed has state t (tracing stop)
        TRYSYSFATAL(ptrace(PTRACE_CONT, child, 0, SIGSTOP));
        event = wait_for_process_events(child);
        REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
        REQUIRE(event.get_stop_signal() == SIGSTOP);
    } else {
        TRYSYSFATAL(ptrace(PTRACE_CONT, child, 0, 0));
        status = 0;
        pid_t waitpid_res = waitpid(child, &status, WNOHANG);
        REQUIRE(status == 0);
        REQUIRE(0 == waitpid_res);
    }

    // Grandchild is unaffected, even though it has the same tgid
    REQUIRE(0 == waitpid(child, &status, WNOHANG));

    // Clean up child and grandchild
    kill(child, SIGKILL);
    event = wait_for_process_events(-1);
    REQUIRE(event.get_event_type() == WaitEventType::KILLED_BY_SIGNAL);
    REQUIRE(event.get_killed_signal() == SIGKILL);
    event = wait_for_process_events(-1);
    REQUIRE(event.get_event_type() == WaitEventType::KILLED_BY_SIGNAL);
    REQUIRE(event.get_killed_signal() == SIGKILL);
}

/*
TEST_CASE("ptrace stopping single threads with SIGSTOP") {
    constexpr int stack_size = 65536;
    constexpr int threads = 2;
    char *stacks = new char[threads * stack_size];
    int pids [threads];
    int status;

    for (int i = 0; i < threads; i++) {
        pids[i] = clone(worker_thread, stacks + (threads - i) * stack_size, CLONE_VM|CLONE_SIGHAND|CLONE_THREAD, nullptr);
        LOGD("ptrace clone() test: Spawned pid %d", pids[i]);
        TRYSYSFATAL(pids[i]);
        TRYSYSFATAL(ptrace(PTRACE_ATTACH, pids[i], 0, 0)); // Operation not permitted if CLONE_THREAD is enabled???
        auto event = wait_for_process_events(pids[i]);
        REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
        REQUIRE(event.get_stop_signal() == SIGSTOP);
        REQUIRE(0 == waitpid(pids[i], &status, WNOHANG));
    }

    // Stop single thread and check if the other is still running
    syscall(__NR_tkill, pids[0], SIGSTOP);
    auto event = wait_for_process_events(pids[0]);
    REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
    REQUIRE(event.get_stop_signal() == SIGSTOP);
    REQUIRE(0 == waitpid(pids[0], &status, WNOHANG));
    REQUIRE(0 == waitpid(pids[1], &status, WNOHANG));

    for (int i = 0; i < threads; i++) {
        kill(pids[i], SIGKILL);
    }
}
*/
#endif
