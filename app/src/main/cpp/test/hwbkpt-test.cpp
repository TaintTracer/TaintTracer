#include <android/log.h>
#define ANDROID_LOG_FN __android_log_print

#include <catch2/catch.hpp>
#include <unistd.h>
#include <android/logging.h>
#include <sys/ptrace.h>
#include <debugger/Debugger.h>
#include <debugger/WaitEvent.h>
#include <linux/uio.h>
#include <elf.h>
#include <asm/ptrace.h>

__attribute__((noinline))
static void noop() {
    asm("");
}

TEST_CASE("Hardware instruction breakpoints") {
    int pid = fork();
    if (pid == 0) {
        while(1) {
            noop();
            usleep(1000);
        }
    }
    auto wait_for_signal = [pid] (int signal) {
        auto event = wait_for_process_events(pid);
        REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
        REQUIRE(event.get_stop_signal() == signal);
    };
    LOGD("hw ins bp test: spawned child %d", pid);
    REQUIRE(pid > 0);
    TRYSYSFATAL(ptrace(PTRACE_ATTACH, pid, 0, 0));
    wait_for_signal(SIGSTOP);
    LOGD("Tracee stopped");
    auto bp = user_hwdebug_state {};
    auto bp_iov = iovec {
        .iov_base = &bp,
        .iov_len = offsetof(user_hwdebug_state, dbg_regs),
    };
    TRYSYSFATAL(ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_BREAK, &bp_iov));
    memset(&bp, 0, sizeof(user_hwdebug_state));
    bp.dbg_regs[0].addr = reinterpret_cast<uint64_t >(&noop);
    bp.dbg_regs[0].ctrl = 0xf << 5 | 1; // Break on A64 instruction
    bp_iov.iov_base = &bp;
    bp_iov.iov_len = offsetof(user_hwdebug_state, dbg_regs) + sizeof(bp.dbg_regs[0]);
    TRYSYSFATAL(ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_BREAK, &bp_iov));
    LOGD("HW Breakpoint set!");
    TRYSYSFATAL(ptrace(PTRACE_CONT, pid, 0, 0));
    wait_for_signal(SIGTRAP);
    LOGD("Tracee stopped because of our breakpoint!");
    kill(pid, SIGKILL);
    auto killed_event = wait_for_process_events(pid);
    CHECK(killed_event.get_event_type() == WaitEventType::KILLED_BY_SIGNAL);
    CHECK(killed_event.get_killed_signal() == SIGKILL);
}

TEST_CASE("Hardware memory breakpoints") {
    volatile int tainted_word = 0xbabe;
    int pid = fork();
    if (pid == 0) {
        while(1) {
            tainted_word++;
            usleep(1000);
        }
    }
    auto wait_for_signal = [pid] (int signal) {
        auto event = wait_for_process_events(pid);
        REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
        REQUIRE(event.get_stop_signal() == signal);
    };
    LOGD("hw mem bp test: spawned child %d", pid);
    REQUIRE(pid > 0);
    TRYSYSFATAL(ptrace(PTRACE_ATTACH, pid, 0, 0));
    wait_for_signal(SIGSTOP);
    LOGD("Tracee stopped");
    auto bp = user_hwdebug_state {};
    auto bp_iov = iovec {
            .iov_base = &bp,
            .iov_len = offsetof(user_hwdebug_state, dbg_regs),
    };
    TRYSYSFATAL(ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &bp_iov));
    memset(&bp, 0, sizeof(user_hwdebug_state));
    bp.dbg_regs[0].addr = reinterpret_cast<uint64_t >(&tainted_word);
    // Watch mem r/w using the BAS of DBGWCRn_EL1 for setting the memory size
    bp.dbg_regs[0].ctrl = ((1<<sizeof(tainted_word)) - 1) << 5 | 0b11 << 3 | 1; // Watch mem r/w
    bp_iov.iov_base = &bp;
    bp_iov.iov_len = offsetof(user_hwdebug_state, dbg_regs) + sizeof(bp.dbg_regs[0]);
    TRYSYSFATAL(ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &bp_iov));
    LOGD("HW Memory Breakpoint set!");
    TRYSYSFATAL(ptrace(PTRACE_CONT, pid, 0, 0));
    wait_for_signal(SIGTRAP);
    LOGD("Tracee stopped because of our breakpoint!");
    kill(pid, SIGKILL);
    auto killed_event = wait_for_process_events(pid);
    CHECK(killed_event.get_event_type() == WaitEventType::KILLED_BY_SIGNAL);
    CHECK(killed_event.get_killed_signal() == SIGKILL);
}

// MASK bits aren't writable on my device
#if 0
TEST_CASE("Hardware memory breakpoints with address mask (> 8 B)") {
    volatile char tainted_data[16] = {0};
    int pid = fork();
    if (pid == 0) {
        while(1) {
            tainted_data[0]++;
            usleep(1000);
        }
    }
    auto wait_for_signal = [pid] (int signal) {
        auto event = wait_for_process_events(pid);
        REQUIRE(event.get_event_type() == WaitEventType::STOPPED_BY_SIGNAL);
        REQUIRE(event.get_stop_signal() == signal);
    };
    LOGD("hw mem bp test: spawned child %d", pid);
    REQUIRE(pid > 0);
    TRYSYSFATAL(ptrace(PTRACE_ATTACH, pid, 0, 0));
    wait_for_signal(SIGSTOP);
    LOGD("Tracee stopped");
    auto bp = user_hwdebug_state {};
    auto bp_iov = iovec {
            .iov_base = &bp,
            .iov_len = sizeof(user_hwdebug_state),
    };
    TRYSYSFATAL(ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &bp_iov));
    LOGD("Watchpoint value register: 0x%llx", bp.dbg_regs[0].addr);
    LOGD("Watchpoint control register: 0x%08x", bp.dbg_regs[0].ctrl);
    memset(&bp, 0, sizeof(user_hwdebug_state));

    uint64_t start_addr = (uint64_t) tainted_data;
    uint64_t end_addr = start_addr + sizeof(tainted_data);
    int lz = __builtin_clzll(start_addr ^ (end_addr - 1));
    uint32_t mask_bits = (uint32_t)(64 - lz); // Index of MSB that differs between start and end address
    assert(3 <= mask_bits);
    assert(mask_bits < 32);
    bp.dbg_regs[0].addr = (uint64_t) tainted_data & ~((1ULL << mask_bits)-1);
    bp.dbg_regs[0].ctrl = 0 << 24 | 0 << 5 | 0b11 << 3 | 1; // Watch mem r/w
    LOGD("Start data ptr: 0x%" PRIx64, start_addr);
    LOGD("End data ptr: 0x%" PRIx64, end_addr - 1);
    LOGD("Watchpoint value register: 0x%llx", bp.dbg_regs[0].addr);
    LOGD("Watchpoint control register: 0x%08x", bp.dbg_regs[0].ctrl);
    bp_iov.iov_base = &bp;
    bp_iov.iov_len = offsetof(user_hwdebug_state, dbg_regs) + sizeof(bp.dbg_regs[0]);
    TRYSYSFATAL(ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &bp_iov));
    LOGD("HW Memory Breakpoint set!");
    TRYSYSFATAL(ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &bp_iov));
    LOGD("Validated watchpoint value register: 0x%llx", bp.dbg_regs[0].addr);
    LOGD("Validated watchpoint control register: 0x%08x", bp.dbg_regs[0].ctrl);
    TRYSYSFATAL(ptrace(PTRACE_CONT, pid, 0, 0));
    wait_for_signal(SIGTRAP);
    LOGD("Tracee stopped because of our breakpoint!");
    kill(pid, SIGKILL);
    auto killed_event = wait_for_process_events(pid);
    CHECK(killed_event.get_event_type() == WaitEventType::KILLED_BY_SIGNAL);
    CHECK(killed_event.get_killed_signal() == SIGKILL);
}
#endif
