#include <catch2/catch.hpp>
#include <unistd.h>
#include <ghc/filesystem.hpp>
#include <debugger/Debugger.h>
#include <android/logging.h>
#include <exception>
#include <fmt/format.h>
#include <sys/mman.h>
#include "taint_fns.h"

namespace fs = ghc::filesystem;

// Get name of the function while still making sure it's a valid identifier
#define fn_name(x) (x, #x)
std::map<const char *, TaintValues> sources = {
        { fn_name(source_ret9), TaintValues({ARM64_REG_W0}, {}) },
        { fn_name(source_ret42), TaintValues({ARM64_REG_W0}, {}) },
};

std::map<const char *, TaintValues> sinks = {
        { fn_name(sink), TaintValues({ARM64_REG_W0}, {}) },
};

void start_notaint_reference(void (*fn)()) {
    pid_t pid = fork();
    if (pid == -1) {
        throw std::runtime_error("Failed to fork a debugger");
    } else if (pid == 0) {
        // We're the child! Time to get some tainted info from one of the functions
        raise(SIGSTOP); // Cooperative to debugger
        fn();
        _exit(0);
    } else {
        // We're the debugger! Time to trace our child
        auto d = Debugger();
        auto &p = d.attach(pid, true);
        d.debug_trace();
    }
}

/* Returns number of data leak events */
size_t start_taint(void (*fn)()) {
    /* Avoid optimizing away sources that are referenced by name */
    source_ret9();
    source_ret42();
    sink(1);

    pid_t pid = fork();
    if (pid == -1) {
        throw std::runtime_error("Failed to fork a debugger");
    } else if (pid == 0) {
        // We're the child! Time to get some tainted info from one of the functions

        /* Debugger expects a fd to binder to be opened */
        int fd = open("/dev/binder", O_RDWR);
        if (fd < 0) {
            throw std::runtime_error("Failed to open binder device");
        }

        LOGD("child-runner: Waiting for debugger");
        raise(SIGSTOP); // Cooperative to debugger
        LOGD("child-runner: Debugger attached. Executing tainted info test");
        fn();
        close(fd);
        _exit(0);
    } else {
        // We're the debugger! Time to trace our child
        auto d = Debugger();
        auto path_to_current_image = fs::canonical(fs::path("/proc/self/exe")).string();
        for (const auto &source : sources) {
            d.add_native_method_source(path_to_current_image, source.first, source.second);
        }
        for (const auto &sink : sinks) {
            d.add_native_method_sink(path_to_current_image, sink.first, sink.second);
        }
        auto &p = d.attach(pid, true, true, true); // Attach, import memory maps and file handles
        p.cont();
        // Process events until the child has exited
        while (d.get_process(pid)) {
            d.handle_event(d.wait_for_event());
        }
        return d.data_leak_count();
    }
}

void add_two_ints() {
    asm("nop");
    int x = source_ret9();
    int y = source_ret42();
    sink(x+y);
    asm("nop");
}

void copy_and_add_tainted_register() {
    asm("nop");
    int x = source_ret42();
    int y = x;
    y++;
    sink(x + y);
    asm("nop");
}

/**
 * False positive when using capstone
 * mov w0, #0x2000
 * is considered to be a register read and write.
 */
void overwrite_tainted_register_with_const() {
    asm("nop");
    int x = source_ret42();
    asm("mov %w0, #0x2000" :  "+r"(x)); // +r required, register %0 should contain tainted value to overwrite
    sink(x);
    asm("nop");
}

void taint_a_to_i_to_a() {
    int x = source_ret42();
    char buf[3];
    snprintf(buf, 3, "%d", x);
    int y = atoi(buf);
    sink(y);
}

/**
 * String conversion from integer in libc++ reads bytes of text for numbers larger than 10
 * from a string buffer std::__ndk1::__itoa::cDigitsLut indexed by the number to convert
 *
 * Relevant disass for AArch64 in  std::__ndk1::__itoa::append4_no_zeros<unsigned int>(char*, unsigned int)
 *
 *    5e4bcec538 29 0b 00 90     adrp       x9,0x5e4be50000
 *    5e4bcec53c 28 78 1f 53     lsl        w8,param_2,#0x1
 *    5e4bcec540 29 31 30 91     add        x9,x9,#0xc0c
 *    5e4bcec544 28 49 68 78     ldrh       w8,[x9, w8, UXTW #0x0]=>cDigitsLut               = "00010203040506070809101112131
 *    5e4bcec548 08 00 00 79     strh       w8,[param_1]
 *    5e4bcec54c 48 00 80 52     mov        w8,#0x2
 *    5e4bcec550 00 00 08 8b     add        param_1,param_1,x8
 *    5e4bcec554 c0 03 5f d6     ret
 *
 * For numbers less than 10, we add the number to the ASCII character '0' and taint info will be propagated:
 *    5e4bcec4cc 3f 24 00 71     cmp        param_2,#0x9
 *    5e4bcec4d0 48 03 00 54     b.hi       LAB_5e4bcec538      # Jump elsewhere if x > 10
 *    5e4bcec4d4 28 c0 00 11     add        w8,param_2,#0x30    # w8 = x + '0'
 *    5e4bcec4d8 08 00 00 39     strb       w8,[param_1]        # Store ASCII byte in char buffer
 */
void taint_a_to_i_to_a_stdlib() {
    /*
     * Single character case: taint propagation cased by adding const char '0' to argument
     */
    sink(atoi(std::to_string(source_ret9()).c_str()));
    /*
     * Taint propagation caused by propagating taints of w8 during table lookup
     * for ldrh instruction (see function comments)
     */
    sink(atoi(std::to_string(source_ret42()).c_str()));
}

void tainted_array_test() {
    int taint = source_ret42();
    auto vec = std::vector<int> {};
    vec.reserve(1);
    vec.push_back(taint);
    sink(vec[0]);
    vec.push_back(42);
    sink(vec[0]);
    sink(vec[1]);
}

void benchmark_performance() {
    using Clock = std::chrono::high_resolution_clock;
    auto t1 = Clock::now();
    for (size_t i = 0; i < 2*64; i+=8) {
        sink(source_ret42());
    }
    sink(0);
    auto t2 = Clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::nanoseconds>(t2-t1);
    LOGD("Benchmark time diff: %s", std::to_string(diff.count()).c_str());
}


void regression_infinite_loop() {
    using Clock = std::chrono::high_resolution_clock;
    int arr[32];
    constexpr size_t size = sizeof(arr)/sizeof(arr[0]);
    int tainted_value = 0;
    auto t1 = Clock::now();
    tainted_value = source_ret42();
    for (size_t i = 0; i < size; i++) {
        arr[i] = tainted_value;
    }
    auto t2 = Clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::nanoseconds>(t2-t1);
    LOGD("Benchmark time diff: %s", std::to_string(diff.count()).c_str());
    sink(arr[size-1]);
}

void mremap_test() {
    char *buf = (char *) mmap(0, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    buf[0] = (char) source_ret42();
    char *buf_new = (char *) 0x42000;
    mremap(buf, PAGE_SIZE, 2 * PAGE_SIZE, MREMAP_FIXED | MREMAP_MAYMOVE, buf_new);
    sink(buf_new[0]);
    munmap(buf_new, 2 * PAGE_SIZE);
}

TEST_CASE("native taint propagation") {
    SECTION("tainted register") {
        // CHECK(start_taint(add_two_ints) == 1);
        // CHECK(start_taint(copy_and_add_tainted_register) == 1);
        // CHECK(start_taint(overwrite_tainted_register_with_const) == 0);
        // CHECK(start_taint(taint_a_to_i_to_a) == 1);
        // CHECK(start_taint(taint_a_to_i_to_a_stdlib) == 2);
        // CHECK(start_taint(tainted_array_test) == 2);
        // CHECK(start_taint(mremap_test) == 1);
        // start_taint(benchmark_performance);
        start_taint(regression_infinite_loop);
    }
}
