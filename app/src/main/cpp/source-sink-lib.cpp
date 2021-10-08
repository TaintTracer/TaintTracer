#include <jni.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <android/log.h>
#include <errno.h>
#include <cstring>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <assert.h>
#include <string>
#include <asm/unistd.h>
#include <linux/futex.h>
#include <thread>
#include <sys/utsname.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <vector>
#include <numeric>

#define TAG "SourceSinkTestNative"

void native_sink(const char *buffer, size_t len) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to create socket: %s", strerror(errno));
    }
    const sockaddr_in addr {
            .sin_family = AF_INET,
            .sin_addr.s_addr = inet_addr("192.168.1.59"),
            .sin_port = htons(11211),
    };
    if (connect(sockfd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr)) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to connect to server: %s", strerror(errno));
    }
    if (write(sockfd, buffer, len) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to write to socket: %s", strerror(errno));
    }
    if (close(sockfd) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to close socket: %s", strerror(errno));
    }
}

jstring native_source(JNIEnv *env, jobject contextwrapper) {
    /* We call stable Android Framework methods that call android::IPCThreadState::transact in libbinder.so */
    auto this_clazz = env->GetObjectClass(contextwrapper);
    auto get_content_resolver_method = env->GetMethodID(this_clazz, "getContentResolver", "()Landroid/content/ContentResolver;");
    assert(get_content_resolver_method);
    auto cr = env->CallObjectMethod(contextwrapper, get_content_resolver_method);
    assert(cr);
    auto cr_clazz = env->GetObjectClass(cr);
    auto query_method = env->GetMethodID(cr_clazz, "query", "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;");
    assert(query_method);
    jobject content_uri;
    auto phone_clazz = env->FindClass("android/provider/ContactsContract$CommonDataKinds$Phone");
    {
        auto field_id = env->GetStaticFieldID(phone_clazz, "CONTENT_URI", "Landroid/net/Uri;");
        assert(field_id);
        content_uri = env->GetStaticObjectField(phone_clazz, field_id);
    }
    auto selection = env->NewStringUTF("has_phone_number > 0");
    auto cursor = env->CallObjectMethod(cr, query_method, content_uri, nullptr, selection, nullptr, nullptr);
    assert(cursor);
    env->DeleteLocalRef(selection);
    auto cursor_clazz = env->GetObjectClass(cursor);
    auto move_to_next_method = env->GetMethodID(cursor_clazz, "moveToNext", "()Z");

    if (env->CallBooleanMethod(cursor, move_to_next_method)) {
        jstring phone_col;
        {
            auto field_id = env->GetStaticFieldID(phone_clazz, "NUMBER", "Ljava/lang/String;");
            assert(field_id);
            phone_col = static_cast<jstring>(env->GetStaticObjectField(phone_clazz, field_id));
        }
        auto get_column_index_method = env->GetMethodID(cursor_clazz, "getColumnIndex", "(Ljava/lang/String;)I");
        assert(get_column_index_method);
        jint col_idx = env->CallIntMethod(cursor, get_column_index_method, phone_col);
        auto get_string_method = env->GetMethodID(cursor_clazz, "getString", "(I)Ljava/lang/String;");
        assert(get_string_method);
        auto res = env->CallObjectMethod(cursor, get_string_method, col_idx);
        assert(res);
        return (jstring) res;
    } else {
        jclass Exception = env->FindClass("java/lang/Exception");
        env->ThrowNew(Exception, "No contacts in contact list");
        throw std::runtime_error("Unreachable?");
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_nativeSink(JNIEnv *env,
                                                                            jobject thiz,
                                                                            jstring tainted_string) {
    const char *tainted_string_native = env->GetStringUTFChars(tainted_string, 0);
    native_sink(tainted_string_native, strlen(tainted_string_native));
    env->ReleaseStringUTFChars(tainted_string, tainted_string_native);
}

extern "C"
JNIEXPORT jstring JNICALL
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_nativeSource(JNIEnv *env,
                                                                              jobject thiz) {
    return native_source(env, thiz);
}

extern "C"
JNIEXPORT void JNICALL
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_nativeSourceToNativeSink(
        JNIEnv *env, jobject thiz) {
    jstring tainted_data = native_source(env, thiz);
    const char *tainted_cstr = env->GetStringUTFChars(tainted_data, 0);
    native_sink(tainted_cstr, strlen(tainted_cstr));
    env->ReleaseStringUTFChars(tainted_data, tainted_cstr);
}


extern "C"
JNIEXPORT void JNICALL
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_runRegressionTests(JNIEnv *env,
                                                                                        jobject thiz) {
    // Allocate buffer
    char *buf;
    long err = posix_memalign((void **)&buf, PAGE_SIZE, PAGE_SIZE);
    if (err != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to allocate memory page");
    }
    int *futex = (int *)(buf + PAGE_SIZE - sizeof(int)); // Futex within the same page

    // Taint buffer
    jstring tainted_data = native_source(env, thiz);
    const char *tainted_cstr = env->GetStringUTFChars(tainted_data, 0);
    buf[0] = tainted_cstr[0];
    env->ReleaseStringUTFChars(tainted_data, tainted_cstr);

    // Spawn thread to wake up waiting processes with futex() at the tainted memory buffer
    // and ensure that the main thread unblocks
    *futex = 0;
    auto t = std::thread([&] {
        usleep(1000000);
        // Wake up main thread
        err = syscall(__NR_futex, futex, FUTEX_WAKE, 1, nullptr, nullptr, 0);
        if (err == -1) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to wake up main thread with futex(): %s", strerror(errno));
        }
    });

    // Wait for other thread
    err = syscall(__NR_futex, futex, FUTEX_WAIT, 0, nullptr, nullptr, 0);
    if (err == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to wait for futex: %s", strerror(errno));
    }
    t.join();
    __android_log_print(ANDROID_LOG_INFO, TAG, "Regression tests passed!");
}

/*
extern "C" const uint64_t input[10] = { 52, 8121, 15, 548, 2154, 293, 41586, 1452, 4586, 12545 };

// Perform a single iteration of the benchmark.
// We use assembly to reason about number of executed instructions deterministically
extern "C"
__attribute__((no_stack_protector))
uint64_t overhead_benchmark_iteration() {
    // Solve longest increasing subsequence of a given array
    uint64_t max_len = 1;
    uint64_t dp[10];

    for (uint64_t &dp_i : dp) {
        dp_i = 1;
    }

    for (uint64_t i = 0; i < 10; i++) {
        for (uint64_t j = i + 1; j < 10; j++) {
            if (input[i] < input[j]) {
                uint64_t lis_i = dp[i] + 1;
                uint64_t lis_j = dp[j];
                dp[j] = lis_j < lis_i ? lis_i : lis_j;
                max_len = max_len < dp[j] ? dp[j] : max_len;
            }
        }
    }

    return max_len;
}
*/
extern "C" uint64_t overhead_benchmark_iteration();

asm(R"asm(
.global overhead_benchmark_iteration
.type  overhead_benchmark_iteration, @function
.text
overhead_benchmark_iteration:
    sub        sp,sp,#0x50
    adrp       x9,input
    add        x9,x9,#:lo12:input

    // Initialize dp array to contain all 1s
    mov        w0,#0x1
    dup        v0.2D,x0
    stp        q0,q0,[sp]
    stp        q0,q0,[sp, #0x20]
    str        q0,[sp, #0x40]
    mov        x10,sp

    mov        x8,xzr // Initialize input index
outer_loop:
    cmp        x8,#0xa
    b.eq       cleanup
    mov        x11,x8
    add        x8,x8,#0x1
    cmp        x8,#0x9
    b.hi       outer_loop
    ldr        x12,[x9, x11, LSL #0x3] // Load input
    mov        x13,x8
    b          inner_loop
inner_loop_inc:
    add        x13,x13,#0x1
    cmp        x13,#0xa
    b.eq       outer_loop
inner_loop:
    ldr        x14,[x9, x13, LSL #0x3]
    cmp        x12,x14
    b.cs       inner_loop_inc // Only process input that is greater than the current index
    ldr        x14,[x10, x11, LSL #0x3] // dp of outer loop
    lsl        x15,x13,#0x3
    ldr        x16,[x10, x15, LSL #0x0] // dp of inner loop
    add        x17,x14,#0x1
    cmp        x17,x16
    csinc      x14,x16,x14,ls
    // Set return value to the highest LIS found so far
    cmp        x0,x14
    csel       x0,x14,x0,cc
    // Store LIS up until index x13 to dynamic programming array
    str        x14,[x10, x15, LSL #0x0]
    b          inner_loop_inc
cleanup:
    add        sp,sp,#0x50
    ret

.data
input: .quad  52, 8121, 15, 548, 2154, 293, 41586, 1452, 4586, 12545
)asm");

/*
 * @param buffer        Pointer to tainted data
 * @param size          Size of buffer
 * @param iterations    Number of benchmark iterations to execute
 * @param taint_iters   Amount of times to process tainted data
 *
 * Number of instructions of overhead_benchmark:
 * 12 // Stack and argument setup, epilogue and return
 * + (iterations - 1) * (6 + 691) // All but the last iteration
 * + (4 + 691) // Last iteration
 * + taint_iters * (1 + instructions that process tainted data)
 * = 10 + iterations * (6 + 691) + taint_iters * (1 + 6)
 */
extern "C" void overhead_benchmark(char *buffer, size_t size, uint64_t iterations, uint64_t taint_iters);
asm(R"bench(
.global overhead_benchmark
.type  overhead_benchmark, @function
.text
overhead_benchmark:
    stp        x22,x21,[sp, #-0x30]!
    stp        x20,x19,[sp, #0x10]
    stp        x29,x30,[sp, #0x20]
    add        x29,sp,#0x20

    mov        x19,x0  // buffer ptr
    mov        x20,xzr // iteration counter
    mov        x21,x2  // iterations
    mov        x22,x3  // taint_iters
1:
    bl         overhead_benchmark_iteration // Execute 691 instructions (see evaluation/overhead/count_ins_native.sh)
    add        x20,x20,#0x1 // Increment iteration counter

    cmp        x20,x21      // Return if max iterations reached
    b.eq       2f

    // Process tainted data taint_iters times
    cmp        x20,x22
    b.gt       1b

    // Process tainted data
    ldrb       w8,[x19]
    add        w8,w8,#0x1
    lsl        w8,w8,#0x3
    sub        w8,w8,#0x7
    lsr        w8,w8,#0x1
    strb       w8,[x19]

    b          1b
2:
    ldp        x29,x30,[sp, #0x20]
    ldp        x20,x19,[sp, #0x10]
    ldp        x22,x21,[sp], #0x30
    ret
)bench");

extern "C" void overhead_benchmark_runner(char *buffer, size_t size) {
    const auto samples = 10;
    auto iterations = 100000;

    auto taint_iterations = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    for (const auto t_it : taint_iterations) {
        std::vector<long long> benchmark_times;
        benchmark_times.reserve(samples);
        for (int i = 0; i < samples; i++) {
            const auto& start = std::chrono::high_resolution_clock::now();
            overhead_benchmark(buffer, size, iterations, t_it);
            const auto& stop = std::chrono::high_resolution_clock::now();
            long long time = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count();
            benchmark_times.push_back(time);
            __android_log_print(ANDROID_LOG_INFO, TAG, "Native benchmark time (%d taint iters): %lld ns", t_it, time);
        }
        double sum = std::accumulate(benchmark_times.begin(), benchmark_times.end(), 0.0);
        double mean = sum / benchmark_times.size();
        std::vector<double> mean_diff(benchmark_times.size());
        std::transform(benchmark_times.begin(), benchmark_times.end(), mean_diff.begin(), [mean](long long i) { return i - mean; });
        double squared_sum = std::inner_product(mean_diff.begin(), mean_diff.end(), mean_diff.begin(), 0.0);
        double stddev = std::sqrt(squared_sum / benchmark_times.size());
        __android_log_print(ANDROID_LOG_INFO, TAG, "Average native benchmark time (%d taint iters): %f ns (stddev: %f ns)", t_it, mean, stddev);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_runNativeOverheadBenchmark(JNIEnv *env,
                                                                                          jobject thiz) {

    constexpr size_t size = 4096;
    char *tainted_data = static_cast<char *>(mmap(0, size, PROT_READ | PROT_WRITE,
                                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    std::fill(tainted_data, tainted_data + size, 'Q');
    syscall(__NR_getegid, 0xF00DCAFE, tainted_data, size);
    overhead_benchmark_runner(tainted_data, size);
    munmap(tainted_data, size);
}


/*
 * Total amount of executed instructions:
 * 13 + 24 * iterations + 16
 * With 100 iterations: 2429
 */
extern "C" void new_overhead_benchmark(int64_t *buffer, uint64_t iterations);
asm(R"bench(
.macro sample_computation xreg
    add        \xreg,\xreg,#0x1
    lsl        \xreg,\xreg,#0x3
.endm

.global new_overhead_benchmark
.type  new_overhead_benchmark, @function
.text
new_overhead_benchmark:
    stp        x22,x21,[sp, #-0x30]!
    stp        x20,x19,[sp, #0x10]
    stp        x29,x30,[sp, #0x20]
    add        x29,sp,#0x20

    mov        x19,x0  // current buffer pointer
    mov        x20,xzr // current iteration
    mov        x21,x0  // original buffer
    mov        x22,x1  // total iterations

    // Load data from buffer in x0-x9
    ldp        x0, x1, [x19], #16
    ldp        x2, x3, [x19], #16
    ldp        x4, x5, [x19], #16
    ldp        x6, x7, [x19], #16
    ldp        x8, x9, [x19], #16
1:
    // Clean up and return if total iterations reached
    cmp        x20,x22
    b.eq       2f

    // Perform a computation within the same register
    sample_computation x0
    sample_computation x1
    sample_computation x2
    sample_computation x3
    sample_computation x4
    sample_computation x5
    sample_computation x6
    sample_computation x7
    sample_computation x8
    sample_computation x9

    add        x20,x20,#0x1 // Increment iteration counter
    b          1b
2:
    // Clean tainted data for next benchmark sample
    mov        x0,xzr
    mov        x1,xzr
    mov        x2,xzr
    mov        x3,xzr
    mov        x4,xzr
    mov        x5,xzr
    mov        x6,xzr
    mov        x7,xzr
    mov        x8,xzr
    mov        x9,xzr

    ldp        x29,x30,[sp, #0x20]
    ldp        x20,x19,[sp, #0x10]
    ldp        x22,x21,[sp], #0x30
    ret
)bench");

extern "C" void new_overhead_benchmark_runner(const char *buffer) {
    const auto samples = 10;
    auto iterations = 500;
    // First byte of buffer that contains untainted data
    // The bytes before it are tainted
    const char *first_untainted = buffer + 4096;

    // Run a benchmark that reads 10 64-bit values into registers starting from varying offsets
    // such that a varying amount of registers contain tainted data, followed by processing tainted data
    for (int tainted_registers = 0; tainted_registers <= 10; tainted_registers++) {
        std::vector<long long> benchmark_times;
        benchmark_times.reserve(samples);
        for (int i = 0; i < samples; i++) {
            auto *slice = (int64_t *) (first_untainted - sizeof(int64_t) * tainted_registers);
            const auto& start = std::chrono::high_resolution_clock::now();
            new_overhead_benchmark(slice, iterations);
            const auto& stop = std::chrono::high_resolution_clock::now();
            long long time = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count();
            benchmark_times.push_back(time);
            __android_log_print(ANDROID_LOG_INFO, TAG, "New native benchmark time (%d tainted regs): %lld ns", tainted_registers, time);
        }
        double sum = std::accumulate(benchmark_times.begin(), benchmark_times.end(), 0.0);
        double mean = sum / benchmark_times.size();
        std::vector<double> mean_diff(benchmark_times.size());
        std::transform(benchmark_times.begin(), benchmark_times.end(), mean_diff.begin(), [mean](long long i) { return i - mean; });
        double squared_sum = std::inner_product(mean_diff.begin(), mean_diff.end(), mean_diff.begin(), 0.0);
        double stddev = std::sqrt(squared_sum / benchmark_times.size());
        __android_log_print(ANDROID_LOG_INFO, TAG, "Average new native benchmark time (%d tainted regs): %f ns (stddev: %f ns)", tainted_registers, mean, stddev);
    }
}

extern "C"
JNIEXPORT void JNICALL
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_runNewNativeOverheadBenchmark(JNIEnv *env,
                                                                                          jobject thiz) {
    // Allocate an 8k buffer, half of which contains tainted data
    constexpr size_t buffer_size = 2 * 4096;
    char *buffer = static_cast<char *>(mmap(0, buffer_size, PROT_READ | PROT_WRITE,
                                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    std::fill(buffer, buffer + buffer_size, 'Q');
    // Mark first 4k bytes as tainted
    syscall(__NR_getegid, 0xF00DCAFE, buffer, buffer_size / 2);
    new_overhead_benchmark_runner(buffer);
    munmap(buffer, buffer_size);
}


extern "C"
JNIEXPORT void JNICALL
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_runNewNativeOverheadBenchmarkParameterized(
        JNIEnv *env, jobject thiz, jint iterations, jint tainted_registers) {
    // Allocate an 8k buffer, half of which contains tainted data
    constexpr size_t buffer_size = 2 * 4096;
    char *buffer = static_cast<char *>(mmap(0, buffer_size, PROT_READ | PROT_WRITE,
                                            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
    std::fill(buffer, buffer + buffer_size, 'Q');
    // Mark first 4k bytes as tainted
    syscall(__NR_getegid, 0xF00DCAFE, buffer, buffer_size / 2);

    // First byte of buffer that contains untainted data
    // The bytes before it are tainted
    const char *first_untainted = buffer + 4096;
    auto *slice = (int64_t *) (first_untainted - sizeof(int64_t) * tainted_registers);
    const auto& start = std::chrono::high_resolution_clock::now();
    new_overhead_benchmark(slice, iterations);
    const auto& stop = std::chrono::high_resolution_clock::now();
    long long time = std::chrono::duration_cast<std::chrono::nanoseconds>(stop - start).count();
    __android_log_print(ANDROID_LOG_INFO, TAG, "New native benchmark time (%d tainted regs): %lld ns", tainted_registers, time);

    munmap(buffer, buffer_size);
}

extern "C"
JNIEXPORT void JNICALL
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_markByteArrayAsTainted(JNIEnv *env,
                                                                                      jobject thiz,
                                                                                      jbyteArray array,
                                                                                      jint offset,
                                                                                      jint size) {
    jboolean isCopy;
    jbyte *elems = env->GetByteArrayElements(array, &isCopy);
    __android_log_print(ANDROID_LOG_ERROR, TAG, "isCopy: %d - %llx", isCopy, (unsigned long long)elems);
    if (isCopy) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "GetByteArrayElements: isCopy is true and must be false");
        abort();
    }
    syscall(__NR_getegid, 0xF00DCAFE, elems + offset, size);
    env->ReleaseByteArrayElements(array, elems, JNI_ABORT);
}

extern "C"
JNIEXPORT void JNICALL
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_markIntArrayAsTainted(JNIEnv *env,
                                                                                      jobject thiz,
                                                                                      jintArray array,
                                                                                      jint offset,
                                                                                      jint size) {
    jboolean isCopy;
    jint *elems = env->GetIntArrayElements(array, &isCopy);
    __android_log_print(ANDROID_LOG_ERROR, TAG, "isCopy: %d - %llx", isCopy, (unsigned long long)elems);
    if (isCopy) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "GetIntArrayElements: isCopy is true and must be false");
        abort();
    }
    syscall(__NR_getegid, 0xF00DCAFE, elems + offset, size * sizeof(jint));
    env->ReleaseIntArrayElements(array, elems, JNI_ABORT);
}

extern "C"
JNIEXPORT void JNICALL
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_markLongArrayAsTainted(JNIEnv *env,
                                                                                      jobject thiz,
                                                                                      jlongArray array,
                                                                                      jint offset,
                                                                                      jint size) {
    jboolean isCopy;
    jlong *elems = env->GetLongArrayElements(array, &isCopy);
    __android_log_print(ANDROID_LOG_ERROR, TAG, "isCopy: %d - %llx", isCopy, (unsigned long long)elems);
    if (isCopy) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "GetLongArrayElements: isCopy is true and must be false");
        abort();
    }
    syscall(__NR_getegid, 0xF00DCAFE, elems + offset, size * sizeof(jlong));
    env->ReleaseLongArrayElements(array, elems, JNI_ABORT);
}