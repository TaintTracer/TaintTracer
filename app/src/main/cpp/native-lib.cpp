#include <jni.h>
#include <string>
#include <link.h>
#include <cstdint>
#include <logging.h>
#include <unistd.h>
#include <sstream>
#include <Debugging.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include "debugger/Config.h"

#undef LOG_TAG
#define LOG_TAG "TaintTracerTraceMe"

bool is_release() {
    pid_t tid = getppid();
    auto r = ptrace(PTRACE_ATTACH, tid, 0, 0);
    if (r == -1 && errno == EPERM) {
        return true;
    } else if (r == -1) {
        throw std::runtime_error("Failed to attach that wasn't due to insufficient permissions: " + std::string(strerror(errno)));
    } else {
        waitpid(tid, 0, 0);
        TRYSYSFATAL(ptrace(PTRACE_DETACH, tid, 0, 0));
    }
    return false;
}

/*
 * Called by a repackaged app that wants to be debugged.
 * A child process will be created that will debug the app.
 * If the phone has been rooted, we could perform taint analysis
 * by attaching to arbitrary processes directly.
 */
void trace_me(const char *debugger_path) {
    pid_t pid = TRYSYSFATAL(fork());
    if (pid == 0) {
        // Take over process as debugger
        std::stringstream pid_chars_ss;
        pid_chars_ss << getppid();
        std::string pid_chars = pid_chars_ss.str();
        LOGD("Starting debugger with image %s and target pid %s", debugger_path, pid_chars.c_str());
        char *envp[] = { nullptr };
        if (is_release()) {
            // Release mode prevents ptrace() syscall, try as root instead
            LOGD("Launching debugger as root since the debuggable flag is disabled");
            char *argv[] = {"/sbin/su", "-c", const_cast<char *>(debugger_path), const_cast<char *>(pid_chars.c_str()), nullptr };
            TRYSYSFATAL(execve(argv[0], argv, envp));
        } else {
            char *argv[] = {const_cast<char *>(debugger_path), const_cast<char *>(pid_chars.c_str()), nullptr };
            TRYSYSFATAL(execve(argv[0], argv, envp));
        }
    } else {
        // Wait for debugger and continue execution of app
        LOGD("Waiting for debugger to be attached...");
        raise(SIGSTOP);
        LOGD("Debugger has been attached to me!");
    }
}

extern "C" jint JNIEXPORT JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved) {
    if (Config::wait_lldb_without_tracing) {
        LOGI("Config::wait_lldb_without_tracing set! Waiting for LLDB to attach to the app...");
        debug_me();
    } else {
        LOGI("Launching TaintTracer executable");
        auto debugger_path = get_code_dir() + "/lib/arm64/libtainttracer-executable.so";
        trace_me(debugger_path.c_str());
    }
    return JNI_VERSION_1_6;
}