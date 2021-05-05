#include "Debugging.h"
#include <android/log.h>
#include <sys/prctl.h>
#include <array>
#include <fstream>
#include <sstream>

void debug_me() {
    char orig_name[16];
    if (prctl(PR_GET_NAME, orig_name) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "WaitForDebugger", "PR_GET_NAME failed");
    }
    if (prctl(PR_SET_NAME, "LLDB_HELP_ME") == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "WaitForDebugger", "PR_SET_NAME failed");
    }
    __android_log_print(ANDROID_LOG_ERROR, "WaitForDebugger", "Process name set to LLDB_HELP_ME. Waiting for debugger to attach to process...");
    raise(SIGSTOP); // Wait for debugger
    if (prctl(PR_SET_NAME, orig_name) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "WaitForDebugger", "PR_GET_NAME failed");
    }
}

void wait_for_lldb(uid_t uid) {
    auto f = std::ifstream(get_data_dir(get_package_name(uid)) + "/.debug-me");
    if (f.good()) {
        __android_log_print(ANDROID_LOG_ERROR, "WaitForDebugger", ".debug-me file present: Waiting for debugger...");
        debug_me();
    } else {
        __android_log_print(ANDROID_LOG_ERROR, "WaitForDebugger", ".debug-me file not present. Continuing execution");
    }
}

std::string get_package_name(uid_t uid) {
    std::array<char, 128> buf;
    std::string pm_out;
    char cmdline[128];
    sprintf(cmdline, "pm list packages --uid %d", uid);
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmdline, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("Failed to spawn child");
    }
    while (fgets(buf.data(), buf.size(), pipe.get()) != NULL) {
        pm_out += buf.data();
    }
    std::string package_name;
    auto pmline = std::istringstream(pm_out);
    if (!(pmline >> package_name)) {
        throw std::runtime_error("No packages associated with the provided uid");
    }
    auto prefix = "package:";
    if (package_name.rfind(prefix) != 0) {
        throw std::runtime_error("package: prefix missing");
    }
    return package_name.substr(strlen(prefix), package_name.size());
}

std::string get_data_dir(std::string package_name) {
    return "/data/data/" + package_name;
}

std::string get_code_dir(std::string package_name) {
    std::array<char, 128> buf;
    std::string pm_out;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen((std::string("pm path ") + package_name).c_str(), "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("Failed to spawn child");
    }
    while (fgets(buf.data(), buf.size(), pipe.get()) != NULL) {
        pm_out += buf.data();
    }
    std::string code_dir;
    auto pmline = std::istringstream(pm_out);
    if (!(pmline >> code_dir)) {
        throw std::runtime_error("No packages associated with the provided uid");
    }
    auto prefix = "package:";
    if (code_dir.rfind(prefix) != 0) {
        throw std::runtime_error("package: prefix missing");
    }
    auto base_pos = code_dir.rfind("/base.apk");
    if (base_pos == std::string::npos) {
        throw std::runtime_error("base.apk suffix missing");
    }
    return code_dir.substr(strlen(prefix), base_pos - strlen(prefix) + 1);
}

void wait_for_lldb_hosted() {
    char orig_name[16];
    if (prctl(PR_GET_NAME, orig_name) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "WaitForDebugger", "PR_GET_NAME failed");
    }
    if (prctl(PR_SET_NAME, "LLDB_HELP_ME") == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "WaitForDebugger", "PR_SET_NAME failed");
    }
    // Run debugger
    auto data_dir = get_data_dir(get_package_name(getuid()));
    auto lldb_path = get_code_dir(get_package_name(getuid())) + "/lib/arm64/liblldb-server.so";
    auto socket_name = "unix-abstract://" + data_dir + "/debug.sock";
    if (fork() == 0) {
        system("killall lldb-server");
        if (execl(lldb_path.c_str(), "lldb-server", "platform", "--server", "--listen", socket_name.c_str(), NULL) == -1) {
            __android_log_print(ANDROID_LOG_ERROR, "LLDB_THREAD", "%s", (std::string("Failed to spawn lldb-server: ")+ strerror(errno)).c_str());
        }
        _exit(1);
    }
    __android_log_print(ANDROID_LOG_ERROR, "WaitForDebugger", "Spawned lldb-server. Waiting for debugger to attach...");
    raise(SIGSTOP); // Wait for debugger
    if (prctl(PR_SET_NAME, orig_name) == -1) {
        __android_log_print(ANDROID_LOG_ERROR, "WaitForDebugger", "PR_GET_NAME failed");
    }
}
