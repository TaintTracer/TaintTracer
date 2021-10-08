#include "android/logging.h"
#include "android/Debugging.h"
#include "debugger/Debugger.h"
#include <debugger/ELFImage.h>
#include <unistd.h>
#include <debugger/procfs/Process.h>
#include <debugger/memory/VirtualAddressSpace.h>
#include <debugger/Config.h>

/**
 * Write log of executed instructions leading to sink events upon receiving SIGUSR1.
 */
extern "C"
void handle_sigusr1(int signum) {
    auto &leaks = Debugger::get_instance().get_data_leaks();
    if (leaks.empty()) {
        LOGW("SIGUSR1 received: No data leak found to log");
    } else {
        LOGI("SIGUSR1 received: Writing log of first data leak out of %d", leaks.size());
        for (const auto &l : leaks) {
            l.plot();
            // break;
        }
    }
}

int main(int argc, char **argv) {
    LOGD("Spawned debugger with pid %d", getpid());
    signal(SIGUSR1, handle_sigusr1);
    if (argc == 1) {
        LOGE("First argument must be a pid");
    }
    pid_t pid = atoi(argv[1]);
    if (!Config::log_to_logcat) {
        __android_log_write(ANDROID_LOG_WARN, LOG_TAG, "Writing to logcat has been disabled in config");
    }
    if (Config::log_to_file) {
        if (Config::log_write_to_tmpdir) {
            android_log_setup("/data/local/tmp/tainttracer_log.txt");
        } else {
            android_log_setup((get_data_dir(get_package_name(get_uid_of_pid(pid))) + "/tainttracer_log.txt").c_str());
        }
    }
    LOGI("Starting new Debugger instance");
    auto &d = Debugger::get_instance();
#ifdef MEASURE_EVENT_TIME
    auto debugger_start = std::chrono::high_resolution_clock::now();
#endif
    if (Config::wait_lldb) {
        debug_me();
    } else {
        wait_for_lldb(get_uid_of_pid(pid));
    }
    d.attach_root(pid);
    auto proc = d.get_process(pid);
    d.cont_all();

    for (;;) {
        auto event = d.wait_for_event();
#ifdef MEASURE_EVENT_TIME
        auto event_start = std::chrono::high_resolution_clock::now();
#endif
        if (d.track_taints) {
            d.handle_event(std::move(event));
        } else {
            d.handle_event_notaint(std::move(event));
        }
#ifdef MEASURE_EVENT_TIME
        auto event_stop = std::chrono::high_resolution_clock::now();
        auto debugger_time = std::chrono::duration_cast<std::chrono::microseconds>(event_start - debugger_start);
        auto event_duration = std::chrono::duration_cast<std::chrono::microseconds>(event_stop - event_start);

        LOGI("Time to handle event: %lld %lld", debugger_time, event_duration);
#endif
    }
    LOGD("Debugger has finished executing");
}
