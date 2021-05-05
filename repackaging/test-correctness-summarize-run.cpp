//usr/bin/env command -v jq &>/dev/null || { echo "jq has not been installed" >&2; exit 1; }
//usr/bin/env g++ -g -std=c++17 "$0" && exec ./a.out "$@"

#include <iostream>
#include <string>
#include <sstream>
#include <fstream>
#include <regex>
#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

std::string exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

struct Metrics {
    int max_taint_size; ///< Largest amount of memory considered tainted at some point during run
    int procs_attached; ///< Number of traced processes
    int activity_crashes; ///< Number of Activity threads that have stopped
    int tracer_crashes; ///< Number of tracer crashes
    int native_crashes; ///< Number of native processes that have crashed, excluding tracer crashes
    int errors; ///< Number of error messages
    int syscall_errors; ///< System call errors happen regularly, so might not be a good heuristic
    int sigreturn; ///< Number of handled signal handlers
    int clone; ///< Number of created processes
    int execve; ///< Number of executable image replacements (execve() syscalls)
    int exit; ///< Number of processes exited
};

int main(int argc, char *argv[]) {
    if (argc < 5) {
        cerr << "4 arguments should be provided" << endl;
        exit(1);
    }
    auto apk_path = string(argv[1]);
    auto run_dir = string(argv[2]);
    auto original_runs_dir = string(argv[3]);
    auto out_csv_path = string(argv[4]);

    smatch sm;
    if (!regex_search(run_dir, sm, regex("([^/]+)-[^-]+$"))) {
        throw runtime_error("Failed to get package id: incorrect amount of regex matches");
    }
    auto package_id = string(sm[1]);

    if (!regex_search(run_dir, sm, regex("-([^-\\/]+)\\/?$"))) {
        throw runtime_error("Failed to get run label: incorrect amount of regex matches");
    }
    auto run_label = string(sm[1]);

    auto original_run_dir = original_runs_dir + "/" + package_id + "-original";

    if (!fs::exists(original_run_dir)) {
        throw runtime_error("original run directory doesn't exist: " + original_run_dir);
    }

    auto metrics = Metrics {};

    // Precompile regex
    auto tainted_mem_size_regex = regex("Tainted memory size .*: ([0-9]+) B");
    auto syscall_regex = regex("System call entry.*: ([a-z_]+)");
    auto process_file = [&] (string &log_path) {
        auto f = ifstream(log_path);
        string line;
        while(getline(f, line)) {
            if (line.find("Tainted memory size") != string::npos) {
                if (!regex_search(line, sm, tainted_mem_size_regex)) {
                    throw runtime_error("Failed to get tainted memory size from log line: " + line);
                }
                metrics.max_taint_size = max(metrics.max_taint_size, stoi(sm[1]));
            }
            if (line.find("Process suspended for the first time after attaching") != string::npos) {
                metrics.procs_attached++;
            }
            if (line.find("ActivityManager: Process ") != string::npos && line.find(package_id) != string::npos) {
                // Log activity crashes of the app that was instrumented
                metrics.activity_crashes++;
            }
            if (line.find("__set_errno_internal") != string::npos || line.find("ThrowByNameWithLastError") != string::npos) {
                metrics.errors++;
            }
            if (line.find("System call error") != string::npos) {
                metrics.syscall_errors++;
            }
            if (line.find("F DEBUG   : pid:") != string::npos) {
                if (line.find("libtainttracer-executable.so") != string::npos) {
                    metrics.tracer_crashes++;
                } else {
                    metrics.native_crashes++;
                }
            }
            if (line.find("System call entry") != string::npos) {
                if (!regex_search(line, sm, syscall_regex)) {
                    throw std::runtime_error("Failed to capture system call name");
                }
                auto syscall = string(sm[1]);
                if (syscall == "clone") {
                    metrics.clone++;
                } else if (syscall == "exit") {
                    metrics.exit++;
                } else if (syscall == "sigreturn" || syscall == "sigreturn_rt") {
                    metrics.sigreturn++;
                } else if (syscall == "execve") {
                    metrics.execve++;
                }
            }
        }
    };

    auto logfiles = { run_dir + "/logcat_processed.txt", run_dir + "/tainttracer_log.txt" };
    for (auto l : logfiles) {
        if (fs::exists(l)) {
            process_file(l);
        }
    }

    auto perms_cmd = "dep/Apktool/brut.apktool/apktool-lib/build/resources/main/prebuilt/linux/aapt d permissions '" + apk_path + "' | "
    + R"EOF(perl -ne '/name='"'"'(.*)'"'"'/ && print $1 . "\n"')EOF";
    auto has_contacts_perm = exec(perms_cmd.c_str()).find("android.permission.READ_CONTACTS") != string::npos;

    // Compare reached activities
    auto get_reached_activities = [&package_id] (string run_dir) -> vector<string> {
        auto res = vector<string>();
        auto cmd_result = exec(("jq -r '.foreground_activity' '" + run_dir + "'/states/*.json | grep '" + package_id + "/' | sort | uniq").c_str());
        auto ss = istringstream(cmd_result);
        string line;
        while (getline(ss, line)) {
            res.emplace_back(move(line));
        }
        sort(res.begin(), res.end());
        return res;
    };

    auto reached_activities = get_reached_activities(run_dir);
    auto reached_activities_orig = get_reached_activities(original_run_dir);
    auto reached_activities_intersection = vector<string>();
    auto reached_activities_union = vector<string>();
    set_intersection(reached_activities.begin(), reached_activities.end(), reached_activities_orig.begin(), reached_activities_orig.end(), back_inserter(reached_activities_intersection));
    set_union(reached_activities.begin(), reached_activities.end(), reached_activities_orig.begin(), reached_activities_orig.end(), back_inserter(reached_activities_union));

    bool csv_exists = fs::exists(out_csv_path);
    auto csv = ofstream(out_csv_path, ios::app);
    if (!csv_exists) {
        csv << "Package id,Has contacts permission,Run label,Foreground activities,Reached activities intersection,Reached activities union,Max taint size,Attached processes,Tracer crashes,Native crashes,Activity crashes,errors,syscall errors,sigreturn,clone,execve,exit\n";
    }

    std::vector<string> row = {
        package_id,
        has_contacts_perm ? "true" : "false",
        run_label,
        to_string(reached_activities.size()),
        to_string(reached_activities_intersection.size()),
        to_string(reached_activities_union.size()),
        to_string(metrics.max_taint_size),
        to_string(metrics.procs_attached),
        to_string(metrics.tracer_crashes),
        to_string(metrics.native_crashes),
        to_string(metrics.activity_crashes),
        to_string(metrics.errors),
        to_string(metrics.syscall_errors),
        to_string(metrics.sigreturn),
        to_string(metrics.clone),
        to_string(metrics.execve),
        to_string(metrics.exit)
    };

    for (size_t i = 0; i < row.size(); i++) {
        if (i != 0) {
            csv << ",";
        }
        csv << row[i];
    }
    csv << '\n';

    return 0;
}
