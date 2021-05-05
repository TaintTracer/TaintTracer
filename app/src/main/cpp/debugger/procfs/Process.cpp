#include <fstream>
#include <android/logging.h>
#include <ghc/filesystem.hpp>
#include <sstream>
#include <dirent.h>
#include <unistd.h>
#include "Process.h"
#include <fmt/format.h>

namespace fs = ghc::filesystem;

uid_t get_uid_of_pid(pid_t pid) {
    auto uid = 0;

    auto procfs_status = std::ifstream("/proc/" + std::to_string(pid) + "/status");
    if (procfs_status.fail()) {
        throw std::runtime_error("Failed to get status of target process");
    }
    auto line = std::string {};
    while(std::getline(procfs_status, line)) {
        if (line.rfind("Uid") != std::string::npos) {
            auto ss = std::istringstream{line};
            auto _ignore = std::string{};
            ss >> _ignore;
            ss >> uid;
            return (uid_t) uid;
        }
    }
    throw std::runtime_error("No process found with matching uid");
}

std::set<pid_t> get_all_uid_pids(uid_t uid, bool list_threads) {
    auto proclist = std::set<pid_t>{};

    struct dirent *dir;
    DIR *d = opendir("/proc");
    if (!d) {
        throw std::runtime_error("Failed to open procfs");
    }
    while((dir = readdir(d)) != nullptr)  {
        char first_digit = dir->d_name[0];
        if (!isdigit(first_digit)) continue;
        auto pid = std::stoi(std::string(dir->d_name));
        auto current_uid = get_uid_of_pid(pid);
        if (uid == current_uid) {
            proclist.insert(pid);
            if (list_threads) {
                for (const auto& tid_path : fs::directory_iterator("/proc/" + std::to_string(pid) + "/task")) {
                    auto tid = (pid_t) std::stoi(tid_path.path().stem());
                    if (pid == tid) continue;
                    auto [it, inserted] = proclist.insert(tid);
                    if (!inserted) {
                        throw std::runtime_error("Tried to insert an already existing pid");
                    }
                }
            }
        }
    }
    return proclist;
}

std::set<pid_t> get_all_user_pids(pid_t pid, bool include_root, bool include_self) {
    auto root_uid = get_uid_of_pid(pid);
    auto proclist = get_all_uid_pids(root_uid, true);
    auto target_in_list = proclist.find(pid);
    assert(target_in_list != proclist.end());
    if (!include_root) {
        proclist.erase(pid);
    }
    if (!include_self) {
        if (auto it = proclist.find(getpid()); it != proclist.end()) {
            proclist.erase(it);
        } else {
            LOGW("get_all_user_pids: self not found in list, skipping deletion");
        }
    }
    return proclist;
}

char get_proc_state(pid_t pid) {
    std::string stat;
    char state;
    {
        auto fs = std::ifstream(fmt::format("/proc/{}/stat", pid));
        std::getline(fs, stat);
        auto statepos = stat.rfind(")"); // Find last occurrence since process name might contain ')'
        if (statepos == std::string::npos) {
            throw std::runtime_error("Failed to find ')' character in stat line");
        }
        statepos += 2; // Skip ')' and space
        state = stat.at(statepos); // Ignore pid and name
    }
    switch (state) {
        case 'R':
        case 'S':
        case 'D':
        case 'Z':
        case 'T':
        case 't':
        case 'X':
            return state;
        default:
            throw std::runtime_error(fmt::format("Process {} has unexpected procfs state '{}' from line {}", pid, state, stat));
    }
}

pid_t get_ppid(pid_t pid) {
    char state;
    pid_t ppid;
    auto fs = std::ifstream(fmt::format("/proc/{}/stat", pid));
    fs.ignore(std::numeric_limits<std::streamsize>::max(), ')'); // Ignore pid and name
    fs >> state; // Ignore state
    fs >> ppid;
    return ppid;
}

std::string get_comm(pid_t pid) {
    auto comm = std::string {};
    auto fs = std::ifstream(fmt::format("/proc/{}/comm", pid));
    fs >> comm;
    return comm;
}
