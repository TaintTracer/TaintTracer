#include <iostream>
#include <string>
#include <ghc/filesystem.hpp>
#include <optional>
#include "logging.h"
#include <cstdlib>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <linux/elf.h>
#include <asm-generic/unistd.h>
#include <array>
#include <sstream>
#include <linux/prctl.h>

namespace fs = ghc::filesystem;

static uid_t get_uid_from_pid(pid_t pid) {
    struct stat proc_stat;
    char proc_path[12];
    sprintf(proc_path, "/proc/%d", pid);
    TRYSYSFATAL(stat(proc_path, &proc_stat));
    return proc_stat.st_uid;
}

pid_t get_ppid(pid_t pid) {
    char state;
    pid_t ppid;
    auto fs = std::ifstream("/proc/" + std::to_string(pid) + "/stat");
    fs.ignore(std::numeric_limits<std::streamsize>::max(), ')'); // Ignore pid and name
    fs >> state; // Ignore state
    fs >> ppid;
    return ppid;
}

static uid_t get_uid_from_package_name(std::string &package_name) {
    auto package_list = std::ifstream("/data/system/packages.list");
    std::string package_line;
    while(getline(package_list, package_line)) {
        auto package_line_ss = std::istringstream(package_line);
        std::string current_package_name;
        package_line_ss >> current_package_name;
        if (current_package_name != package_name) continue;
        uid_t uid;
        package_line_ss >> uid;
        return uid;
    }
    throw std::runtime_error("No uid found for package with name " + package_name);
}

static std::string get_cmdline(pid_t pid) {
    std::ifstream cmdline_in("/proc/" + std::to_string(pid) + "/cmdline");
    std::string cmdline;
    std::getline(cmdline_in, cmdline, '\0');
    return cmdline;
}

static bool is_status_relevant(int status) {
    // Syscall or ptrace event caused by ptrace option
    return status == ((SIGTRAP | 0x80) << 8 | 0x7f) || (status & (~0xffff));
}

static void continue_process(pid_t pid, int status, int ptrace_request) {
    int signal_to_forward = 0;
    if (!is_status_relevant(status)) {
        int signal_to_forward = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
        std::cerr << "Forwarding non-relevant signal " << signal_to_forward << " to " << pid << " while waiting for syscall event" << std::endl;
    }
    TRYSYSFATAL(ptrace(ptrace_request, pid, 0, signal_to_forward));
}

static int wait_relevant(pid_t pid, int ptrace_request) {
    int status;
    bool relevant;
    do {
        TRYSYSFATAL(waitpid(pid, &status, 0));
        relevant = is_status_relevant(status);
        if (!relevant) {
            int signal_to_forward = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
            std::cerr << "Forwarding non-relevant signal " << signal_to_forward << " to " << pid << " while waiting for syscall event" << std::endl;
            TRYSYSFATAL(ptrace(ptrace_request, pid, 0, signal_to_forward));
        }
    } while (!relevant);
    return status;
}

static void attach_zygote(pid_t pid) {
    TRYSYSFATAL(ptrace(PTRACE_ATTACH, pid, 0, 0));
    int status;
    TRYSYSFATAL(waitpid(pid, &status, 0));
    if (!WIFSTOPPED(status) || WSTOPSIG(status != SIGSTOP)) {
        throw std::runtime_error("Expected SIGSTOP after ptrace() attach");
    }
    TRYSYSFATAL(ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK)); // Trace forked children
    TRYSYSFATAL(ptrace(PTRACE_CONT, pid, 0, 0));
}

static uint64_t wait_syscall(pid_t pid, bool is_64bit) {
    TRYSYSFATAL(ptrace(PTRACE_SYSCALL, pid, 0, 0));

    int status = wait_relevant(pid, PTRACE_SYSCALL);
    user_pt_regs regs;
    struct iovec io {
            .iov_base = &regs,
            .iov_len = sizeof(regs)
    };
    if (!is_64bit) {
        throw std::runtime_error("NYI: 32-bit processes");
    }
    TRYSYSFATAL(ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io));
    std::cerr << "Syscall-entry event: " << std::hex << status << std::dec << std::endl;
    uint64_t syscall_nr = regs.regs[8];
    std::cerr << "Syscall number: " << syscall_nr << std::endl;
    if (syscall_nr > __NR_syscalls) {
        throw std::runtime_error("Syscall number is out-of-bounds");
    }
    TRYSYSFATAL(ptrace(PTRACE_SYSCALL, pid, 0, 0));
    TRYSYSFATAL(waitpid(pid, &status, 0));
    std::cerr << "Syscall-exit event: " << std::hex << status << std::dec << std::endl;
    return regs.regs[8];
}

int main(int argc, char **argv) {
    if (argc < 3) {
        assert(argc > 0);
        std::cerr << "Usage: " << argv[0] << " package_name command_string" << std::endl;
        exit(1);
    }

    std::string package_name = argv[1];
    uid_t target_uid = get_uid_from_package_name(package_name);
    pid_t zygote_pid = -1, zygote64_pid = -1;
    {
        std::optional<pid_t> zygote_pid_opt;
        std::optional<pid_t> zygote64_pid_opt;
        for (const auto &e : fs::directory_iterator("/proc/")) {
            char *end = nullptr;
            pid_t pid = (pid_t) strtol(e.path().filename().c_str(), &end, 10);
            if (*end != '\0') {
                continue; // Ignore non-numeric procfs directories
            }
            if (get_uid_from_pid(pid) != 0) {
                continue; // Skip non-root processes
            }

            std::ifstream cmdline_in(e/"cmdline");
            std::string cmdline;
            std::getline(cmdline_in, cmdline, '\0'); // Skip trailing zero bytes of cmdline
            if (cmdline == "zygote") {
                if (zygote_pid_opt) {
                    throw std::runtime_error("Multiple zygote processes found");
                }
                zygote_pid_opt = pid;
            } else if (cmdline == "zygote64") {
                if (zygote64_pid_opt) {
                    throw std::runtime_error("Multiple zygote64 processes found");
                }
                zygote64_pid_opt = pid;
            }
        }

        if (!zygote_pid_opt) {
            throw std::runtime_error("zygote process not found");
        } else if (!zygote64_pid_opt) {
            throw std::runtime_error("zygote64 process not found");
        }
        zygote_pid = *zygote_pid_opt;
        zygote64_pid = *zygote64_pid_opt;
    }
    std::cerr << "Found zygote (pid " << zygote_pid << "), zygote64 (pid " << zygote64_pid << ")" << std::endl;

    // attach_zygote(zygote_pid); NYI: 32-bit processes
    attach_zygote(zygote64_pid);

    int status;
    while(true) {
        pid_t pid = TRYSYSFATAL(wait(&status));
        if (pid == zygote_pid || pid == zygote64_pid) {
            std::cerr << "Ignoring zygote event with status " << std::hex << status << std::dec << std::endl;
            continue_process(pid, status, PTRACE_CONT);
        } else if (WIFSTOPPED(status) && (get_ppid(pid) == zygote_pid || get_ppid(pid) == zygote64_pid)) {
            std::cerr << "Chlid pid: " << pid << std::endl;
            system(("cat /proc/" + std::to_string(pid) + "/status").c_str());
            std::cerr << "Chlid event: " << std::hex << status << std::dec << std::endl;
            bool is_64bit = get_ppid(pid) == zygote64_pid;
            if (status != (SIGSTOP << 8 | 0x7f) ) {
                throw std::runtime_error("Expected SIGSTOP event of child after fork");
            }
            // Do not trace children of forked process
            TRYSYSFATAL(ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD));
            /*
             * Wait until the UID of the child process is dropped from root to the UID of the app.
             * Process is specialized after forking by com.android.internal.os.specializeAppProcess().
             * TODO: Don't stop so soon, but instead stop right before the first instruction of the
             *       app developer is executed.
             */
            uid_t uid;
            while(wait_syscall(pid, is_64bit) != __NR_setresuid) {}
            if ((uid = get_uid_from_pid(pid)) == 0) {
                throw std::runtime_error("UID is not dropped after setresuid()");
            }

            std::cerr << "Launched app (pid " << pid <<  ") has uid of " << uid << std::endl;
            // Check package name
            if (uid != target_uid) {
                std::cerr << "Ignoring launched app isn't the one we're interested in. Expected uid: " << target_uid << " got: " << uid << std::endl;
                TRYSYSFATAL(ptrace(PTRACE_DETACH, pid, 0, 0));
                continue;
            }

            /*
             * The forked process will be killed when it is stopped for longer than a few seconds
             * unless it is sufficiently initialized.
             * We empirically determine that the process can be stopped after the process has set
             * its name to the package name with prctl().
             */
            auto zygote_cmdline = get_cmdline(pid);
            if (zygote_cmdline.rfind("zygote") == std::string::npos) {
                throw std::runtime_error("Process name after setresuid() is not zygote but is " + zygote_cmdline);
            }
            // Wait for process to change its name from <pre-initialized> to the package
            std::string cmdline;
            while (wait_syscall(pid, is_64bit) && (cmdline = get_cmdline(pid)) != "<pre-initialized>") {}
            while (wait_syscall(pid, is_64bit) && (cmdline = get_cmdline(pid)) == "<pre-initialized>") {}
            std::cerr << "Process name changed from " << zygote_cmdline << " to " << cmdline << std::endl;

            kill(pid, SIGSTOP);
            TRYSYSFATAL(ptrace(PTRACE_CONT, pid, 0, SIGSTOP));
            waitpid(pid, &status, 0);
            TRYSYSFATAL(ptrace(PTRACE_DETACH, pid, 0, 0));
            std::cerr << "Stopped target process " << pid << " with status " << std::hex << status << std::dec << std::endl;

            pid_t command_pid = TRYSYSFATAL(fork());
            if (command_pid == 0) {
                std::string pid_marker = "{}";
                std::string command_string = argv[2];
                size_t pos = command_string.rfind(pid_marker);
                for(; pos != std::string::npos; pos = command_string.rfind(pid_marker)) {
                    command_string.replace(pos, pid_marker.length(), std::to_string(pid));
                }
                std::cout << "Command to execute: " << command_string << std::endl;
                char * const sh_args[] = {"sh", "-c", (char *const)(command_string.c_str()), nullptr};
                execv("/bin/sh", sh_args);
            }
        } else {
            std::cerr << "Ignoring child pid " << pid << " with event " << std::hex << status
                      << std::dec << std::endl;
        }
    }
}
