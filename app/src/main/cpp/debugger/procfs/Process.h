#pragma once

#include <sys/types.h>
#include <set>

/**
 * Get real user id of a running process
 * @param pid Process id
 * @return Real user id
 */
uid_t get_uid_of_pid(pid_t pid);

/**
 * Get parent process id of a running process
 * @param pid Process id
 * @return Parent process id
 */
pid_t get_ppid(pid_t pid);

/**
 * List all processes that match a given real user id
 * @param uid User id
 * @param list_threads Include process ids that are threads (processes with pid != tgid)
 * @return Process id list
 */
std::set<pid_t> get_all_uid_pids(uid_t uid, bool list_threads);

/**
 * List all process with the same real uid as the uid of the provided process.
 * We treat threads (processes with a shared thread group id) and process the same.
 * @param pid Process to obtain the user id from
 * @param include_root Whether to include the provided process in the list
 * @param exclude_self Whether to include the process id of the debugger itself
 * @return Process id list of all sub-processes
 */
std::set<pid_t> get_all_user_pids(pid_t pid, bool include_root, bool include_self);

/**
 * Get the process state as reported by procfs.
 * The following states can be reported:
 *     R  Running
 *     S  Sleeping in an interruptible wait
 *     D  Waiting in uninterruptible disk sleep
 *     Z  Zombie
 *     T  Stopped (on a signal)
 *     t  Tracing stop
 *     X  Dead
 */
char get_proc_state(pid_t pid);

/**
 * Get command name of process
 */
std::string get_comm(pid_t pid);
