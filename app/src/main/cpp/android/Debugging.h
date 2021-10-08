#pragma once

#include <unistd.h>
#include <string>

/**
 * Set the process name to LLDB_HELP_ME and suspends all threads.
 */
void debug_me();

/**
 * Wait for LLDB debugger to attach using debug-tainttracer.sh
 * @param uid User ID of the whome directory to look for .debug-me file
 */
void wait_for_lldb(uid_t uid);

/**
 * Launch lldb-server in the background and wait for an lldb client to attach to the process.
 * This is useful for when the run-as command is forbidden if the debuggable flag of the manifest
 * is not enabled.
 * This method requires that the precompiled lldb-server is bundled together with the APK
 * such that it is installed in the code directory (/data/app/.../lib/arm64/) by placing
 * the executable under app/src/main/jniLibs/[abi]/lib*.so where [abi] is the ABI of the target
 * (e.g. arm64-v8a).
 * The executable needs to match the regex `lib*.so` for it to be installed to the code dir.
 * Since Android 10, executing binaries with the exec* syscalls require the binary to be
 * placed in the code directory, and not the writable data directory.
 * See this thread for more info: https://old.reddit.com/r/androiddev/comments/b2inbu/psa_android_q_blocks_executing_binaries_in_your/
 *
 * The following commands can be useful for the lldb instance on the host to attach to the server:
 * ```
 * package_name=$(cat app/build.gradle | perl -ne '/applicationId.*"(.+)"/ && print $1')
 * socket_path=/data/data/$package_name/debug.sock
 * lldb -S ./lldbinit -O "platform select remote-android" -o "platform connect unix-abstract-connect://$socket_path"
 * ```
 *
 * TODO: Attaching a release build of an app fails with `error: attach failed: unable to launch a GDB server on 'localhost'`
 * This should not be an issue for TaintTracer, since we can modify this flag when repackaging.
 */
void wait_for_lldb_hosted();

/**
 * Get package name of the given uid without JNIEnv
 * @param uid User id generated for the app
 * @return Package name
 */
std::string get_package_name(uid_t uid);

/**
 * Get the path to the data directory for the given package name without JNIEnv
 */
std::string get_data_dir(std::string package_name = get_package_name(getuid()));

/**
 * Get the path to the read-only code directory of the given package name without JNIEnv
 */
std::string get_code_dir(std::string package_name = get_package_name(getuid()));
