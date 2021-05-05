#!/usr/bin/env bash
##
# Runs a lldb-server instance on the device as root, and attach to a process that requested
# to be debugged.
##

set -e

lldb_path="/data/local/tmp/lldb-server"
adb push $HOME/Android/Sdk/ndk/*/toolchains/llvm/prebuilt/linux-x86_64/lib64/clang/*/lib/linux/aarch64/lldb-server "$lldb_path"
adb shell chmod +x "$lldb_path"

# socket="/data/local/tmp/root.sock"
# Connecting to the remote UNIX socket isn't stable: 'failed to get reply to handshake packet'
# We use the TCP transport instead.
# LLDB will do the forwarding via adb for us
port="22222"

# if ! adb shell su -c lsof | grep $socket &>/dev/null; then
if ! adb shell su -c lsof | grep "TCP :$port" &>/dev/null; then
  ## Launch server
  echo "Starting LLDB as root"
  # adb shell su -c $lldb_path platform --server --listen unix-abstract://$socket &
  adb shell su -c $lldb_path platform --server --listen 127.0.0.1:$port &
fi


echo Waiting for process that requested a debugger...
pid="$1"
while [ -z "$pid" ]; do
  sleep 0.5
  pid=$(adb shell su -c ps -Ao PID,CMD | awk '$2 == "LLDB_HELP_ME" {print $1}')
done
pid_n=$(echo "\$pid" | wc -l)
if [ "$pid_n" -ne 1 ]; then
  echo Found $pid_n matching pids instead of 1
  exit 1
fi

# Spawn lldb debugger installed on the host machine, attach remote process via adb and continue once to handle raise(SIGSTOP)
# lldb -S ./lldbinit -O "platform select remote-android" -o "platform connect unix-abstract-connect://$socket" -o "attach --pid $pid" -o continue
lldb -S ./lldbinit -O "platform select remote-android" -o "platform connect connect://localhost:$port" -o "attach --pid $pid" -o continue
