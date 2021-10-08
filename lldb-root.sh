#!/usr/bin/env bash
##
# Runs lldb on the device as root, and attach to a process that requested to be debugged.
##

set -e

host_dir="$(dirname "$(readlink -f "$0")")/lldb-target"
lldb_device_dir="/data/local/tmp/lldb-target"

adb shell su -c killall lldb || true
adb shell su -c killall lldb-server || true

# Copy lldb-target to lldb_device_dir
if ! adb shell find "$lldb_device_dir" &>/dev/null ; then
    set -ex
    tar -C "$host_dir" -cvf payload.tar --owner=0 --group=0 .
    adb push payload.tar /sdcard/payload.tar
    adb shell <<EOF
    mkdir -p "$lldb_device_dir"
    cd "$lldb_device_dir"
    tar xvf /sdcard/payload.tar --no-same-owner --no-same-permissions
    rm /sdcard/payload.tar
EOF
    rm payload.tar
fi

echo Waiting for process that requested a debugger...
pid=""
while [ -z "$pid" ]; do
  sleep 0.5
  pid=$(adb shell su -c ps -Ao PID,CMD | awk '$2 == "LLDB_HELP_ME" {print $1}')
done
pid_n=$(echo "\$pid" | wc -l)
if [ "$pid_n" -ne 1 ]; then
  echo Found $pid_n matching pids instead of 1
  exit 1
fi

echo Attaching lldb to pid $pid
expect -c "spawn adb shell
expect "/"
send \"su\\r\"
expect \"#\"
send \"$lldb_device_dir/lldb -O \\\"attach --pid $pid\\\"\ -o continue \r\"
interact"

