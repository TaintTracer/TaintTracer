set -e

package_name=$(cat app/build.gradle | perl -ne '/applicationId.*"(.+)"/ && print $1')
lldb_server_path="./lldb/bin/lldb-server"  # Default path used by android studio
socket_path=/data/data/$package_name/debug.sock

adb shell run-as $package_name touch .debug-me
adb shell run-as $package_name killall lldb-server || true

if ! adb shell run-as $package_name find "$lldb_server_path"; then
  adb push ~/bin/android-studio/bin/lldb/android/arm64-v8a/lldb-server /sdcard/lldb-server
  adb shell run-as $package_name mkdir -p \"$(dirname "$lldb_server_path")\"
  adb shell run-as $package_name mv /sdcard/lldb-server \"$lldb_server_path\"
  adb shell run-as $package_name chmod +x \"$lldb_server_path\"
fi
adb shell run-as $package_name \"$lldb_server_path\" platform --server --listen "unix-abstract://$socket_path" &

echo Waiting for process that requested a debugger...
pid=""
while [ -z "$pid" ]; do
  sleep 0.5
  pid=$(adb shell run-as $package_name ps -Ao PID,CMD | awk '$2 == "LLDB_HELP_ME" {print $1}')
done
pid_n=$(echo "\$pid" | wc -l)
if [ "$pid_n" -ne 1 ]; then
  echo Found $pid_n matching pids instead of 1
  exit 1
fi

# Spawn lldb debugger installed on the host machine, attach remote process via adb and continue once to handle raise(SIGSTOP)
lldb -S ./lldbinit -O "platform select remote-android" -o "platform connect unix-abstract-connect://$socket_path" -o "attach --pid $pid" -o continue

adb shell run-as $package_name rm .debug-me
adb shell run-as $package_name killall lldb-server
