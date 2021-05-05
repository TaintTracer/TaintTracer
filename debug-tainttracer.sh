#!/usr/bin/env bash
##
# Set up debugging environment using LLDB with ncurses support on the device itself.
# A start.sh script will be placed into the sandbox of the target application
# which attaches to any process that is in a stopped state, e.g. by calling
# wait_for_lldb() in android/Debugging.h
##

set -ex
package_name=$(cat app/build.gradle | perl -ne '/applicationId.*"(.+)"/ && print $1')

host_dir="$(dirname "$(readlink -f "$0")")/lldb-target"
device_dir="files/lldb" # Directory relative to data dir inside the app sandbox

clean() {
  adb shell run-as $package_name <<EOF
  rm -rf "$device_dir"
EOF
}

# clean

# Copy lldb-target to device_dir
if ! adb shell run-as $package_name find "$device_dir" &>/dev/null ; then
    set -ex
    tar -C "$host_dir" -cvf payload.tar --owner=0 --group=0 .
    adb push payload.tar /sdcard/payload.tar
    adb shell run-as $package_name <<EOF
    mkdir -p "$device_dir"
    cd "$device_dir"
    tar xvf /sdcard/payload.tar --no-same-owner --no-same-permissions
    rm /sdcard/payload.tar
EOF
    rm payload.tar
fi

# Copy debug.sh start script
cat - <<EOF > payload.sh
  set -x
  data_dir="\$(pwd)"
  debug_file="\$data_dir/.debug-me"
  cd "$device_dir"
  rm start.sh || true
  touch "\$debug_file" # Presence of this file causes application to SIGSTOP
  pid=""
  while [ -z "\$pid" ]; do
    echo Waiting for process that requested a debugger
    sleep 0.5
    pid=\$(ps -Ao PID,CMD| awk '\$2 == "LLDB_HELP_ME" {print \$1}')
  done
  pid_n=\$(echo "\$pid" | wc -l)
  if [ \$pid_n -ne 1 ]; then
    echo Found \$pid_n matching pids instead of 1
    exit 1
  fi
  echo Found process with stopped state with pid \$pid
  export LD_LIBRARY_PATH=.
  export TERMINFO=\$(pwd)/terminfo
  ./lldb --attach-pid \$pid
  rm "\$debug_file"
EOF
adb push payload.sh /sdcard/payload.sh
rm payload.sh
adb shell run-as $package_name <<EOF
  cp /sdcard/payload.sh debug.sh
  rm /sdcard/payload.sh
  chmod +x debug.sh
EOF

# Copy source files to device to enable on-device debugging
src_dir_host="$(pwd)/app/src"
src_tarball="$(pwd)/src.tar"
cd "$src_dir_host"
find . -type f \( -iname \*.c -o -iname \*.h -o -name \*.cpp -o -iname \*.hpp -o -iname \*.cc -o -iname \*.hh \) | tar -cvf "$src_tarball" -T -
cd -
adb push "$src_tarball" /sdcard/src.tar
rm "$src_tarball"
adb shell run-as $package_name <<EOF
  set -ex
  rm -rf src || true
  mkdir src
  tar -C src -xvf /sdcard/src.tar --no-same-owner --no-same-permissions
  rm /sdcard/src.tar
  echo "settings set target.source-map $src_dir_host \$(pwd)/src" > .lldbinit
EOF

echo "Spawning an interactive shell. Enter the following commands to enter lldb"
echo "  ./debug.sh"

./adb-cmd.sh run-as $package_name
