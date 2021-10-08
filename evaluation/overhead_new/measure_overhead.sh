#!/usr/bin/env bash
set -eo pipefail
set -x
trap 'kill $(jobs -p)' INT TERM EXIT
package_name=$(cat ../../app/build.gradle | perl -ne '/applicationId.*"(.+)"/ && print $1') 
lcfile="logcat.txt"
csv="results.csv"
 
for cmd in adb xmlstarlet perl; do
  if ! [ -x "$(command -v $cmd)" ]; then
    echo "error: $cmd is not installed" >&2
    exit 1
  fi
done
 
get_ui_dump() {
    adb shell -tt 'uiautomator dump /dev/fd/2 1>/dev/null'
}
 
get_tap_coords() {
    # Return center coordinates of element matching a given text
    local dump="$1"
    local text="$2"
 
    local bounds_raw="$(xmlstarlet sel -T -t -v '//node[@text="'"$text"'"]/@bounds' <<< "$dump")"
    if [ -z "$bounds_raw" ]; then
        echo "No UI element found with text '$text'" >&2
        exit 1
    fi
    perl -ne '/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/ && print int(int($1+$3)/2) . " " . int(int($2+$4)/2)' <<< "$bounds_raw"
}

tap() {
  adb shell input tap "$1"
}

new_logcat() {
  if [ -n "$logcat_pid" ]; then
    kill $logcat_pid
    wait $logcat_pid || true
  fi
  rm -f "$lcfile"
  while ! adb logcat -c; do
    echo "Retrying adb logcat -c" >&2
  done
  (adb logcat > "$lcfile")&
  logcat_pid=$!
}

sample() {
  system="$1"
  environment="$2"
  tainted_regs="$3"

  if [ "$system" == TaintTracer ]; then
    echo "Starting app with tracer"
    (cd ../../; exec ./run.sh > /dev/null)& # Launch tracer
    tracer_shell=$!
    sleep 5
  else
    adb shell monkey -p $package_name -c android.intent.category.LAUNCHER 1
    sleep 2
  fi

  set_bench_config $environment $tainted_regs
  ui_dump="$(get_ui_dump)"
  new_logcat
  tap "$(get_tap_coords "$ui_dump" "AUTOMATED OVERHEAD BENCHMARK")"
  echo "Waiting for $environment benchmark to complete with $tainted_regs tainted regs and system: $system"
  if [ "$system" == TaintTracer ]; then
    sleep 10
  else
    sleep 5
  fi
  extract_logs $system $environment

  if [ "$system" == TaintTracer ]; then
    kill $tracer_shell
  fi
}

set_bench_config() {
  environment="$1"
  tainted_regs="$2"
  adb shell 'su -c "echo -e '"$environment\\\\\n$tainted_regs"' > /data/data/'"$package_name"'/files/bench.command"'
}

extract_logs() {
  system="$1" # None or TaintTracer
  environment="$2" # native or java
  if [ ! -f "$csv" ]; then
    echo "system,environment,tainted registers,time" > "$csv"
  fi
  cat "$lcfile" | perl -ne '/New (\w+) benchmark time \((\d+) tainted regs\): (\d+)/ && print "'"$system"'", ",", $1, ",", $2, ",", $3, "\n"' | tee -a "$csv"
}

# Install benchmark app
adb shell 'su -c "setprop pm.dexopt.install everything"'
adb uninstall $package_name
pushd ../..
./gradlew installRelease
popd

adb shell pm clear $package_name
adb shell pm grant $package_name android.permission.READ_CONTACTS || echo "Failed to grant read contacts permission. Ignoring..." >&2
adb shell pm grant $package_name android.permission.ACCESS_COARSE_LOCATION || echo "Failed to grant access coarse location permission. Ignoring..." >&2
adb shell pm grant $package_name android.permission.ACCESS_FINE_LOCATION || echo "Failed to grant access fine location permission. Ignoring..." >&2

rm -f "$csv" || true

for environment in native java; do
  for system in None TaintTracer; do
    for tainted_regs in {0..10}; do
      for s in {0..10}; do
        sample $system $environment $tainted_regs
      done
    done
  done
done
