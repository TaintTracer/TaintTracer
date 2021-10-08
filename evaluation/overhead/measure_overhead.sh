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

extract_logs() {
  system="$1" # None or TaintTracer
  environment="$2" # native or java
  if [ ! -f "$csv" ]; then
    echo "system,environment,taint iterations,mean (us),stddev (us),total instructions,tainted instructions" > "$csv"
  fi
  case $environment in
    native)
      inspe='",", 10 + 100000 * (6+691) + $2 * (1 + 6), ",", $2 * 6'
      ;;
    java)
      inspe='",", 100000 * (6 + 803) + $2 * 11, ",", $2 * 11'
      ;;
    *)
      echo "Invalid environment specified: got $environment instead of native or java" >&2
      exit 1
      ;;
  esac
 
  cat "$lcfile" | perl -ne '/Average (\w+) benchmark time \((\d+) taint iters\): (\d+\.\d+).*(\d+\.\d+)/ && print "'"$system"'", ",", $1, ",", $2, ",", $3, ",", $4, '"$inspe"', "\n"' | tee -a "$csv"
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

adb shell monkey -p $package_name -c android.intent.category.LAUNCHER 1

ui_dump="$(get_ui_dump)"

new_logcat
tap "$(get_tap_coords "$ui_dump" "NATIVE OVERHEAD BENCHMARK")"
echo "Waiting for native benchmark to complete without tracer..."
sleep 5
extract_logs None native

new_logcat
tap "$(get_tap_coords "$ui_dump" "JAVA OVERHEAD BENCHMARK")"
echo "Waiting for java benchmark to complete without tracer..."
sleep 5
extract_logs None java


echo "Restarting app with tracer"
(cd ../../; exec ./run.sh > /dev/null)& # Launch tracer
tracer_shell=$!
sleep 5

new_logcat
tap "$(get_tap_coords "$ui_dump" "NATIVE OVERHEAD BENCHMARK")"
echo "Waiting for native benchmark to complete with tracer..."
sleep 15
extract_logs TaintTracer native

new_logcat
tap "$(get_tap_coords "$ui_dump" "JAVA OVERHEAD BENCHMARK")"
echo "Waiting for java benchmark to complete with tracer..."
sleep 15
extract_logs TaintTracer java
