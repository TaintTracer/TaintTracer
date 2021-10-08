#!/usr/bin/env bash

out="scores.csv"

if [ -f "$out" ]; then
    echo "$out already exists" >&2
    exit 1
fi

echo "System,Sieve,Loop,Logic,String,Float,Method,Overall" > "$out"

package_name="com.android.cm3"

stop_cm() {
    adb shell am force-stop $package_name
}

run() {
  label=${1:-None}

  stop_cm
  for i in {1..20}; do
      adb shell monkey -p $package_name -c android.intent.category.LAUNCHER 1
      sleep 25
      { echo -n "$label,"; ./get_caffeinemark_score.sh; } | tee -a "$out"
      stop_cm
  done
}

# run None

. ../launcher_dep.sh
launcher_push
tainttracer_remote_path="$(tainttracer_push)"
adb logcat -c
(
    launcher $package_name "$tainttracer_remote_path {}" &
    launcher_pid=$!
    trap "kill $launcher_pid; adb shell su -c killall launcher" TERM INT
    wait $launcher_pid
)&

sleep 1 # Wait for launcher to attach to zygote

run Tracer
