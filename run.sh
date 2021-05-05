#!/usr/bin/env bash
##
## Usage ./run.sh [PACKAGE_NAME]
## Clear logs, kill, and show logs of a new run
## Note: This script does not build and deploy the app from source
##

trap 'kill $(jobs -p)' INT

set -e
package_name=${1:-$(cat app/build.gradle | perl -ne '/applicationId.*"(.+)"/ && print $1')}
# Main activity: xmlstarlet sel -T -t -v '//action[@android:name="android.intent.action.MAIN"]/../../@android:name' AndroidManifest.xml

remote_logfile="/data/local/tmp/tainttracer_log.txt"
adb shell pm clear $package_name
adb shell pm grant $package_name android.permission.READ_CONTACTS || echo "Failed to grant read contacts permission. Ignoring..." >&2
adb shell su -c rm -f $remote_logfile || true

. ./launcher_dep.sh
launcher_push
tainttracer_remote_path="$(tainttracer_push)"
adb logcat -c
(
    adb shell monkey -p $package_name -c android.intent.category.LAUNCHER 1
)&

(
    launcher $package_name "$tainttracer_remote_path {}" &
    launcher_pid=$!
    trap "kill $launcher_pid; adb shell su -c killall launcher" TERM INT
    wait $launcher_pid
)&

sleep 1 # Wait for launcher to attach to zygote

adb shell monkey -p $package_name -c android.intent.category.LAUNCHER 1 &

lcfile=tmplogcat.txt
logfile=tmp.txt

>"$lcfile"
>"$logfile"
(adb logcat > "$lcfile")&
(
    while ! adb shell su -c tail -n +0 -f "$remote_logfile" > "$logfile"; do :; done
)&
tail -f "$lcfile" # Stream logcat to stdout

