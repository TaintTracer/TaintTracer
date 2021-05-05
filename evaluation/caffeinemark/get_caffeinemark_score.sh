#!/usr/bin/env bash
##
## Get CaffeineMark scores from UI dump
##

dump="$(adb shell -tt 'uiautomator dump /dev/fd/2 1>/dev/null')"

scores=""
for score in Sieve Loop Logic String Float Method Overall; do
scores="${scores}$(perl -ne '/'$score' score = (\d+)/ && print $1' <<< "$dump"),"
done
echo ${scores::-1}
adb shell am force-stop com.android.cm3
