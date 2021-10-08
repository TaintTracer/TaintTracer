#!/usr/bin/env sh
##
# Pull test runner of the currently deployed package
##

package_name=$(cat app/build.gradle | perl -ne '/applicationId.*"(.+)"/ && print $1')
adb shell su -c ls /data/app/$package_name-*/*/*/tainttracer-test.so | xargs adb pull
