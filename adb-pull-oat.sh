#!/usr/bin/env bash
##
# Build and install a Release build of the app, AOT-compile everything and pull the resulting oat
# directory from the device to the host
##
set -ex
package_name=$(cat app/build.gradle | perl -ne '/applicationId.*"(.+)"/ && print $1')

### Set AOT compilation options ###
# Generate symbols and extended debug info: adb shell setprop debug.generate-debug-info true
# This will generate more sections (.gnu_debugdata, .debug_frame) than manually running oatdump symbolize.
old_debug_info=$(adb shell getprop debug.generate-debug-info)
old_install=$(adb shell getprop pm.dexopt.install)
adb shell setprop debug.generate-debug-info true
adb shell 'su -c "setprop pm.dexopt.install everything"'

./gradlew installRelease
code_dir=$(adb shell pm path $package_name | sed 's/package://' | sed 's/\/base.apk//')
rm -rf oat/
adb shell su -c tar -C $code_dir -cf - oat | tar xvf -

# Revert adb properties
adb shell setprop debug.generate-debug-info $old_debug_info
adb shell 'su -c "setprop pm.dexopt.install '"$old_install"'"'
