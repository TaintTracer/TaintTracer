#!/usr/bin/env bash
if [ ! -z $1 ]; then
  echo "Setting Post-install dexopt filter to $1..."
  adb shell 'su -c "setprop pm.dexopt.install '$1'"'
fi

echo "ART library path: $(adb shell getprop persist.sys.dalvik.vm.lib.2)"
echo "Post-install dexopt filter: $(adb shell getprop pm.dexopt.install)"
echo "Post-OTA update dexopt filter: $(adb shell getprop pm.dexopt.boot)"
echo "Generate debug info when running dexopt: $(adb shell getprop debug.generate-debug-info)"
echo "JIT enabled: $(adb shell getprop dalvik.vm.usejit)"
