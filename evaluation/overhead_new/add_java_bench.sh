#!/usr/bin/env bash
set -e

echo "This script has been deprecated since dex2oat optimizes away unused smali variables" >&2
exit 1

. ../../repackaging/deps.sh

rm -rf app-release/
apktool d ../../app/build/outputs/apk/release/app-release.apk

echo "Instrumenting smali"
target="app-release/smali/org/TaintTracer/TaintTracer/TestSourceSinkContextActivity.smali"
cp "$target" "$target.orig"
sed -i '/^\.method newJavaOverheadBenchmark/,/^\.end/d;' "$target"
cat newJavaOverheadBenchmark.smali >> "$target"

apktool b app-release/
uas -a app-release/dist/app-release.apk --overwrite
adb uninstall org.TaintTracer.TaintTracer || true
adb install app-release/dist/app-release.apk

package_name=$(cat ../../app/build.gradle | perl -ne '/applicationId.*"(.+)"/ && print $1') 
adb shell monkey -p $package_name -c android.intent.category.LAUNCHER 1
