#!/usr/bin/env bash
set -e

. ../../repackaging/deps.sh

rm -rf app-release/
apktool d ../../app/build/outputs/apk/release/app-release.apk

# Instrument benchmark iteration smali with instruction counters
# After executing javaOverheadBenchmarkIteration, the iterationInstructions variable of TestSourceSinkContextActivity should be updated
echo "Instrumenting javaOverheadBenchmarkIteration"
cp app-release/smali/org/TaintTracer/TaintTracer/TestSourceSinkContextActivity.smali app-release/smali/org/TaintTracer/TaintTracer/TestSourceSinkContextActivity.smali.orig
gawk -i inplace -f instrument_smali.awk app-release/smali/org/TaintTracer/TaintTracer/TestSourceSinkContextActivity.smali

apktool b app-release/
uas -a app-release/dist/app-release.apk --overwrite
adb uninstall org.TaintTracer.TaintTracer || true
adb install app-release/dist/app-release.apk

