#!/usr/bin/env bash
##
## Request and pull taint events plot after sink event
##
set -ex
tracer_pid=$(adb shell ps -A -o PID,CMD | grep libtainttracer- | cut -d' ' -f1)
adb shell su -c kill -SIGUSR1 $tracer_pid
adb shell su -c cat /data/data/org.TaintTracer.TaintTracer/plot | tee final.dot | dot -Tpdf | csplit --quiet --elide-empty-files --prefix tmpplot -b %02d.pdf - "/%%EOF/+1" "{*}"

pdfunite tmpplot* final.pdf
rm tmpplot*
xdg-open final.pdf
