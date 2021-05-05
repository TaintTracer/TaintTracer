#!/usr/bin/env sh
## To be executed on the targer device using e.g. Termux
set -ex
git clone https://github.com/TaintTracer/vex.git
cd vex
make -f Makefile-gcc -j$(nproc) all

# After successful compilation, transfer libvex.a and the pub directory
# Example command to copy libvex.a on termux:
#   adb shell "su -c cat /data/user/0/com.termux/files/home/src/vex/libvex.a" > libvex.a
