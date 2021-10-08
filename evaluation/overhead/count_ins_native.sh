#!/usr/bin/env bash
##
## Count the number of instructions run by the native benchmark on AArch64
##
set -eo pipefail

cat ../../app/src/main/cpp/source-sink-lib.cpp | sed '1,/R"asm/d;/)asm/,$d' | aarch64-linux-gnu-gcc -nostdlib -x assembler -
qemu-aarch64 -g 12345 ./a.out &

if [ $# -eq 0 ]; then
  gdb -ex 'target remote localhost:12345' -ex 'layout asm' -x count_instructions.gdb a.out
else
  gdb -ex 'target remote localhost:12345' -ex 'layout asm' a.out
fi
