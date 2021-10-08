#!/usr/bin/env expect
spawn adb shell
expect "/"
send "su\r"
expect "#"
send "export PATH=\$PATH:/data/data/com.termux/files/usr/bin\r"
expect "/"
send "cd /data/app/org.TaintTracer.TaintTracer-*/\r"
interact
