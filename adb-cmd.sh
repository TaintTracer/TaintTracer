#!/usr/bin/env expect
spawn adb shell
expect "/"
send [ concat [ join $argv " " ] ]
send "\r"
interact