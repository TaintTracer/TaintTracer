LOGFILE="${1:-tainttracer-log.txt}"
perl -ne '/^(.*)? .*Tainted memory size.*: ([0-9]+) B/ && print $1, ",", $2, "\n"' < "$LOGFILE"
