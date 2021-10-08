#!/usr/bin/env sh
###
## Listen for data written on a named pipe on the app's local storage and plot it
## Now outdated since we write to a file that we can pull later for performance reasons
##

for x in adb dot csplit pdfunite; do
    if [ -z "$(command -v $x)" ]; then
        echo Unable to start plot server. Command $x is not installed. >&2
        exit 1
    fi
done

set -xeo pipefail
package_name=$(cat app/build.gradle | perl -ne '/applicationId.*"(.+)"/ && print $1')
fifo="plot"

adb shell run-as "$package_name" <<EOF | tee final.dot | dot -Tpdf | csplit --quiet --elide-empty-files --prefix tmpplot -b %02d.pdf - "/%%EOF/+1" "{*}"
rm plot &>/dev/null || true
mkfifo $fifo
cat $fifo
rm $fifo
EOF

pdfunite tmpplot* final.pdf
rm tmpplot*
xdg-open final.pdf
