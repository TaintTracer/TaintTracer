#!/usr/bin/sh
# Compute the percentage of apps that use native libraries
set -e
set -x

apk_dir=../../repackaging/fetched_apks/

app_count=0
native_count=0


for d in "$apk_dir"/*/; do
  native=0
  # Scan one or more APK files
  for apk in "$d"/*.apk; do
    if zipinfo -1 "$apk" | grep -q '^lib/.*\.so'; then
      native=1
    fi
  done
  if [ $native -eq 1 ]; then
    native_count=$((native_count + 1))
  fi
  app_count=$((app_count + 1))
done

echo $native_count / $app_count
