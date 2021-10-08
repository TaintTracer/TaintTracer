#!/usr/bin/env bash
dir="$1" # Directory containing APK (or Split APKs) and optionally OBB files
package_id="$(basename "$dir")" # It is assumed that the directory name is the package id

apk_files=("$(find "$1" -type f -name '*.apk' -maxdepth 1)")
obb_files=("$(find "$1" -type f -name '*.obb' -maxdepth 1)")

if [ ${#apk_files[@]} -eq 0 ]; then
    echo "No APK files found in $dir" >&2
    exit 1
elif [ ${#apk_files[@]} -eq 1 ]; then
    adb install "$apk_files"
elif
    adb install-multi-package "${apk_files[@]}"
fi

for obb in "${obb_files[@]}"; do
    adb push "$obb" "/sdcard/Android/obb/$package_id/"
done

