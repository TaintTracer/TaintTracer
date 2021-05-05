#!/usr/bin/env bash
## Download an APK from the Google Play store on the device
## and pull all installed resources from it (e.g. APK, OBB)

set -e

for cmd in adb xmlstarlet perl; do
  if ! [ -x "$(command -v $cmd)" ]; then
    echo "error: $cmd is not installed" >&2
    exit 1
  fi
done

. ./deps.sh

get_ui_dump() {
    adb shell -tt 'uiautomator dump /dev/fd/2 1>/dev/null'
}

get_tap_coords() {
    # Return center coordinates of element matching a given text
    local dump="$1"
    local text="$2"

    local bounds_raw="$(xmlstarlet sel -T -t -v '//node[@text="'"$text"'"]/@bounds' <<< "$dump")"
    if [ -z "$bounds_raw" ]; then
        echo "No UI element found with text '$text'" >&2
        exit 1
    fi
    perl -ne '/\[(\d+),(\d+)\]\[(\d+),(\d+)\]/ && print int(int($1+$3)/2) . " " . int(int($2+$4)/2)' <<< "$bounds_raw"
}

get_top_apps() {
    local -n result=$1
    local country=$2
    local num=$3
    local IFS=$'\n'
    result=($(google_play_scraper - <<EOF
var gplay = require('google-play-scraper');
gplay.list({
    collection: gplay.collection.TOP_FREE,
    country: '$country',
    num: $num
}).then(arr => arr.forEach(app => console.log(app.appId)), err => { console.err(err); process.exit(1); })
EOF
))
}

fetch_apk() {
    local app_id=$1
    local target_dir="$2"

    if [ -z $app_id ]; then
        echo "No app id provided" >&2
        return 1
    fi


    # Remove app if it was not installed first
    local installed=0
    if ! [ -z "$(adb shell pm list packages $app_id)" ]; then
        installed=1
    fi
    if [ $installed -eq 0 ]; then
        adb shell am start -a android.intent.action.VIEW -d "market://details?id=$app_id"
        local ui_dump="$(get_ui_dump)"

        if grep -q "You're offline" &>/dev/null <<< "$ui_dump"; then
            echo "Device has no internet connection" >&2
            return 1
        elif grep -q "Item not found" &>/dev/null <<< "$ui_dump"; then
            echo "$app_id not found on the Play Store" >&2
            return 1
        elif grep -q "This item isn't available in your country." &> /dev/null <<< "$ui_dump"; then
            echo "$app_id is not available in your country." >&2
            return 2
        elif grep -q "Your device isn't compatible with this version." &>/dev/null <<< "$ui_dump"; then
            echo "$app_id isn't compatible with the connected device" >&2
            return 2
        fi

	while ! grep -q '"Install"' <<< "$ui_dump"; do
            echo "Waiting for 'Install' button to appear..."
            ui_dump="$(get_ui_dump)"
        done

        local install_coords
        install_coords=$(get_tap_coords "$ui_dump" Install)
	if [ ! $? -eq 0 ]; then
            exit 1
        fi
        echo Pushing install button with coordinates: $install_coords
        adb shell input tap $install_coords

        while :; do
            ui_dump="$(get_ui_dump)"
            if grep -q '"Uninstall"' <<< "$ui_dump"; then
                break
            fi

            if grep -q '"Waiting for download…"' <<< "$ui_dump"; then
                echo "Waiting for download..."
            elif grep -q -E '"[0-9]{1,2}% of' <<< "$ui_dump"; then
                perl -ne '/"([0-9]{1,2}% of .*?)"/ && print "$1\n"' <<< "$ui_dump"
            elif grep -q '"Cancel"' <<< "$ui_dump"; then
                # In some cases, the Cancel and Open button can appear at the same time
		# during the installation process. We wait until the Uninstall button appears.
                echo "Installing..."
            else
            echo "$ui_dump" > ui_dump.xml
                echo "Unknown status while downloading. Saved to ui_dump.xml" >&2
                return 1
            fi
        done
        echo App installed to device
    fi

    local archives=($(adb shell pm path "$app_id" | perl -ne '/package:(.*)/ && print "$1\n"')) # Pull APK files
    archives+=($(adb shell find /sdcard/Android/obb/$app_id/ -type f 2>&- || true)) # Pull OBB files
    echo "Found ${#archives[@]} archive files for app $app_id"

    rm -rf "$target_dir" || true
    mkdir -p "$target_dir"
    for package in "${archives[@]}"; do
        adb pull "$package" "$target_dir"
    done

    if [ $installed -eq 0 ]; then
        echo "Uninstalling package since it was not present prior to running this script"
        adb uninstall $app_id
    fi

}

apk_list=
get_top_apps apk_list us 200
echo "Fetching ${#apk_list[@]} apps"

for app in "${apk_list[@]}"; do
    target_dir="./fetched_apks/$app/"
    if [ -d "$target_dir" ]; then
        echo "$app has already been downloaded. Skipping..." >&2
        continue
    fi
    fetch_apk $app "$target_dir" && err_code=$? || err_code=$?
    if [ $err_code -eq 0 ]; then
        echo "Successfully downloaded $app"
    elif [ $err_code -eq 2 ]; then
        echo "Skipping download for $app"
    else
        echo "Failed to download app. Terminating..." >&2
        exit $err_code
    fi
done
