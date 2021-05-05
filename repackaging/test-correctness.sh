#!/usr/bin/env bash
set -eo pipefail
set -x

continue_from_package="$1"
skip_nontraced="1"

. ./deps.sh
. ../launcher_dep.sh
resolve_droidbot # Import droidbot command
resolve_build_tools # Import aapt

# TODO: Graceful SIGINT shutdown
killall droidbot || true
killall adb || true

out_dir="test-results-$(date +"%Y-%m-%d-%H-%M-%S")"
mkdir -p "$out_dir"
script_log="$out_dir/script_log.txt"

exec > >(tee "$script_log") 2>&1 # Log terminal output to file

launcher_push
tainttracer_remote_path="$(tainttracer_push)"

retry_backoff () {
    local delay=1
    while ! "$@"; do
        echo "Command '$*' failed to execute. Sleeping for $delay seconds..."
        sleep $delay
        delay=$((delay * 2))
    done
}

get_new_logs() {
    # Clearing adb logcat buffer doesn't clear all log entries.
    # We ignore logcat messages until no new messages get printed and only provide messages thereafter
    retry_backoff adb logcat -c
    adb logcat 2>&1 | { # Forward error messages as well
        adb wait-for-device
        while IFS= read -t 1 -r line; do
            : # Wait until old log files have been read
            echo "[filtered] $line" >&2
        done

        echo '\0' >&3 # Send ready signal to other thread

        cat - # Forward new messages from logcat to stdout
    }
}

grant_runtime_perms() {
    local apk=$1
    local runtime_perms=($(aapt d permissions "$apk" | perl -ne '/name='"'"'(.+)'"'"'/ && print $1 . "\n"'))
    for perm in "${runtime_perms[@]}"; do
        echo "Granting runtime permission $perm"
	    adb shell pm grant $package_id $perm || true # Ignore unchangeable permission type errors
    done
}

debug_app() {
    local apk="$1"
    local run_label="$2"
    local trace="$3"
    local track_taints="$4"

    local package_id
    package_id="$(aapt dump badging $apk | perl -ne '/package: name='"'"'(.*?)'"'"'/ && print $1')"
    local remote_tainttracer_log="/data/local/tmp/tainttracer_log.txt"
    local run_dir="$out_dir/$package_id-$run_label"
    local original_run_dir="${run_dir//-[^-]+$/-original}"
    mkdir -p "$run_dir"

    adb shell pm clear $package_id # Clear app data (including disable_taint_path) and allowed permissions
    adb shell su -c rm -f $remote_tainttracer_log || true # Clean up old log when script was not terminated gracefully
    grant_runtime_perms "$apk"
    if [ $trace -eq 1 ]; then
        if [ $track_taints -eq 0 ]; then
            # When this file exists, the debugger will not track tainted data
            disable_taint_path="/data/data/$package_id/disable_taint_analysis"
            adb shell "su -c 'touch $disable_taint_path'"
        else
            [ $track_taints -eq 1 ]
        fi
    fi

    echo "Starting run of package $package_id ($run_label)"

    # We create a pipe to signal when we have read through old log entries and are ready to start
    # the application. We use file descriptor number 3 for this purpose
    ready_fifo=$(mktemp -u)
    mkfifo "$ready_fifo"
    exec 3<> "$ready_fifo"
    rm "$ready_fifo"

    logcat_path="$run_dir/logcat_filtered.txt"
    get_new_logs > "$logcat_path" &
    log_runner_pid=$!

    echo "Waiting for old log entries to be cleared..." >&2
    read -n 1 <&3

    if [ $trace -eq 1 ]; then
        echo "Starting launcher" >&2
        # Hook zygote and wait until desired app is launched by droidbot
        launcher $package_id "$tainttracer_remote_path {}" 2>&1 | tee "$run_dir/launcher_log.txt" &
        launcher_pid=$!
    fi

    sleep 1 # HACK: Wait until launcher has hooked Zygote using constant sleep interval
    if ! kill -0 $log_runner_pid; then
        echo "Log runner background process is dead!"
        exit 1
    fi

    # Start the app and generate touch events
    (
        common_opts=(-a "$apk" -keep_app -count 100 -interval 5 -timeout -1 -o "$run_dir")
        if [[ "$run_dir" == "$original_run_dir" ]]; then
            droidbot "${common_opts[@]}" &
            droidbot_pid=$!
        else
            # Replay original run for subsequent runs to avoid non-determinism
            droidbot "${common_opts[@]}" -policy replay -replay_output "$original_run_dir" &
            droidbot_pid=$!
        fi

        trap "kill $droidbot_pid; exit" TERM
        if [ $trace -eq 1 ]; then
            trap "adb shell su -c killall launcher || true; adb shell su -c killall $(basename $tainttracer_remote_path) || true" EXIT
        fi
        wait $droidbot_pid && err=$? || err=$? # Wait for DroidBot or SIGTERM, whichever comes first
        adb shell log -t test_correctness completed run
        echo "DroidBot runner finished"
        exit $err
    )&
    runner_pid=$!

    set +x
    while ps -p $runner_pid > /dev/null && IFS= read -r line; do
        echo "$line" >> "$run_dir/logcat_processed.txt"

        if [[ $line == *"test_correctness: completed run"* ]]; then
            break
        fi

        if [[ "$line" == *"read: unexpected EOF!"* ]]; then
            echo "logcat failed to read log entry: Unexpected EOF. Retrying run..." >&2
            rm -rf "$run_dir"
            kill $runner_pid || true
            kill $log_runner_pid || true # Most likely already terminated after printing error message
            debug_app "$@"
            return $?
        fi

        should_kill=0
        if [[ "$line" == *"ActivityManager: Process $package_id "*" has died"* ]]; then
            echo "Activity process has crashed! Killing DroidBot..." >&2
            should_kill=1

        fi
        if [[ "$line" == *"F DEBUG   : pid:"* ]]; then
            echo "A native process has crashed! Killing DroidBot..." >&2
            should_kill=1
        fi

        if [ $should_kill -eq 1 ]; then
            kill $runner_pid || true
            break
        fi
    done < <(tail -f -n +0 "$logcat_path")
    set -x

    kill $log_runner_pid
    wait $log_runner_pid || true

    echo Waiting for DroidBot subshell runner to stop
    wait $runner_pid && runner_status=$? || runner_status=$?
    if [ ! $runner_status -eq 0 ] && [ ! $runner_status -eq 143 ]; then
        echo DroidBot stopped with error $runner_status, restarting run... >&2
        rm -rf "$run_dir"
        debug_app "$@"
        return $?
    fi

    # Wait for tracer and droidbot to stop to avoid tracer panic and false positive crashes in log
    adb shell am force-stop $package_id # Stop all processes in sandbox

    tainttracer_log="$run_dir/tainttracer_log.txt"
    adb shell su -c "cat '$remote_tainttracer_log' 2>&-" > "$tainttracer_log" || true # Fetch remote log
    adb shell su -c rm -f $remote_tainttracer_log # Clean up log on device

    if [ $trace -eq 1 ]; then
        if [ ! -s "$tainttracer_log" ]; then
            echo "TaintTracer log pulled from device is empty" >&2
            exit 1
        fi
    else
        if [ -s "$tainttracer_log" ]; then
            echo "Tracing is disabled but TaintTracer logfile found at $tainttracer_log" >&2
            exit 1
        fi
        rm "$tainttracer_log"
    fi

    # echo "Summarizing log file..."
    # ./test-correctness-summarize-run.cpp "$apk" "$run_dir" "$out_dir/test_results.csv"

    echo "Run completed"

    # Cleanup
    exec 3>&- # Close fd
}

# AOT compile apps on install to avoid JIT or bytecode interpretation
adb shell 'su -c "setprop pm.dexopt.install everything"'

# Hide status bar for screenshot
adb shell settings put global policy_control immersive.full=*
# Enable rotation lock
adb shell content insert --uri content://settings/system --bind name:s:accelerometer_rotation --bind value:i:0
# Use portrait orientation
adb shell content insert --uri content://settings/system --bind name:s:user_rotation --bind value:i:0

for apk in original/*.apk; do
    if [ ! -f "$apk" ]; then
        echo "No APKs found in ./original/" >&2
        exit 1
    fi
    package_id="$(aapt dump badging "$apk" | perl -ne '/package: name='"'"'(.*?)'"'"'/ && print $1')"

    if [ -n "$continue_from_package" ]; then
      if [[ $continue_from_package == "$package_id" ]]; then
          continue_from_package=""
      else
          continue
      fi
    fi

    adb uninstall $package_id || true
    adb install "$apk"

    if [ -z "$skip_nontraced" ] || [ "$skip_nontraced" -eq 0 ]; then
        debug_app "$apk" "original" 0 0
        debug_app "$apk" "original2" 0 0 # Run original multiple times to assert usefulness of UI similarity
    fi
    # debug_app "$apk" "tracing without taint tracking" 1 0
    debug_app "$apk" "tracing with taint tracking" 1 1

    adb uninstall $package_id
done

# Restore status bar
adb shell settings put global policy_control null*
