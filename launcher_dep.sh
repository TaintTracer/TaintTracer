launcher_dep_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

launcher_path_remote="/data/local/tmp/launcher"
tainttracer_path_remote="/data/local/tmp/libtainttracer-executable.so"
launcher_push() {
    local host_path="$launcher_dep_dir/app/build/intermediates/cmake/release/obj/arm64-v8a/launcher"
    if [ ! -f "$host_path" ]; then
        echo "Launcher has not been built yet. Please build the launcher executable as a Release target." >&2
        exit 1
    fi

    adb shell su -c "killall '$(basename "$host_path")'" || true
    adb push "$host_path" "$launcher_path_remote"
    adb shell su -c "chmod +x '$launcher_path_remote'"
    echo "$launcher_path_remote"
}

tainttracer_push() {
    # Find latest build artifact of tracer
    local host_path="$(find "$launcher_dep_dir/app/build/" -type f -name "$(basename "$tainttracer_path_remote")" -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d " ")"
    adb shell su -c "killall '$(basename "$tainttracer_path_remote")'" > /dev/null || true
    adb push "$host_path" "$tainttracer_path_remote" > /dev/null
    adb shell su -c "chmod +x '$tainttracer_path_remote'"
    echo "$tainttracer_path_remote"
}

launcher() {
    # Allocate tty to work arond failed binder transactions due to SELinux policy
    # We force-allocate a tty and redirect a dummy stream as input to allow it to be run in the background
    adb shell -tt "su -c '$launcher_path_remote $1 "'"'"$2"'"'"'" < /dev/null # TODO: Propagate status code?
}

tainttracer() {
    adb shell -tt su -c "'$tainttracer_path_remote' $*" < /dev/null
}

