# Works with source'd scripts
# https://stackoverflow.com/a/246128
script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

resolve_build_tools() {
    local sdk="${ANDROID_SDK_ROOT:-$HOME/Android/Sdk}"
    local set=0
    for d in "$sdk"/build-tools/*; do
        if [ -f "$d/aapt" ]; then
            PATH="$PATH:$d"
            set=1
            break
        fi
    done
    if [ "$set" -eq 0 ]; then
        echo "Failed to resolve aapt binary: aapt not found in $sdk" >&2
    fi
}

# Build Apktool if needed
resolve_apktool() {
    local cmd=javac
    if ! [ -x "$(command -v $cmd)" ]; then
        echo "error: $cmd is not installed" >&2
        exit 1
    fi

    local src_dir="${script_dir}/dep/Apktool"
    local apktool_bin="${src_dir}/brut.apktool/apktool-cli/build/libs/apktool-cli-all.jar"
    if [ ! -f "$apktool_bin" ]; then
       cd "$src_dir"
       echo "Building Apktool..." >&2
       ./gradlew >&2
       cd - >&2
    fi
    if [ ! -f "$apktool_bin" ]; then
        echo "Failed to build Apktool: Gradle did not produce binary at $apktool_bin"
    fi
    # wget https://github.com/iBotPeaches/Apktool/releases/download/v2.4.1/apktool_2.4.1.jar
    echo "$apktool_bin"
}

# CLI wrapper for Apktool
apktool() {
    java -jar "$(resolve_apktool)" "$@"
}

resolve_uas() {
    local uas_bin="${script_dir}/dep/uber-app-signer.jar"
    if [ ! -f "$uas_bin" ]; then
        echo "Downloading uber-app-signer..." >&2
        curl -L "https://github.com/patrickfav/uber-apk-signer/releases/download/v1.1.0/uber-apk-signer-1.1.0.jar" -o "$uas_bin"
    fi
    echo "$uas_bin"
}

uas() {
    java -jar "$(resolve_uas)" "$@"
}

resolve_droidbot() {
    local cmd=python3
    if ! [ -x "$(command -v $cmd)" ]; then
        echo "error: $cmd is not installed" >&2
        exit 1
    fi

    if ! [ -x "$(command -v droidbot)" ]; then
        local src_dir="$script_dir/dep/droidbot"
        git clone https://github.com/honeynet/droidbot.git "$src_dir"
        cd "$src_dir"
        git checkout 9e7bc6e517df85f2a2ba00e7da7831d8d0cf7247
        git apply "$script_dir/droidbot_forcestop_patch.diff"
        python3 -m pip install --user -e .
        cd -
    fi

    echo "$(command -v droidbot)"
}

google_play_scraper() {
    for cmd in npm node; do
        if ! [ -x "$(command -v $cmd)" ]; then
            echo "error: $cmd is not installed" >&2
            exit 1
        fi
    done
    (
        cd "$script_dir/dep/"
	if ! npm install google-play-scraper &> /dev/null; then
            echo "Failed to install google-play-scraper node module with npm" >&2
        fi
    )
    sh -c "cd '$script_dir/dep/' && node $@"
}

min_img_similarity() {
    if ! python -c "import imagehash" &>/dev/null; then
        python3 -m pip install --user ImageHash
    fi
    python3 "$script_dir/min-img-similarity.py" "$@"
}
