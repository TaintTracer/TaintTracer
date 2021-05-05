#!/usr/bin/env bash
##
## Add the debugger to multiple APKs and repackage them
## Usage: ./start.sh [APK_PATH]...
##

set -eo pipefail
shopt -s nullglob
script_dir="$(dirname "$0")"

orig_apks=()
install=0
while [ $# -gt 0 ]; do
    case "$1" in
        --install)
            install=1
            shift
            ;;
        *)
            orig_apks+=("$1")
            shift
            ;;
    esac
done

if [ -z "$orig_apks" ]; then
    orig_apks=(original/*.apk)
fi
apkwd="$(realpath ./_tmp)" # Working directory for modifying APK contents
lib_name="native-lib" # Without the required lib prefix and without .so suffix
set_debuggable="0" # Whether to set the debuggable attribute to true such that ptrace() succeeds without root
dry_run="0" # Don't modify smali files for debugging

# Check system requirements
for cmd in xmlstarlet; do
  if ! [ -x "$(command -v $cmd)" ]; then
    echo "error: $cmd is not installed" >&2
    exit 1
  fi
done

# Find latest library path that was modified
libs_to_merge="$(find $(realpath "$script_dir/../app/build/")  -type d -name arm64-v8a -printf '%T@ %p\n' | sort -n | tail -1 | cut -f2- -d " ")"
echo Injecting libraries in $libs_to_merge into apk

if [ ! -d "$libs_to_merge" ]; then
    echo "No arm64-v8a directory found in project root. Please compile the TaintTracer project first." >&2
    exit 1
fi

if [ ! -f "$libs_to_merge/lib$lib_name.so" ]; then
    echo "Failed to find lib$lib_name.so in library path: $libs_to_merge" >&2
    exit 1
fi

. ./deps.sh

# Resolve a fully-qualified Java name to a smali path
# This function is compatible with multidex applications
resolve_smali_fqn() {
    local fqn="$1"
    local allow_empty="${2:-0}"
    local class_dirs=("$apkwd"/smali*)
    local sub_path="$(echo "$fqn" | sed 's/\./\//g').smali"

    local res=""
    for dir in "${class_dirs[@]}"; do
        local maybe_res="$dir/$sub_path"
        if [ -f "$maybe_res" ]; then
           res="$maybe_res"
           break
        fi
    done
    if [ -z "$res" ] && [ $allow_empty -eq 0 ]; then
        echo "Unable to find smali file for fully-qualified Java name $fqn" >&2
        exit 1
    fi
    echo "$res"
}

# Get fully-qualified names of classes that are the possible entrypoints
# of the application
# TODO: We can reduce the entry points by leaving out redundant entrypoints
#       e.g. we know that if the Application class is subclassed, that class
#       is initialized before any activities, services or receivers
entrypoints=() # Use global array as return value
list_entrypoints() {
    local manifest="$1"

    entrypoints=()
    # Subclassing the Application class is optional
    local package_id=$(xmlstarlet sel -T -t -v '/manifest/@package' "$manifest_path")
    application_fqn=$(xmlstarlet sel -T -t -v '//application/@android:name' "$manifest" || true)
    application_fqn=$(sed "s/^\./$package_id\//" <<< "$application_fqn") # Convert dot shorthand to FQN
    if [ ! -z "$application_fqn" ]; then
        if [ -z "$(resolve_smali_fqn "$application_fqn" 1)" ]; then
            echo "Application FQN specified in manifest but no corresponsing class found" >&2
	    exit 1
        fi
        entrypoints=( "${entrypoints[@]}" "$application_fqn" )
    fi

    # List all app
    entrypoints=( "${entrypoints[@]}" $(xmlstarlet sel -T -t -v '//*[local-name()="activity" or local-name()="service" or local-name="receiver" or local-name()="provider"]/@android:name' "$manifest") )
}

rm -rf "$apkwd"|| true
rm -rf modified
for apk in "${orig_apks[@]}"; do
    rm -rf "$apkwd" || true
 
    # --force-manifest option of Apktool during decoding will cause the XML to be
    # placed in the APK in raw form instead of the binary encoded form.
    # We may want to file an issue for Apktool that encodes the XML if it's not
    # yet in binary form.
    # We invoke apktool to just get the decoded XML manifest
    apktool d "$apk" -o "$apkwd" --no-src --no-res --force-manifest
    manifest_path=$(mktemp --suffix=.xml)
    cp "$apkwd/AndroidManifest.xml" "$manifest_path"
    rm -rf "$apkwd"
    package_id=$(xmlstarlet sel -T -t -v '/manifest/@package' "$manifest_path")
    echo Repackaging package with id $package_id

    apktool d "$apk" -o "$apkwd" # Extract code but keep resources intact
                                 # Avoids bugs when rebuilding resources

    # Check if the architecture is supported
    # Either no lib dir, lib/arm64-v8a exists
    arch_dirs=($(echo "${apkwd}/lib/*"))
    if [ ${#arch_dirs[@]} -gt 0 ]; then
        compat=0
        for d in "${arch_dirs[@]}"; do
            if [ $(basename "$d") == "arm64-v8a" ]; then
                compat=1
                break
            fi
        done
    else
        compat=1
    fi
    if [ $compat -eq 0 ]; then
        echo "APK does not support arm64-v8a: $apk" >&2
        break
    fi

    if [ ! $dry_run -eq 1 ]; then
        # Functionality provided by Apktool (-d flag) that should modify the manifest doesn't seem to work. An issue should be sumbitted.
        # In fact, enabling the -d flag after we manually set the debuggable attribute to true removes that attribute!
        if [ $set_debuggable -eq 1 ]; then
            xmlstarlet edit --insert "//application" --type attr -n android:debuggable --value "true" "${apkwd}/AndroidManifest.xml" > "${apkwd}/AndroidManifest.xml.dst"
            mv "${apkwd}/AndroidManifest.xml.dst" "${apkwd}/AndroidManifest.xml"
        fi
	# Ensure standalone executables disguised as libraries are extracted to the filesystem
	cat "${apkwd}/AndroidManifest.xml" \
		| xmlstarlet edit --delete "//application/@android:extractNativeLibs" \
                | xmlstarlet edit --insert "//application" --type attr -n android:extractNativeLibs --value "true" \
                > "${apkwd}/AndroidManifest.xml.dst"
        mv "${apkwd}/AndroidManifest.xml.dst" "${apkwd}/AndroidManifest.xml"


        # Modify the least amount of smali files that are part of the inheritance tree of all entry point classes
        list_entrypoints "$manifest_path"
        echo "List of entrypoints: ${entrypoints[*]}"
        "$script_dir"/classes_to_inject.py --apk-path "$apkwd" "$package_id" "${entrypoints[@]}" | while IFS= read -r smali_to_inject; do
            echo "Modifying smali: $smali_to_inject"
            # Invoke entry point when launching any activity
            cat "$smali_to_inject" | awk '
                /<clinit>/ {
                    custom_clinit=1;
                    a=1;
                    print;
                    next
                }
                a == 1 {
                    if (/.locals 0/) {
                    print "    .locals 1";
                    } else {
                    print;
                    }
                    print "";
                    print "    const-string v0, \"'"$lib_name"'\"";
                    print "";
                    print "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V";
                    a=0;
                    next;
                }
                END {
                    if (custom_clinit != 1) {
                        print ".method static constructor <clinit>()V";
                        print "    .locals 1";
                        print "";
                        print "    const-string v0, \"'"$lib_name"'\"";
                        print "";
                        print "    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V";
                        print "";
                        print "    return-void";
                        print ".end method";
                    }
                }
                1' > "${smali_to_inject}.new"
            mv "${smali_to_inject}.new" "$smali_to_inject"
        done

        # Copy library files
        apk_arch_libs="${apkwd}/lib/arm64-v8a"
        mkdir -p "$apk_arch_libs"
        cp -nrT "$libs_to_merge" "$apk_arch_libs"

	# Remove unused shared libraries that have been statically linked, test runner and test libraries
	rm "$apk_arch_libs/libdwarf++.so"
	rm "$apk_arch_libs/libelf++.so"
	rm "$apk_arch_libs/libsource-sink.so"
	rm "$apk_arch_libs/tainttracer-test.so"
    fi

    # Rebuild apk
    dest_apk="modified/$(basename "$apk")"
    if [ $set_debuggable -eq 1 ]; then
        apktool b "$apkwd" -o "$dest_apk" --use-aapt2 || continue
    else
        apktool b "$apkwd" -o "$dest_apk" || continue
    fi
    rm -rf "$apkwd"|| true
    rm "$manifest_path"

    # Sign apk
    uas -a "$dest_apk" --overwrite

    if [ $install -eq 1 ]; then
        # Install APK
        echo "Installing repackaged package: $package_id"
        adb install "$dest_apk"
    fi
done
