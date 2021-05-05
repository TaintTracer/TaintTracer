#!/usr/bin/env sh
# Move non-split and non-OBB apps to original folder before our repackaging script supports multi-apk files

set -e

SOURCE_DIR=${1:-./fetched_apks}
DEST_DIR=${2:-./original}

mv "$DEST_DIR" "$DEST_DIR-$(date +%s)" || true
mkdir -p "$DEST_DIR"

for d in "$SOURCE_DIR"/*/; do
    app_id=$(basename "$d")
    num_files=$(ls "$d" | wc -l)
    if [ $num_files -eq 1 ]; then
        if [ ! -f "$d/base.apk" ]; then
            echo "No base.apk found in $d" >&2
            exit 1
        fi
        cp "$d/base.apk" "$DEST_DIR/$app_id.apk"
    fi
done
