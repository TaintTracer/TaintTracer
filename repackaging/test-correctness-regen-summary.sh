#!/usr/bin/env bash
set -e
test_directory="$1"
csv_path="$test_directory/test_results.csv"
rm "$csv_path" || true

original_runs_dir="test-results-original"

if [ ! -d "$original_runs_dir" ]; then
    echo "Directory '$original_runs_dir' with non-traced DroidBot runs doesn't exist" >&2
    exit 1
fi

find "$original_runs_dir" "$test_directory" -mindepth 1 -maxdepth 1 -type d -print0 | sort -z | while IFS= read -r -d '' run_dir; do
    echo "Regenerating summary of run $run_dir"
    package_id=$(perl -ne '/([^\/]+)-[^-]+$/ && print $1' <<< "$run_dir")
    apk_path="./original/$package_id.apk"
    ./test-correctness-summarize-run.cpp "$apk_path" "$run_dir" "$original_runs_dir" "$csv_path"
done
