# TaintTracer
This project can be built with Android Studio or directly with Gradle. Building the default project will build our dynamic taint-analysis system and our benchmark app.

All submodules should be cloned before building TaintTracer.
This can be done by executing the following command: `git submodule update --init`

### Directory structure
- `app/src/main/cpp`: TaintTracer source code
- `app/src/main/java`: Demo app source code
- `docs/`: Documentation about configuring ART
- `evaluation/`: Scripts to generate evaluation plots
- `lldb-scripts/`: LLDB scripts used for debugging memory accesses (`disassembly_mode.py` taken from LLVM)
- `lldb-target/`: Precompiled LLDB for Android
- `repackaging/repackage.sh`: Script to repackage third-party APKs with our system. TaintTracer needs to be built before repackaging apps.
- `repackaging/test-correctness.sh`: Automated testing of apps using DroidBot. APK files must be placed in `repackaging/original`.
- `repackaging/test-correctness-regen-summary.sh`: Summarize log files of test runs.
- `stats/`: Scripts to summarize and plot log files
- `dashboard.sh`: Runs a repackaged app with the provided package ID and displays system output in different tmux panes and windows. This requires `log_to_file` to be enabled.
