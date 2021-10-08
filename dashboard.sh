#!/usr/bin/env bash
##
# Usage: dashboard.sh [PACKAGE_ID|LOGFILE]
##

set -x
package_name=$(cat app/build.gradle | perl -ne '/applicationId.*"(.+)"/ && print $1')
logfile="/data/local/tmp/tainttracer_log.txt"

if [[ -f "$1" ]]; then
    cmd="echo Running in log preview mode"
    local_logfile="$1"
else
    cmd="./run.sh $1"
    local_logfile="tmp.txt"
fi

tmuxinator start -p <(cat - <<EOF
name: debug-layout
root: .

on_project_start: "> tmp.txt && > tmplogcat.txt"

# Run on project start, the first time
# on_project_first_start: command

# Run on project start, after the first time
# on_project_restart: command

# Run on project exit ( detaching from tmux session )
# on_project_exit: command

# Run on project stop
# on_project_stop: command

# Runs in each window and pane before window/pane specific commands. Useful for setting up interpreter versions.
# pre_window: rbenv shell 2.0.0-p247

# Pass command line options to tmux. Useful for specifying a different tmux.conf.
# tmux_options: -f ~/.tmux.mac.conf

startup_window: filtered

# Specifies (by index) which pane of the specified window will be selected on project startup. If not set, the first pane is used.
# startup_pane: 1

windows:
  - logcat:
      panes:
        - "$cmd"
  - full_log:
      panes:
        - tail -n +1 -f "$local_logfile"
  - filtered:
      layout: even-vertical
      # Synchronize all panes of this window, can be enabled before or after the pane commands run.
      # 'before' represents legacy functionality and will be deprecated in a future release, in favour of 'after'
      # synchronize: after
      panes:
        - tail -n +1 -f tmplogcat.txt | stdbuf -oL grep -a -v "TaintTracer:" | grep -a -v " I chatty"
        - tail -n +1 -f "$local_logfile" | grep -a -E "__set_errno_internal|System call error|ThrowByNameWithLastError|exit\(\)" -B 1
        - >-
          tail -n +1 -f "$local_logfile" | awk '/NTMainActivity: / { print } /Stopped stack/ { getline;  print "\033[36m" \$0 "\033[0m"; getline; print }'
  - memory:
      layout: even-horizontal
      panes:
        - tail -n +1 -f "$local_logfile" | grep -a -E "Marking memory|sink event"
        - tail -n +1 -f "$local_logfile" | grep -a "Instruction @ pc tried to access" -A 8
  - editor:
      layout: main-horizontal
      panes:
        - bash
EOF
)

