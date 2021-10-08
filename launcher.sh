#!/usr/bin/env bash
set -e

. launcher_dep.sh

launcher_push
launcher "$@"
