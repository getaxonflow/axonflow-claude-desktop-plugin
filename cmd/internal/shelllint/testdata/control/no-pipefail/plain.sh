#!/usr/bin/env bash
# No pipefail: out of scope, so this pipe is not reported.
set -eu
printf '%s\n' a | grep -q a
