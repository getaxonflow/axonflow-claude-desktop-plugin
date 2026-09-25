#!/usr/bin/env bash
# `set -o errexit -o pipefail` sets pipefail too: in scope, one finding.
set -o errexit -o pipefail
printf '%s\n' a | grep -q a
