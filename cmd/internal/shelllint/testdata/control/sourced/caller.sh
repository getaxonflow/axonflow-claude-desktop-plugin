#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$0")/helpers.sh"
grep -q ok <<<"$(stack_state)"
