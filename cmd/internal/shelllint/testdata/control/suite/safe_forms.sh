#!/usr/bin/env bash
# In scope (pipefail), and every form here is safe: no finding.
set -euo pipefail

X="a b c"
cmd() { printf '%s\n' one two three; }

grep -q b <<<"$X"
grep -q two <<<"$(cmd)"
cmd | grep two >/dev/null
cmd | grep -c two >/dev/null
cmd | sort | uniq
case "$X" in *b*) : ;; esac
echo 'cmd | grep -q two'              # quoted text, not a pipe
echo "literal | grep -q in a string"  # double-quoted text, not a pipe
# cmd | grep -q two                   (a comment)
cat <<EOT
cmd | grep -q two
EOT
[ -n "$X" ] || grep -q x <<<"$X"
true || cmd | grep two >/dev/null
