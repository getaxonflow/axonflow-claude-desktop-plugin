#!/usr/bin/env bash
# Every line marked EXPECT pipes into a grep that can exit before its input
# ends, in a pipefail script. The scanner must report each, at its own line,
# and nothing else in this file.
set -euo pipefail

X="a b c"
cmd() { printf '%s\n' one two three; }

echo "$X" | grep -q b                      # EXPECT
printf '%s' "$X" | grep -qE 'a|b'           # EXPECT
cmd | grep -m1 two                          # EXPECT
cmd | grep -l two                           # EXPECT
cmd | egrep -q two                          # EXPECT
cmd | grep --quiet two                      # EXPECT
cmd |& grep -q two                          # EXPECT
cmd | LC_ALL=C grep -q two                  # EXPECT
if ! cmd | grep -qx two; then :; fi         # EXPECT
v=$(cmd | grep --max-count=1 two)           # EXPECT
cmd |                                       # EXPECT
  grep -q two
echo "$(cmd | grep -L two)"                 # EXPECT
cmd |                                       # EXPECT
  sort | grep -q two
cmd | \grep -q two                          # EXPECT
cmd | /usr/bin/grep -q two                  # EXPECT
echo 'x' \| grep -q x || true
cmd | timeout 5 grep -q two                 # EXPECT
cmd | timeout -s KILL 5 grep -q two         # EXPECT
cmd | nice -n 10 grep -q two                # EXPECT
cmd | env -u FOO grep -q two                # EXPECT
cmd | sudo -u nobody grep -q two            # EXPECT
cmd | { grep -q two; }                      # EXPECT
cmd | (grep -q two)                         # EXPECT
cmd | xargs -0 printf '%s' | wc -l
cmd | xargs grep -ql two
