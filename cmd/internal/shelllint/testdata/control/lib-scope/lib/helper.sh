#!/usr/bin/env bash
# A lib/ helper with no set line of its own is in scope: it runs with its
# caller's options.
has_ready() {
  local x="ready"
  printf '%s\n' "$x" \
    | grep -q ready
}
