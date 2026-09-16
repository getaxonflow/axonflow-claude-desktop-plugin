#!/usr/bin/env bash
# Sourced by caller.sh, so in scope without a set line of its own.
stack_state() { echo ok; }
is_ready() {
  stack_state | grep -q ok
}
