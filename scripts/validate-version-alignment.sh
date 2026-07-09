#!/usr/bin/env bash
# validate-version-alignment.sh — CI gate: the three version surfaces must agree.
#
# X-Axonflow-Client (#2860) puts proxyVersion ON THE WIRE, so a drift between
# the Go constant, manifest.json (what build.sh stamps on the .mcpb artifact),
# and the CHANGELOG's latest release entry silently misreports the fleet's
# version distribution — exactly the failure mode the claude-code plugin hit
# (three releases collapsed into one telemetry bucket; see its PR #105, whose
# gate this mirrors).
#
# Checks:
#   1. cmd/axonflow-mcp-proxy/main.go  const proxyVersion = "X.Y.Z"
#   2. manifest.json                   "version": "X.Y.Z"
#   3. CHANGELOG.md                    first "## [X.Y.Z]" heading
#      ("## [Unreleased]" is skipped: unreleased work rides the last release's
#      version until the release commit bumps all three surfaces together.)
#
# Exit 0 when all three match; exit 1 with a diff-style report otherwise.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "❌ $*" >&2; exit 1; }

go_version="$(sed -n 's/^const proxyVersion = "\(.*\)"$/\1/p' cmd/axonflow-mcp-proxy/main.go)"
[ -n "$go_version" ] || fail "could not extract proxyVersion from cmd/axonflow-mcp-proxy/main.go"

# Same extraction build.sh uses (build.sh:17) — the value stamped on the .mcpb.
manifest_version="$(grep -m1 '"version"' manifest.json | sed 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')"
[ -n "$manifest_version" ] || fail "could not extract version from manifest.json"

changelog_version="$(grep -m1 -E '^## \[[0-9]' CHANGELOG.md | sed 's/^## \[\([^]]*\)\].*/\1/')"
[ -n "$changelog_version" ] || fail "could not extract latest release heading from CHANGELOG.md"

echo "proxyVersion (main.go):      $go_version"
echo "manifest.json version:       $manifest_version"
echo "CHANGELOG latest release:    $changelog_version"

if [ "$go_version" != "$manifest_version" ] || [ "$go_version" != "$changelog_version" ]; then
  fail "version surfaces disagree — bump ALL of main.go proxyVersion, manifest.json, and the CHANGELOG release heading together"
fi

echo "✅ version surfaces aligned at $go_version"
