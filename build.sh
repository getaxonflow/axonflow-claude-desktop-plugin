#!/usr/bin/env bash
# Build the AxonFlow Governance .mcpb Desktop Extension.
#
# Produces multi-arch proxy binaries and packs them, the manifest, and assets
# into a single installable .mcpb (a zip — Claude Desktop's Settings →
# Extensions installs it). Per the multi-arch requirement, the macOS binary is a
# universal (arm64 + amd64) build so it runs on both Apple Silicon and Intel
# Macs; Linux ships both amd64 and arm64; Windows ships amd64.
#
# Usage:  ./build.sh            # build everything + pack .mcpb
#         ./build.sh binaries   # binaries only (no pack)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

VERSION="$(grep -m1 '"version"' manifest.json | sed -E 's/.*"version": *"([^"]+)".*/\1/')"
OUT="build/mcpb"
SRC="./cmd/axonflow-mcp-proxy"
LDFLAGS="-s -w"

echo "==> AxonFlow Governance .mcpb build v${VERSION}"
rm -rf build
mkdir -p "$OUT/server" "$OUT/assets"

build() { # GOOS GOARCH OUTFILE
  echo "    - $1/$2 -> $3"
  GOOS="$1" GOARCH="$2" CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o "$3" "$SRC"
}

# Linux (amd64 + arm64) and Windows (amd64).
build linux  amd64 "$OUT/server/axonflow-mcp-proxy-linux-amd64"
build linux  arm64 "$OUT/server/axonflow-mcp-proxy-linux-arm64"
build windows amd64 "$OUT/server/axonflow-mcp-proxy-windows-amd64.exe"

# macOS: build both arches, then lipo into a universal binary so a single
# darwin entry_point covers Apple Silicon + Intel. Falls back to arm64-only
# (the dominant Mac fleet arch) when lipo is unavailable (non-macOS builder).
build darwin arm64 "$OUT/server/axonflow-mcp-proxy-darwin-arm64"
build darwin amd64 "$OUT/server/axonflow-mcp-proxy-darwin-amd64"
if command -v lipo >/dev/null 2>&1; then
  echo "    - lipo darwin universal"
  lipo -create \
    "$OUT/server/axonflow-mcp-proxy-darwin-arm64" \
    "$OUT/server/axonflow-mcp-proxy-darwin-amd64" \
    -output "$OUT/server/axonflow-mcp-proxy-darwin"
  rm -f "$OUT/server/axonflow-mcp-proxy-darwin-arm64" "$OUT/server/axonflow-mcp-proxy-darwin-amd64"
else
  echo "    ! lipo not found — shipping darwin arm64 as the macOS binary"
  mv "$OUT/server/axonflow-mcp-proxy-darwin-arm64" "$OUT/server/axonflow-mcp-proxy-darwin"
  rm -f "$OUT/server/axonflow-mcp-proxy-darwin-amd64"
fi
chmod +x "$OUT"/server/axonflow-mcp-proxy-* 2>/dev/null || true

if [ "${1:-}" = "binaries" ]; then
  echo "==> binaries built in $OUT/server"
  exit 0
fi

# Stage manifest + assets + example config + docs.
cp manifest.json "$OUT/manifest.json"
cp config.example.json "$OUT/config.example.json"
cp README.md "$OUT/README.md" 2>/dev/null || true
[ -f assets/logo.png ] && cp assets/logo.png "$OUT/assets/logo.png"

# Pack. Prefer the official `mcpb` CLI (validates the manifest) when present;
# otherwise fall back to a plain zip (Claude Desktop accepts either).
PKG="axonflow-governance-${VERSION}.mcpb"
rm -f "build/$PKG"
if command -v mcpb >/dev/null 2>&1; then
  echo "==> packing with mcpb CLI"
  ( cd "$OUT" && mcpb pack . "../$PKG" )
else
  echo "==> packing with zip (install 'npm i -g @anthropic-ai/mcpb' for manifest validation)"
  ( cd "$OUT" && zip -r -q "../$PKG" . )
fi

echo "==> built build/$PKG"
ls -lh "build/$PKG"
