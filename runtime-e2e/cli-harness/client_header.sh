#!/usr/bin/env bash
# Runtime proof — X-Axonflow-Client version identifier on the wire (#2860).
#
# Drives the REAL proxy (same binary Claude Desktop launches) through a
# header-recording reverse proxy (recorder/) in front of a LIVE enterprise
# agent, and asserts on the actual wire:
#
#   [1] the /api/v1/decide call carries  X-Axonflow-Client: mcp-proxy/<proxyVersion>
#   [2] the /api/v1/mcp/check-output call carries the same value
#   [3] the governed tools/call still SUCCEEDS through the recorder (the
#       header is transparent to governance)
#   [4] FAIL-OPEN: a decide with a garbage X-Axonflow-Client — and one with
#       none at all — still returns HTTP 200 + a verdict (telemetry can never
#       fail a decision or 401)
#
# The expected value is extracted from cmd/axonflow-mcp-proxy/main.go
# (proxyVersion), NOT hardcoded — the assertion follows the single source.
#
# Requirements: a live enterprise agent (reuses matrix.sh's stack when up, or
# boots the harness docker-compose) + AXONFLOW_LICENSE_KEY.
#
# Usage:
#   export AXONFLOW_LICENSE_KEY="$(cat partner.license)"
#   ./client_header.sh                                     # boot, run, tear down
#   COMPOSE_PROJECT=sh-e2e-matrix AXONFLOW_ENDPOINT=http://localhost:8080 \
#     ./client_header.sh                                   # reuse a running stack
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE="$HERE/docker-compose.yml"
PROJECT="${COMPOSE_PROJECT:-sh-e2e-clienthdr}"
ORG="${AXONFLOW_ORG_ID:-bukuwarung-eval}"
ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
RECORDER_ADDR="${RECORDER_ADDR:-127.0.0.1:18099}"
WORK="$(mktemp -d)"

: "${AXONFLOW_LICENSE_KEY:?set AXONFLOW_LICENSE_KEY to an Enterprise license (org=$ORG)}"

ok() { echo "==> $1"; }
fail=0
RECORDER_PID=""
cleanup() {
  [ -n "$RECORDER_PID" ] && kill "$RECORDER_PID" >/dev/null 2>&1 || true
  rm -rf "$WORK"
  if [ "${KEEP_STACK:-0}" != "1" ] && [ "${REUSED_STACK:-0}" != "1" ]; then
    docker compose -f "$COMPOSE" -p "$PROJECT" down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# --- 0. expected header value from the single source ------------------------
PROXY_VERSION="$(sed -n 's/^const proxyVersion = "\(.*\)"$/\1/p' "$ROOT/cmd/axonflow-mcp-proxy/main.go")"
[ -n "$PROXY_VERSION" ] || { echo "FATAL: cannot extract proxyVersion"; exit 1; }
EXPECTED="mcp-proxy/$PROXY_VERSION"
ok "expecting X-Axonflow-Client: $EXPECTED"

# --- 1. build proxy + backend + recorder ------------------------------------
ok "building proxy + official-SDK backend + recorder"
PROXY="$WORK/axonflow-mcp-proxy"; BACKEND="$WORK/backend"; RECORDER="$WORK/recorder"
( cd "$ROOT" && go build -o "$PROXY" ./cmd/axonflow-mcp-proxy && go build -o "$RECORDER" ./runtime-e2e/cli-harness/recorder )
( cd "$HERE/backend" && go build -o "$BACKEND" . )
printf '[{"id":"bw","command":"%s"}]\n' "$BACKEND" > "$WORK/backends.json"

# --- 2. live agent (reuse or boot) ------------------------------------------
if curl -s -m 3 "$ENDPOINT/health" >/dev/null 2>&1; then
  ok "reusing already-healthy stack at $ENDPOINT"
  REUSED_STACK=1
else
  ok "starting live enterprise agent ($PROJECT)"
  AXONFLOW_LICENSE_KEY="$AXONFLOW_LICENSE_KEY" \
    docker compose -f "$COMPOSE" -p "$PROJECT" up -d >/dev/null
fi
echo -n "    waiting for tier=Enterprise"
tier=""
for _ in $(seq 1 60); do
  tier="$(curl -s -m 3 "$ENDPOINT/health" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("tier",""))' 2>/dev/null || true)"
  [ "$tier" = "Enterprise" ] && break
  echo -n "."; sleep 3
done
echo ""
[ "$tier" = "Enterprise" ] || { echo "FATAL: agent never reached tier=Enterprise (got '$tier')"; exit 1; }

# Gate on the response plane answering 200 (health flips early; see matrix.sh).
echo -n "    waiting for check-output to answer 200"
co_auth="$(printf %s "$ORG:$AXONFLOW_LICENSE_KEY" | base64 | tr -d '\n')"
code=""
for _ in $(seq 1 40); do
  code="$(curl -s -o /dev/null -m 4 -w '%{http_code}' -X POST "$ENDPOINT/api/v1/mcp/check-output" \
    -H "Authorization: Basic $co_auth" -H "Content-Type: application/json" \
    -d "{\"message\":\"warmup\",\"connector_type\":\"claude-desktop-proxy\",\"tenant_id\":\"$ORG\"}" 2>/dev/null || true)"
  [ "$code" = "200" ] && break
  echo -n "."; sleep 2
done
echo " ($code)"
[ "$code" = "200" ] || { echo "FATAL: check-output never reached 200"; exit 1; }

# --- 3. recorder between proxy and agent ------------------------------------
ok "starting recorder $RECORDER_ADDR → $ENDPOINT"
WIRE="$WORK/wire.jsonl"
"$RECORDER" "$RECORDER_ADDR" "$ENDPOINT" "$WIRE" 2>"$WORK/recorder.stderr" &
RECORDER_PID=$!
sleep 1
kill -0 "$RECORDER_PID" 2>/dev/null || { echo "FATAL: recorder died"; cat "$WORK/recorder.stderr"; exit 1; }

# --- 4. drive the REAL proxy through the recorder ---------------------------
# One allow-path tools/call: decide fires pre-call, check-output fires on the
# response (redact=always). Exactly what Claude Desktop does per governed call.
ok "driving real proxy (initialize + tools/call get_sales_summary)"
cat > "$WORK/req.jsonl" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_sales_summary","arguments":{"period":"2026-Q2"}}}
EOF
AXONFLOW_ENDPOINT="http://$RECORDER_ADDR" \
AXONFLOW_CLIENT_ID="$ORG" \
AXONFLOW_CLIENT_SECRET="$AXONFLOW_LICENSE_KEY" \
AXONFLOW_TENANT_ID="$ORG" \
AXONFLOW_ORG_ID="$ORG" \
AXONFLOW_BACKENDS_FILE="$WORK/backends.json" \
AXONFLOW_AUDIT_LOG="$WORK/audit.jsonl" \
AXONFLOW_FAIL_MODE="closed" \
AXONFLOW_REDACT_RESPONSES="always" \
AXONFLOW_DECIDE_TIMEOUT="8s" \
  "$PROXY" < "$WORK/req.jsonl" > "$WORK/out.jsonl" 2>"$WORK/proxy.stderr"

# --- 5. assert the wire ------------------------------------------------------
ok "asserting wire records"
python3 - "$WIRE" "$WORK/out.jsonl" "$EXPECTED" <<'PY' || fail=1
import json, sys
wire_path, out_path, expected = sys.argv[1], sys.argv[2], sys.argv[3]
records = [json.loads(l) for l in open(wire_path) if l.strip()]
by_path = {}
for r in records:
    by_path.setdefault(r["path"], []).append(r)

rc = 0
for path in ("/api/v1/decide", "/api/v1/mcp/check-output"):
    rows = by_path.get(path, [])
    if not rows:
        print(f"  ❌ no {path} call observed on the wire"); rc = 1; continue
    bad = [r for r in rows if r["x_axonflow_client"] != expected]
    if bad:
        print(f"  ❌ {path}: {len(bad)}/{len(rows)} calls without {expected!r}: {bad}"); rc = 1
    else:
        print(f"  ✅ {path}: {len(rows)} call(s), all with X-Axonflow-Client={expected!r}")

# [3] governance transparent: the tools/call must have succeeded end-to-end.
got_result = False
for line in open(out_path):
    line = line.strip()
    if not line: continue
    o = json.loads(line)
    if o.get("id") == 2 and "result" in o and "error" not in o:
        got_result = True
if got_result:
    print("  ✅ tools/call id=2 returned a result through the recorder (governance unaffected)")
else:
    print("  ❌ tools/call id=2 did not return a result"); rc = 1
sys.exit(rc)
PY

# --- 6. fail-open: garbage / absent header must not affect a decision --------
ok "fail-open: decide with GARBAGE X-Axonflow-Client"
decide_body="{\"stage\":\"tool\",\"caller_identity\":{\"gateway_id\":\"claude_desktop.hdrtest\",\"tenant_id\":\"$ORG\",\"org_id\":\"$ORG\"},\"target\":{\"type\":\"tool\",\"tool\":\"lookup\"},\"query\":\"tool_call: lookup\"}"
garbage='x!!/////not a client@@@ 版本 <script>alert(1)</script> aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
for hdr_mode in garbage absent; do
  if [ "$hdr_mode" = "garbage" ]; then
    resp="$(curl -s -m 8 -w '\n%{http_code}' -X POST "$ENDPOINT/api/v1/decide" \
      -H "Authorization: Basic $co_auth" -H "Content-Type: application/json" \
      -H "X-Axonflow-Client: $garbage" -d "$decide_body")"
  else
    resp="$(curl -s -m 8 -w '\n%{http_code}' -X POST "$ENDPOINT/api/v1/decide" \
      -H "Authorization: Basic $co_auth" -H "Content-Type: application/json" \
      -d "$decide_body")"
  fi
  http_code="$(echo "$resp" | tail -1)"
  verdict="$(echo "$resp" | sed '$d' | python3 -c 'import sys,json;print(json.load(sys.stdin).get("verdict",""))' 2>/dev/null || true)"
  if [ "$http_code" = "200" ] && [ -n "$verdict" ]; then
    echo "  ✅ $hdr_mode header: HTTP 200 verdict=$verdict (decision unaffected, no 401)"
  else
    echo "  ❌ $hdr_mode header: HTTP $http_code verdict='$verdict'"; fail=1
  fi
done

echo ""
if [ "$fail" = "0" ]; then echo "=== client_header.sh: ALL PASS ==="; else echo "=== client_header.sh: FAILURES ==="; fi
exit $fail
