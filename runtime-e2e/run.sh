#!/usr/bin/env bash
# runtime-e2e for the AxonFlow Claude Desktop governance proxy.
#
# Drives the REAL proxy (over stdio, exactly as Claude Desktop launches it) in
# front of a REAL stub backend MCP server, against a LIVE ENTERPRISE AxonFlow
# agent authenticated with a REAL Ed25519 license. No mocked verdicts AND no
# mocked redaction: every allow/deny verdict is a real PDP decision, and every
# redaction is performed by the platform's AUTHORITATIVE engine
# (POST /api/v1/mcp/check-output) — the proxy holds no local redactor anymore.
#
# Asserts:
#   1. allow        — a benign tool call is forwarded to the backend
#   2. deny         — a SQL-injection tool call is blocked (-32001), backend untouched
#   3. redact       — a CLEAN request whose response carries NIK + SSN + email +
#                     phone has ALL FOUR stripped by the engine before reaching
#                     Claude (the §4.3 control; no request-side obligation needed)
#   4. fail-closed  — PDP/engine unreachable → the call is blocked (-32003)
#   5. demo-creds   — a bogus license is REFUSED (-32003); the backend is never
#                     reached and no PII is forwarded (no demo creds, ever)
#
# Usage (real license + enterprise image are REQUIRED — see docker-compose.yml):
#   export AXONFLOW_AGENT_IMAGE=axonflow-agent:enterprise-local
#   export AXONFLOW_LICENSE_KEY="AXON-…"          # real Ed25519 Enterprise license
#   export AXONFLOW_ORG_ID="desktop-e2e"          # license org id (Basic-auth user)
#   docker compose up -d
#   ./run.sh
#   docker compose down -v
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PROXY="$WORK/axonflow-mcp-proxy"
STUB="$WORK/stub-mcp-server"

pass=0 fail=0
ok()   { echo "  ✅ $1"; pass=$((pass+1)); }
bad()  { echo "  ❌ $1"; fail=$((fail+1)); }

# ---- guard: a REAL license is mandatory; demo creds are refused -------------
LICENSE="${AXONFLOW_LICENSE_KEY:-}"
ORG="${AXONFLOW_ORG_ID:-}"
if [ -z "$LICENSE" ] || [ -z "$ORG" ]; then
  echo "FATAL: AXONFLOW_LICENSE_KEY and AXONFLOW_ORG_ID must be set to a REAL Ed25519" >&2
  echo "       Enterprise license + its org id. This harness does NOT ship demo creds." >&2
  echo "       Mint one with the enterprise repo: scripts/setup-e2e-testing.sh enterprise" >&2
  echo "       (or ee/platform/agent/license/cmd/keygen)." >&2
  exit 1
fi
case "$LICENSE" in
  AXON-*) : ;;  # V2 Ed25519 prefix
  *) echo "FATAL: AXONFLOW_LICENSE_KEY does not look like a real license (AXON-…); refusing." >&2; exit 1 ;;
esac
# Reject obvious placeholders/demo strings outright.
case "$LICENSE" in
  *bogus*|*demo*|*placeholder*|*REPLACE*|*test-license*) echo "FATAL: license looks like a placeholder; refusing." >&2; exit 1 ;;
esac

echo "==> building proxy + stub"
( cd "$ROOT" && go build -o "$PROXY" ./cmd/axonflow-mcp-proxy && go build -o "$STUB" ./runtime-e2e/stub-mcp-server )
echo "    proxy: $PROXY"
echo "    stub:  $STUB"

echo "==> checking live ENTERPRISE agent at $ENDPOINT"
if ! curl -s -m 5 "$ENDPOINT/health" >/dev/null; then
  echo "FATAL: no live agent at $ENDPOINT — run 'docker compose up -d' first" >&2
  exit 1
fi
ok "live agent reachable"

BACKENDS="[{\"id\":\"crm\",\"command\":\"$STUB\"}]"

# drive <endpoint> <client_secret> <audit_file> <requests...> — pipes
# newline-delimited JSON-RPC into the proxy over stdio (enterprise Basic auth:
# CLIENT_ID=org, CLIENT_SECRET=license) and prints the proxy's stdout.
drive() {
  local endpoint="$1" secret="$2" audit="$3"; shift 3
  printf '%s\n' "$@" | AXONFLOW_ENDPOINT="$endpoint" \
    AXONFLOW_CLIENT_ID="$ORG" \
    AXONFLOW_CLIENT_SECRET="$secret" \
    AXONFLOW_ORG_ID="$ORG" \
    AXONFLOW_TENANT_ID="$ORG" \
    AXONFLOW_BACKENDS="$BACKENDS" \
    AXONFLOW_AUDIT_LOG="$audit" \
    AXONFLOW_LEADER_EMAIL="ben.jonathan@bukuwarung.test" \
    AXONFLOW_FAIL_MODE="closed" \
    AXONFLOW_REDACT_RESPONSES="always" \
    AXONFLOW_DECIDE_TIMEOUT="8s" \
    "$PROXY" 2>"$audit.stderr"
}

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
INITED='{"jsonrpc":"2.0","method":"notifications/initialized"}'
LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# ---------------------------------------------------------------------------
echo "==> TEST 1: live allow / deny / engine-backed redact (NIK+SSN+email+phone)"
AUDIT="$WORK/audit.jsonl"
ALLOW_CALL='{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"export_ledger","arguments":{"rows":3}}}'
DENY_CALL='{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"lookup_customer","arguments":{"q":"1 OR 1=1; DROP TABLE customers;--"}}}'
# CLEAN request (customer_id only → allow, NO obligation) whose RESPONSE carries
# NIK + SSN + email + phone. The engine must strip all four on the response side.
REDACT_CALL='{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"lookup_customer","arguments":{"customer_id":"CUST-001"}}}'

OUT="$(drive "$ENDPOINT" "$LICENSE" "$AUDIT" "$INIT" "$INITED" "$LIST" "$ALLOW_CALL" "$DENY_CALL" "$REDACT_CALL")"
echo "$OUT" > "$WORK/out.jsonl"

python3 - "$WORK/out.jsonl" "$AUDIT" <<'PY'
import json, sys
out_path, audit_path = sys.argv[1], sys.argv[2]
resp = {}
for line in open(out_path):
    line = line.strip()
    if not line: continue
    o = json.loads(line)
    if "id" in o and o["id"] is not None:
        resp[o["id"]] = o
audit = [json.loads(l) for l in open(audit_path) if l.strip()]
fails = 0
def check(cond, msg):
    global fails
    print(("  ✅ " if cond else "  ❌ ")+msg)
    if not cond: fails += 1

tl = resp.get(2,{}).get("result",{}).get("tools",[])
names = sorted(t.get("name") for t in tl)
check("export_ledger" in names and "lookup_customer" in names, f"tools/list aggregated backend tools: {names}")

# ALLOW (id 10)
r10 = resp.get(10,{})
check("error" not in r10 and "result" in r10, "allow: benign call forwarded (result, no error)")

# DENY (id 11) → -32001
r11 = resp.get(11,{})
check(r11.get("error",{}).get("code") == -32001, f"deny: SQLi blocked with -32001 (got {r11.get('error',{}).get('code')})")

# REDACT (id 12) → allow result, ALL FOUR PII categories stripped by the engine
r12 = resp.get(12,{})
body = json.dumps(r12.get("result",{}))
check("error" not in r12, "redact: clean request allowed (no obligation)")
raw_pii = {
    "NIK":   "3174012509900001",
    "email": "budi.santoso@example.co.id",
    "phone": "+6281234567890",
    "SSN":   "123-45-6789",
}
for label, val in raw_pii.items():
    check(val not in body, f"redact: {label} ({val}) stripped from response")
# The response must still be a non-empty, valid MCP result (engine round-trip).
check(bool(r12.get("result",{}).get("content")), "redact: forwarded response is a valid non-empty MCP result")

# Audit rows: one per call, real verdicts + correlation fields
check(len(audit) == 3, f"audit: exactly 3 Layer-1 rows written (got {len(audit)})")
deny_rows  = [a for a in audit if a["verdict"]=="deny"]
check(len(deny_rows) >= 1 and deny_rows[0]["decision_id"], "audit: deny row carries decision_id")
redact_rows = [a for a in audit if a.get("redaction_count",0) > 0]
check(len(redact_rows) == 1, f"audit: exactly one row recorded redactions (got {len(redact_rows)})")
for a in audit:
    if not (a.get("session_id") and a.get("leader_email") and a.get("trace_id") and a.get("gateway_id","").startswith("claude_desktop.")):
        check(False, f"audit: row missing required fields: {a}")
        break
else:
    check(True, "audit: every row carries session_id/leader_email/trace_id/gateway_id")

sys.exit(1 if fails else 0)
PY
[ $? -eq 0 ] && ok "TEST 1 assertions passed" || bad "TEST 1 assertions failed"

# ---------------------------------------------------------------------------
echo "==> TEST 2: fail-closed (PDP/engine unreachable → blocked)"
AUDIT2="$WORK/audit-fc.jsonl"
FC_CALL='{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"export_ledger","arguments":{"rows":1}}}'
OUT2="$(drive "http://127.0.0.1:1" "$LICENSE" "$AUDIT2" "$INIT" "$INITED" "$FC_CALL")"
echo "$OUT2" > "$WORK/out-fc.jsonl"
python3 - "$WORK/out-fc.jsonl" "$AUDIT2" <<'PY'
import json, sys
resp = {}
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    o=json.loads(line)
    if o.get("id") is not None: resp[o["id"]]=o
audit=[json.loads(l) for l in open(sys.argv[2]) if l.strip()]
fails=0
def check(cond,msg):
    global fails; print(("  ✅ " if cond else "  ❌ ")+msg)
    if not cond: fails+=1
r=resp.get(20,{})
check(r.get("error",{}).get("code") == -32003, f"fail-closed: blocked with -32003 (got {r.get('error',{}).get('code')})")
check(any(a["verdict"]=="deny" for a in audit), "fail-closed: audit row recorded verdict=deny")
sys.exit(1 if fails else 0)
PY
[ $? -eq 0 ] && ok "TEST 2 assertions passed" || bad "TEST 2 assertions failed"

# ---------------------------------------------------------------------------
echo "==> TEST 3: demo creds refused (bogus license → blocked, no PII forwarded)"
AUDIT3="$WORK/audit-demo.jsonl"
DEMO_CALL='{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"lookup_customer","arguments":{"customer_id":"CUST-001"}}}'
# A deliberately invalid license — the live agent must 401 the decide call, so
# the proxy fails closed and never reaches the backend / never forwards PII.
OUT3="$(drive "$ENDPOINT" "AXON-not-a-real-license.deadbeef" "$AUDIT3" "$INIT" "$INITED" "$DEMO_CALL")"
echo "$OUT3" > "$WORK/out-demo.jsonl"
python3 - "$WORK/out-demo.jsonl" <<'PY'
import json, sys
resp = {}
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    o=json.loads(line)
    if o.get("id") is not None: resp[o["id"]]=o
fails=0
def check(cond,msg):
    global fails; print(("  ✅ " if cond else "  ❌ ")+msg)
    if not cond: fails+=1
r=resp.get(30,{})
check(r.get("error",{}).get("code") == -32003, f"demo-creds: blocked with -32003 (got {r.get('error',{}).get('code')})")
blob=json.dumps(r)
check("3174012509900001" not in blob and "123-45-6789" not in blob, "demo-creds: no PII forwarded under refused creds")
sys.exit(1 if fails else 0)
PY
[ $? -eq 0 ] && ok "TEST 3 assertions passed" || bad "TEST 3 assertions failed"

# ---------------------------------------------------------------------------
echo
echo "==> RESULT: $pass passed, $fail failed"
echo "--- sample Layer-1 audit rows (TEST 1) ---"
cat "$WORK/audit.jsonl" 2>/dev/null | python3 -m json.tool --json-lines 2>/dev/null || cat "$WORK/audit.jsonl"
echo "--- engine-redacted lookup_customer response (id 12) ---"
python3 -c 'import json,sys; o=[json.loads(l) for l in open(sys.argv[1]) if l.strip()]; r=[x for x in o if x.get("id")==12]; print(json.dumps(r[0]["result"], indent=2) if r else "(none)")' "$WORK/out.jsonl" 2>/dev/null || true
[ "$fail" -eq 0 ] || exit 1
