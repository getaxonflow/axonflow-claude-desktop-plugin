#!/usr/bin/env bash
# runtime-e2e for the AxonFlow Claude Desktop governance proxy.
#
# Drives the REAL proxy (over stdio, exactly as Claude Desktop launches it) in
# front of a REAL stub backend MCP server, against a LIVE AxonFlow Decision API.
# No mocked verdicts: every allow/deny/redact assertion is a real PDP decision,
# and the audit assertions read the proxy's actual Layer-1 JSONL.
#
# Asserts the four governance behaviours from issue #2520's acceptance criteria:
#   1. allow        — a benign tool call is forwarded to the backend
#   2. deny         — a SQL-injection tool call is blocked (-32001), backend untouched
#   3. redact       — a PII-bearing response is stripped before reaching Claude
#   4. fail-closed  — PDP unreachable → the call is blocked (-32003)
#
# Usage:
#   docker compose up -d          # boot the live agent (see docker-compose.yml)
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

echo "==> building proxy + stub"
( cd "$ROOT" && go build -o "$PROXY" ./cmd/axonflow-mcp-proxy && go build -o "$STUB" ./runtime-e2e/stub-mcp-server )
echo "    proxy: $PROXY"
echo "    stub:  $STUB"

echo "==> checking live agent at $ENDPOINT"
if ! curl -s -m 5 "$ENDPOINT/health" >/dev/null; then
  echo "FATAL: no live agent at $ENDPOINT — run 'docker compose up -d' first" >&2
  exit 1
fi
ok "live agent reachable"

BACKENDS="[{\"id\":\"crm\",\"command\":\"$STUB\"}]"

# drive <endpoint> <audit_file> <requests...>  — pipes newline-delimited
# JSON-RPC into the proxy over stdio and prints the proxy's stdout (responses).
drive() {
  local endpoint="$1" audit="$2"; shift 2
  printf '%s\n' "$@" | AXONFLOW_ENDPOINT="$endpoint" \
    AXONFLOW_CLIENT_ID="e2e-2520" \
    AXONFLOW_TENANT_ID="e2e-tenant" \
    AXONFLOW_BACKENDS="$BACKENDS" \
    AXONFLOW_AUDIT_LOG="$audit" \
    AXONFLOW_LEADER_EMAIL="ben.jonathan@bukuwarung.test" \
    AXONFLOW_FAIL_MODE="closed" \
    AXONFLOW_DECIDE_TIMEOUT="8s" \
    "$PROXY" 2>"$audit.stderr"
}

INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}'
INITED='{"jsonrpc":"2.0","method":"notifications/initialized"}'
LIST='{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# ---------------------------------------------------------------------------
echo "==> TEST 1: live allow / deny / redact"
AUDIT="$WORK/audit.jsonl"
ALLOW_CALL='{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"export_ledger","arguments":{"rows":3}}}'
DENY_CALL='{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"lookup_customer","arguments":{"q":"1 OR 1=1; DROP TABLE customers;--"}}}'
# REDACT trigger vs content (two different things):
#  - REQUEST-side trigger: the arg carries an Aadhaar (RBI India PII). On the
#    pinned community agent the redact_pii OBLIGATION fires for RBI India PII
#    (policy sys_pii_aadhaar); Indonesia NIK alone returns allow with no
#    obligation on this image — hence Aadhaar is the deterministic trigger.
#  - RESPONSE-side content: the stub's lookup_customer returns INDONESIAN PII
#    (NIK + email + +62 phone); the proxy strips THAT from the response. So the
#    test proves request-trigger → response-redaction end to end.
REDACT_TRIGGER='{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"lookup_customer","arguments":{"pii_trigger_rbi_aadhaar":"2234 5678 9012"}}}'

OUT="$(drive "$ENDPOINT" "$AUDIT" "$INIT" "$INITED" "$LIST" "$ALLOW_CALL" "$DENY_CALL" "$REDACT_TRIGGER")"
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

# tools/list aggregated the stub's tools
tl = resp.get(2,{}).get("result",{}).get("tools",[])
names = sorted(t.get("name") for t in tl)
check("export_ledger" in names and "lookup_customer" in names, f"tools/list aggregated backend tools: {names}")

# ALLOW (id 10) → result present, no error
r10 = resp.get(10,{})
check("error" not in r10 and "result" in r10, "allow: benign call forwarded (result, no error)")

# DENY (id 11) → JSON-RPC error -32001
r11 = resp.get(11,{})
check(r11.get("error",{}).get("code") == -32001, f"deny: SQLi blocked with -32001 (got {r11.get('error',{}).get('code')})")

# REDACT (id 12) → allow result, PII stripped, tokens present
r12 = resp.get(12,{})
body = json.dumps(r12.get("result",{}))
check("error" not in r12, "redact: PII request allowed with obligation")
check("3174012509900001" not in body and "budi.santoso@example.co.id" not in body,
      "redact: NIK + email stripped from response")
check("[REDACTED:" in body, "redact: redaction tokens present in response")

# Audit rows: one per call, real verdicts + correlation fields
by_id = {a["tool_name"]+":"+a["verdict"]: a for a in audit}
verdicts = sorted(a["verdict"] for a in audit)
check(len(audit) == 3, f"audit: exactly 3 Layer-1 rows written (got {len(audit)})")
allow_rows = [a for a in audit if a["verdict"]=="allow"]
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
echo "==> TEST 2: fail-closed (PDP unreachable → blocked)"
AUDIT2="$WORK/audit-fc.jsonl"
FC_CALL='{"jsonrpc":"2.0","id":20,"method":"tools/call","params":{"name":"export_ledger","arguments":{"rows":1}}}'
OUT2="$(drive "http://127.0.0.1:1" "$AUDIT2" "$INIT" "$INITED" "$FC_CALL")"
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
echo
echo "==> RESULT: $pass passed, $fail failed"
echo "--- sample Layer-1 audit rows (TEST 1) ---"
cat "$WORK/audit.jsonl" 2>/dev/null | python3 -m json.tool --json-lines 2>/dev/null || cat "$WORK/audit.jsonl"
[ "$fail" -eq 0 ] || exit 1
