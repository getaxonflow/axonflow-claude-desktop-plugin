#!/usr/bin/env bash
# DETERMINISTIC governance matrix for the AxonFlow Claude Desktop proxy.
#
# Companion to run.sh. run.sh proves the chain through Claude Code (a real LLM
# MCP client) on a happy path; this matrix drives the SAME real proxy + real
# official-SDK backend + live in-vpc-enterprise PDP through a DETERMINISTIC MCP
# client (exact JSON-RPC over stdio, exactly as Claude Desktop frames it), so
# every governance behaviour is exercised with its trigger PRESENT *and* ABSENT.
#
# Why a deterministic client AND the Claude-Code one: the §4.3 response-only leak
# (#2530) survived 30/0 because the only redact case always put PII in the
# request — so the clean-request path was never run. An LLM client can't be
# trusted to emit an exact DELETE string or a foreign tenant id on demand; this
# harness can. The proxy's response to this client is byte-identical to what it
# hands Claude.
#
# Coverage (>=15 core cases + fail-closed + tenant-isolation):
#   allow:   export_ledger, get_sales_summary                       (neither)
#   redact:  lookup_customer(customer_id) / get_bank_details /      (response-only)
#            list_contacts(array)
#   redact:  lookup_customer(customer_id + aadhaar)                 (both)
#   request-only PII: export_ledger(aadhaar arg), clean response    (request-only)
#   deny:    DROP / UNION / OR-true / injection-override /          (system policies)
#            injection-reveal / dangerous-command
#   deny:    DELETE / UPDATE / INSERT                               (BukuWarung bundle read-only)
#   fail-closed: PDP unreachable -> -32003
#   tenant-isolation: foreign tenant -> PDP 403 -> blocked
# Every case is also run through the UNIVERSAL PII-leak detector (matrix_assert.py).
#
# Requirements: docker, AXONFLOW_LICENSE_KEY (Enterprise, org=AXONFLOW_ORG_ID),
# and the BukuWarung policy bundle SQL (for the read-only cases) — by default the
# canonical file in a sibling axonflow-enterprise checkout; override with
# AXONFLOW_BUNDLE_SQL.
#
# Usage:
#   export AXONFLOW_LICENSE_KEY="$(cat bukuwarung.license)"
#   ./matrix.sh                       # brings the stack up, runs, tears it down
#   KEEP_STACK=1 ./matrix.sh          # leave the stack up
#   COMPOSE_PROJECT=cd-live AXONFLOW_ENDPOINT=http://localhost:8080 ./matrix.sh  # reuse a running stack
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE="$HERE/docker-compose.yml"
PROJECT="${COMPOSE_PROJECT:-sh-e2e-matrix}"
ORG="${AXONFLOW_ORG_ID:-bukuwarung}"
LEADER="${AXONFLOW_LEADER_EMAIL:-ben.jonathan@bukuwarung.test}"
ENDPOINT="${AXONFLOW_ENDPOINT:-http://localhost:8080}"
FOREIGN_TENANT="${FOREIGN_TENANT:-acme-corp}"
BUNDLE_SQL="${AXONFLOW_BUNDLE_SQL:-$ROOT/../axonflow-enterprise/config/seed-data/bukuwarung/bukuwarung_policy_bundle.sql}"
WORK="$(mktemp -d)"

: "${AXONFLOW_LICENSE_KEY:?set AXONFLOW_LICENSE_KEY to an Enterprise license (org=$ORG)}"

ok() { echo "==> $1"; }
cleanup() {
  rm -rf "$WORK"
  if [ "${KEEP_STACK:-0}" != "1" ] && [ "${REUSED_STACK:-0}" != "1" ]; then
    echo "==> tearing down stack ($PROJECT)"
    docker compose -f "$COMPOSE" -p "$PROJECT" down -v >/dev/null 2>&1 || true
  else
    echo "==> leaving stack up ($PROJECT)"
  fi
}
trap cleanup EXIT

# --- 1. build proxy + the real SDK backend ---------------------------------
ok "building proxy + official-SDK backend"
PROXY="$WORK/axonflow-mcp-proxy"
BACKEND="$WORK/bukuwarung-backend"
if [ -n "${PROXY_BIN:-}" ]; then
  cp "$PROXY_BIN" "$PROXY"; chmod +x "$PROXY"
else
  ( cd "$ROOT" && go build -o "$PROXY" ./cmd/axonflow-mcp-proxy )
fi
( cd "$HERE/backend" && go build -o "$BACKEND" . )
BACKENDS_FILE="$WORK/backends.json"
printf '[{"id":"bw","command":"%s"}]\n' "$BACKEND" > "$BACKENDS_FILE"

# --- 2. bring up (or reuse) the live in-vpc-enterprise stack ----------------
if curl -s -m 3 "$ENDPOINT/health" >/dev/null 2>&1; then
  ok "reusing already-healthy stack at $ENDPOINT (project $PROJECT)"
  REUSED_STACK=1
else
  ok "starting live in-vpc-enterprise agent ($PROJECT)"
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
[ "$tier" = "Enterprise" ] || { echo "FATAL: agent did not reach tier=Enterprise (got '$tier')"; exit 1; }
echo "    /health → tier=Enterprise"

# --- 3. seed the BukuWarung policy bundle (read-only enforcement) -----------
# The DELETE/UPDATE/INSERT deny cases (114-116) require the bundle's
# buku_org_readonly_write_block row; vanilla system policies allow writes. The
# decide path reads static_policies live, so no agent restart is needed.
if [ -f "$BUNDLE_SQL" ]; then
  ok "seeding BukuWarung policy bundle ($BUNDLE_SQL)"
  docker compose -f "$COMPOSE" -p "$PROJECT" exec -T postgres \
    psql -U axonflow -d axonflow < "$BUNDLE_SQL" >/dev/null 2>&1 \
    && echo "    bundle seeded (idempotent)" \
    || { echo "FATAL: bundle seed failed"; exit 1; }
else
  echo "FATAL: BukuWarung bundle SQL not found at $BUNDLE_SQL — set AXONFLOW_BUNDLE_SQL."
  echo "       (read-only cases 114-116 require it; refusing to silently skip.)"
  exit 1
fi

# --- 3b. neutralise the anti-abuse circuit breaker for the test org --------
# The agent trips a per-client circuit breaker after 5 policy violations in a
# 5-min window (an anti-abuse feature, ORTHOGONAL to the proxy behaviour under
# test). The matrix intentionally generates 9 denies per run, which would trip it
# and turn every later call into a 503/fail-closed. So the harness raises the
# test org's violation threshold, clears any open circuit, and restarts the agent
# so the change + a clean breaker state are loaded. This touches ONLY the test
# org's anti-abuse config — it does not weaken any governance verdict.
ok "neutralising anti-abuse circuit breaker for org=$ORG (test-only)"
PSQL() { docker compose -f "$COMPOSE" -p "$PROJECT" exec -T postgres psql -U axonflow -d axonflow "$@"; }
PSQL -c "INSERT INTO circuit_breaker_config (org_id, tenant_id, error_threshold, violation_threshold, window_seconds, default_timeout_seconds, max_timeout_seconds, enable_auto_recovery) VALUES ('$ORG','$ORG',100000,100000,60,30,300,true) ON CONFLICT (org_id, tenant_id) DO UPDATE SET error_threshold=EXCLUDED.error_threshold, violation_threshold=EXCLUDED.violation_threshold, window_seconds=EXCLUDED.window_seconds;" >/dev/null 2>&1 || true
PSQL -c "DELETE FROM circuit_breaker WHERE org_id='$ORG';" >/dev/null 2>&1 || true
docker compose -f "$COMPOSE" -p "$PROJECT" restart axonflow-agent >/dev/null 2>&1 || docker restart "${PROJECT}-axonflow-agent-1" >/dev/null 2>&1 || true
echo -n "    waiting for tier=Enterprise after restart"
for _ in $(seq 1 60); do
  tier="$(curl -s -m 3 "$ENDPOINT/health" 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin).get("tier",""))' 2>/dev/null || true)"
  [ "$tier" = "Enterprise" ] && break
  echo -n "."; sleep 3
done
echo ""
[ "$tier" = "Enterprise" ] || { echo "FATAL: agent did not recover after breaker reset"; exit 1; }
sleep 2

# --- 4. generate the exact-arg JSON-RPC request streams --------------------
# Python writes the request files so exact SQL/injection strings keep their
# quoting verbatim (the whole point of a deterministic client).
gen_requests() { python3 "$HERE/matrix_gen.py" "$WORK"; }
gen_requests

# drive <reqfile> <outfile> <auditfile> <endpoint> <tenant> [redact_mode]
drive() {
  local req="$1" out="$2" audit="$3" endpoint="$4" tenant="$5" redact="${6:-always}"
  AXONFLOW_ENDPOINT="$endpoint" \
  AXONFLOW_CLIENT_ID="$ORG" \
  AXONFLOW_CLIENT_SECRET="$AXONFLOW_LICENSE_KEY" \
  AXONFLOW_TENANT_ID="$tenant" \
  AXONFLOW_ORG_ID="$ORG" \
  AXONFLOW_BACKENDS_FILE="$BACKENDS_FILE" \
  AXONFLOW_AUDIT_LOG="$audit" \
  AXONFLOW_LEADER_EMAIL="$LEADER" \
  AXONFLOW_FAIL_MODE="closed" \
  AXONFLOW_REDACT_RESPONSES="$redact" \
  AXONFLOW_DECIDE_TIMEOUT="8s" \
    "$PROXY" < "$req" > "$out" 2>"$out.stderr"
}

ok "driving deterministic matrix (own tenant, default redact=always)"
drive "$WORK/main.req.jsonl"       "$WORK/matrix.out.jsonl"            "$WORK/matrix.audit.jsonl"            "$ENDPOINT"          "$ORG"
ok "driving fail-closed (dead PDP)"
drive "$WORK/failclosed.req.jsonl" "$WORK/matrix_failclosed.out.jsonl" "$WORK/matrix_failclosed.audit.jsonl" "http://127.0.0.1:1" "$ORG"
ok "driving tenant-isolation (foreign tenant=$FOREIGN_TENANT)"
drive "$WORK/tenant.req.jsonl"     "$WORK/matrix_tenant.out.jsonl"     "$WORK/matrix_tenant.audit.jsonl"     "$ENDPOINT"          "$FOREIGN_TENANT"
ok "driving NEGATIVE CONTROL (clean request, legacy redact=on-obligation → MUST leak)"
drive "$WORK/negcontrol.req.jsonl" "$WORK/matrix_negcontrol.out.jsonl" "$WORK/matrix_negcontrol.audit.jsonl" "$ENDPOINT"          "$ORG"               "on-obligation"

# --- 5. assert -------------------------------------------------------------
ok "asserting"
echo "------------------------------------------------------------"
set +e
python3 "$HERE/matrix_assert.py" "$WORK" "$PROJECT" "$COMPOSE" "$LEADER"
rc=$?
set -e
echo "------------------------------------------------------------"

# --- 6. evidence -----------------------------------------------------------
echo
echo "===== EVIDENCE: proxy responses (id → verdict/redaction) ====="
python3 - "$WORK/matrix.out.jsonl" <<'PY'
import json, sys
for line in open(sys.argv[1]):
    line = line.strip()
    if not line: continue
    o = json.loads(line)
    if o.get("id") is None: continue
    if "error" in o:
        print(f'  id={o["id"]:>3}  ERROR {o["error"]["code"]}  {o["error"]["message"][:70]}')
    else:
        body = json.dumps(o.get("result", {}))
        red = body.count("[REDACTED:")
        print(f'  id={o["id"]:>3}  result  redactions={red}  {body[:80]}')
PY
echo
echo "===== EVIDENCE: platform audit_logs decide rows (psql) ====="
docker compose -f "$COMPOSE" -p "$PROJECT" exec -T postgres psql -U axonflow -d axonflow -At -c \
  "SELECT policy_decision, policy_details->>'gateway_id', array_to_string(ARRAY(SELECT jsonb_array_elements_text(policy_details->'policy_ids')),',') FROM audit_logs WHERE id LIKE 'decide_%' ORDER BY timestamp DESC LIMIT 18;" 2>/dev/null || true

exit $rc
