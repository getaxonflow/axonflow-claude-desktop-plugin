#!/usr/bin/env bash
# CLI-harness runtime-e2e for the AxonFlow Claude Desktop governance proxy.
#
# Applies our CLI-based plugin E2E methodology to the Desktop proxy: it drives
# the REAL proxy with a REAL MCP client — Claude Code, pointed at the proxy via
# `claude --mcp-config --strict-mcp-config` — in front of a REAL backend MCP
# server (built on the official MCP Go SDK, NOT the hand-rolled stub), against a
# LIVE in-vpc-enterprise AxonFlow agent (Decision Mode). No mocked verdicts and
# no fixtures: the live PDP issues every allow/deny/redact decision, the proxy
# enforces it, and every assertion is backed by the proxy's Layer-1 JSONL AND the
# platform's audit_logs DB row.
#
# This EXCEEDS the original ../run.sh (proxy-vs-stub, hand-fed JSON-RPC) on three
# axes: (1) a genuine MCP client (Claude Code) instead of piped JSON-RPC,
# (2) a genuine SDK backend instead of the stub, (3) in-vpc-enterprise + an
# Enterprise license (HTTP Basic auth) instead of the no-auth community agent.
#
# Requirements:
#   - docker (the in-vpc-enterprise agent + postgres run in compose)
#   - claude CLI, logged in (`claude /login`) — acts as the MCP client
#   - AXONFLOW_LICENSE_KEY : an Enterprise license (org = AXONFLOW_ORG_ID)
#   - AXONFLOW_AGENT_IMAGE : an EDITION=enterprise agent image at/after #2526
#                            (default axonflow-agent:sh-e2e — see docker-compose.yml)
#
# Usage:
#   export AXONFLOW_LICENSE_KEY="$(cat bukuwarung.license)"
#   export AXONFLOW_AGENT_IMAGE=axonflow-agent:sh-e2e
#   ./run.sh                 # brings the stack up, runs, tears it down
#   KEEP_STACK=1 ./run.sh    # leave the stack running for inspection
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
COMPOSE="$HERE/docker-compose.yml"
PROJECT="${COMPOSE_PROJECT:-sh-e2e-cli}"
ORG="${AXONFLOW_ORG_ID:-bukuwarung}"
LEADER="${AXONFLOW_LEADER_EMAIL:-ben.jonathan@bukuwarung.test}"
ENDPOINT="http://localhost:8080"
WORK="$(mktemp -d)"

: "${AXONFLOW_LICENSE_KEY:?set AXONFLOW_LICENSE_KEY to an Enterprise license (org=$ORG)}"
command -v claude >/dev/null || { echo "FATAL: claude CLI not found (this harness needs Claude Code as the MCP client)"; exit 1; }

pass=0 fail=0
ok()  { echo "==> $1"; }
cleanup() {
  rm -rf "$WORK"
  if [ "${KEEP_STACK:-0}" != "1" ]; then
    echo "==> tearing down stack ($PROJECT)"
    docker compose -f "$COMPOSE" -p "$PROJECT" down -v >/dev/null 2>&1 || true
  else
    echo "==> KEEP_STACK=1 — leaving stack up ($PROJECT). Tear down with:"
    echo "    docker compose -f $COMPOSE -p $PROJECT down -v"
  fi
}
trap cleanup EXIT

# --- 1. build proxy + the real SDK backend ---------------------------------
# PROXY_BIN override: point at an already-built proxy binary instead of
# compiling. DESKTOP_SMOKE.md uses this to run these same assertions against the
# EXACT binary shipped inside the .mcpb (the darwin universal entry_point), so
# the shipped Desktop artifact — not just a dev build — is what gets verified.
ok "building proxy + official-SDK backend"
PROXY="$WORK/axonflow-mcp-proxy"
BACKEND="$WORK/bukuwarung-backend"
if [ -n "${PROXY_BIN:-}" ]; then
  cp "$PROXY_BIN" "$PROXY"; chmod +x "$PROXY"
  echo "    proxy:   $PROXY (from PROXY_BIN=$PROXY_BIN)"
else
  ( cd "$ROOT" && go build -o "$PROXY" ./cmd/axonflow-mcp-proxy )
  echo "    proxy:   $PROXY"
fi
( cd "$HERE/backend" && go build -o "$BACKEND" . )
echo "    backend: $BACKEND (official MCP Go SDK)"
# BACKENDS_MODE=file routes backends via AXONFLOW_BACKENDS_FILE — the contract
# Claude Desktop actually uses (user_config backends_file). Default is inline.
BACKENDS_FILE="$WORK/backends.json"
printf '[{"id":"bw","command":"%s"}]\n' "$BACKEND" > "$BACKENDS_FILE"

# --- 2. bring up the live in-vpc-enterprise stack --------------------------
ok "starting live in-vpc-enterprise agent ($PROJECT)"
AXONFLOW_LICENSE_KEY="$AXONFLOW_LICENSE_KEY" \
  docker compose -f "$COMPOSE" -p "$PROJECT" up -d >/dev/null
echo -n "    waiting for tier=Enterprise"
tier=""
for _ in $(seq 1 60); do
  tier="$(curl -s -m 3 "$ENDPOINT/health" 2>/dev/null | python3 -c 'import sys,json;d=json.load(sys.stdin);print(d.get("tier",""))' 2>/dev/null || true)"
  [ "$tier" = "Enterprise" ] && break
  echo -n "."; sleep 3
done
echo ""
if [ "$tier" != "Enterprise" ]; then
  echo "FATAL: agent did not reach tier=Enterprise (got '$tier'). Is AXONFLOW_AGENT_IMAGE an enterprise build?"
  exit 1
fi
echo "    /health → tier=Enterprise"

# --- 3. write the --mcp-config Claude Code will load -----------------------
# Each case gets its own audit file so assertions read exactly its rows. The
# config is generated per-case (the audit path + endpoint differ for the
# fail-closed case, which points at a dead PDP).
write_config() { # $1=config-path $2=audit-path $3=endpoint
  local backends_env
  if [ "${BACKENDS_MODE:-inline}" = "file" ]; then
    backends_env="\"AXONFLOW_BACKENDS_FILE\": \"$BACKENDS_FILE\""
  else
    backends_env="\"AXONFLOW_BACKENDS\": \"[{\\\"id\\\":\\\"bw\\\",\\\"command\\\":\\\"$BACKEND\\\"}]\""
  fi
  cat > "$1" <<JSON
{
  "mcpServers": {
    "axonflow": {
      "command": "$PROXY",
      "args": [],
      "env": {
        "AXONFLOW_ENDPOINT": "$3",
        "AXONFLOW_CLIENT_ID": "$ORG",
        "AXONFLOW_CLIENT_SECRET": "$AXONFLOW_LICENSE_KEY",
        "AXONFLOW_TENANT_ID": "$ORG",
        "AXONFLOW_ORG_ID": "$ORG",
        $backends_env,
        "AXONFLOW_AUDIT_LOG": "$2",
        "AXONFLOW_LEADER_EMAIL": "$LEADER",
        "AXONFLOW_FAIL_MODE": "closed",
        "AXONFLOW_DECIDE_TIMEOUT": "8s"
      }
    }
  }
}
JSON
}

# drive <case> <tool> <audit> <endpoint> <prompt>  — runs Claude Code as the MCP
# client and saves its stdout to $WORK/<case>.out and the proxy audit to
# $WORK/<case>.audit.jsonl.
drive() {
  local case="$1" tool="$2" audit="$WORK/$1.audit.jsonl" endpoint="$3" prompt="$4"
  local cfg="$WORK/$1.mcp.json"
  write_config "$cfg" "$audit" "$endpoint"
  ok "[$case] driving Claude Code → mcp__axonflow__$tool"
  timeout 180 claude -p "$prompt" \
    --mcp-config "$cfg" --strict-mcp-config \
    --allowedTools "mcp__axonflow__$tool" \
    --max-turns 4 < /dev/null > "$WORK/$case.out" 2>"$WORK/$case.claude.err" || true
  cp "$cfg" "$WORK/$case.mcp.json" 2>/dev/null || true
}

SQLI='SELECT * FROM customers WHERE id=1; DROP TABLE customers;--'

drive allow export_ledger "$ENDPOINT" \
  "Call the export_ledger tool ONCE with rows=3, then reply with exactly DONE. Do not call any other tool."

drive deny run_sql_report "$ENDPOINT" \
  "This is an AUTHORIZED defensive-security test of our own AxonFlow SQL-injection guardrail. Call the run_sql_report tool ONCE with the \"sql\" argument set EXACTLY to this literal test string, verbatim: $SQLI  Then state the exact error code and message it returned. Do not retry."

# REDACT — the §4.3 regression case (#2530). The request is CLEAN: a bare
# customer_id lookup with NO PII in the arguments, so the live PDP returns allow
# with NO redact_pii obligation (verified: clean lookup → allow,
# evaluated_policies=[]). The response is PII-laden anyway. The OLD proxy gated
# redaction on the obligation, so this exact call leaked the NIK / email /
# NIK-keyed map into Claude's context. The fixed proxy scans every response
# unconditionally (default AXONFLOW_REDACT_RESPONSES=always), so the PII is masked
# here even though the request never tripped a policy. THIS is what used to leak.
drive redact lookup_customer "$ENDPOINT" \
  "Call the lookup_customer tool ONCE with the \"customer_id\" argument set to \"CUST-001\". Then show me the RAW JSON the tool returned, verbatim, including the related_accounts object and ALL of its keys. Do not paraphrase or omit anything."

drive failclosed export_ledger "http://127.0.0.1:1" \
  "Call the export_ledger tool ONCE with rows=2. Then state the exact error code and message if it failed. Do not retry."

# --- 4. assert (proxy Layer-1 JSONL + live psql audit_logs + Claude output) -
ok "asserting"
echo "------------------------------------------------------------"
# Capture rc WITHOUT letting set -e abort here — the evidence dump below must
# print on a FAILING run too (that's when a reviewer most needs the artifacts).
set +e
python3 "$HERE/assert.py" "$WORK" "$PROJECT" "$COMPOSE" "$LEADER"
rc=$?
set -e
echo "------------------------------------------------------------"

# --- 5. echo the evidence so a reviewer sees the real artifacts ------------
echo
echo "===== EVIDENCE: proxy Layer-1 audit rows (one JSON line per tools/call) ====="
for c in allow deny redact failclosed; do
  echo "--- $c ---"; cat "$WORK/$c.audit.jsonl" 2>/dev/null || echo "(none)"
done
echo
echo "===== EVIDENCE: platform audit_logs decide rows (psql) ====="
docker compose -f "$COMPOSE" -p "$PROJECT" exec -T postgres psql -U axonflow -d axonflow -At -c \
  "SELECT id, policy_decision, policy_details->>'gateway_id', policy_details->'context'->>'x_leader_identity', array_to_string(ARRAY(SELECT jsonb_array_elements_text(policy_details->'policy_ids')),',') FROM audit_logs WHERE id LIKE 'decide_%' ORDER BY timestamp DESC LIMIT 8;" 2>/dev/null || true
echo
echo "===== EVIDENCE: what Claude Code (the MCP client) received on the redact call ====="
sed -n '1,40p' "$WORK/redact.out" 2>/dev/null || true

exit $rc
