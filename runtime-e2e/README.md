# runtime-e2e — Claude Desktop governance proxy

End-to-end test that drives the **real** proxy (over stdio, exactly as Claude
Desktop launches it) in front of a **real** stub backend MCP server, against a
**live ENTERPRISE** AxonFlow agent authenticated with a **real Ed25519 license**.
No mocked verdicts **and no mocked redaction** — every allow / deny verdict is a
genuine PDP decision, and every redaction is performed by the platform's
**authoritative engine** (`POST /api/v1/mcp/check-output`). The proxy holds no
local redactor; this test proves the engine-backed path end-to-end (#2563).

Enterprise edition + a real license are **required**: the full PII coverage the
test asserts (NIK + SSN + email + phone, #2565) lives in the enterprise
detectors — a community agent would not redact SSN/NIK via check-output.

## What it asserts

| # | Behaviour | How |
|---|-----------|-----|
| 1 | **allow** | a benign tool call (`export_ledger`) is forwarded to the backend |
| 2 | **deny** | a SQL-injection tool call is blocked with JSON-RPC `-32001`; the backend is never reached |
| 3 | **redact** | a **clean** request (`lookup_customer {customer_id}` → allow, **no** obligation) whose response carries **NIK + SSN + email + phone** has all four masked by the engine before the response reaches Claude's context — the §4.3 control. (Redaction is gated on the *response*, never on a request-side flag.) |
| 4 | **fail-closed** | with the PDP/engine unreachable the call is blocked (`-32003`), never forwarded |
| 5 | **demo creds refused** | a bogus license is rejected (`-32003`); the backend is never reached and no PII is forwarded |

Plus: `tools/list` aggregates the backend's tools, and exactly one Layer-1 audit
row is written per call carrying `session_id` / `leader_email` / `decision_id` /
`trace_id` / `gateway_id` (`claude_desktop.*`), with `redaction_count > 0` on the
redacted call.

## Run

```bash
# 1) Build an ENTERPRISE agent image from the enterprise repo:
#    docker build --build-arg EDITION=enterprise \
#      -f platform/agent/Dockerfile -t axonflow-agent:enterprise-local .
# 2) Mint a real Enterprise license (scripts/setup-e2e-testing.sh enterprise,
#    or ee/platform/agent/license/cmd/keygen) for some org id.

export AXONFLOW_AGENT_IMAGE=axonflow-agent:enterprise-local
export AXONFLOW_LICENSE_KEY="AXON-…"      # real Ed25519 Enterprise license
export AXONFLOW_ORG_ID="desktop-e2e"      # the license's org id (Basic-auth user)

docker compose up -d        # boots postgres + the live enterprise agent
./run.sh                    # builds proxy + stub, runs all assertions
docker compose down -v
```

`run.sh` **refuses to run without a real license** (`AXONFLOW_LICENSE_KEY` /
`AXONFLOW_ORG_ID`) and rejects obvious placeholders — there are no demo creds in
this harness. The agent posture is pinned in `docker-compose.yml`
(`AXONFLOW_EDITION=enterprise`, `DEPLOYMENT_MODE=in-vpc-enterprise`,
`SQLI_ACTION=block`, `PII_ACTION=redact`) so the verdicts are reproducible.

## Components

- `stub-mcp-server/` — a minimal stdio MCP backend that returns a PII-bearing
  record (`lookup_customer` → NIK + SSN + email + phone) and a configurable-size
  record array (`export_ledger`), so redaction and `response_record_count` are
  observable.
- `run.sh` — builds the binaries, drives the JSON-RPC exchange under enterprise
  Basic auth, and parses the proxy's stdout + audit JSONL with inline Python
  assertions.

## Sample evidence (against a live enterprise agent, real license)

```
==> TEST 1: live allow / deny / engine-backed redact (NIK+SSN+email+phone)
  ✅ tools/list aggregated backend tools: ['export_ledger', 'lookup_customer']
  ✅ allow: benign call forwarded (result, no error)
  ✅ deny: SQLi blocked with -32001 (got -32001)
  ✅ redact: clean request allowed (no obligation)
  ✅ redact: NIK (3174012509900001) stripped from response
  ✅ redact: email (budi.santoso@example.co.id) stripped from response
  ✅ redact: phone (+6281234567890) stripped from response
  ✅ redact: SSN (123-45-6789) stripped from response
  ✅ redact: forwarded response is a valid non-empty MCP result
  ✅ audit: exactly one row recorded redactions (got 1)
==> TEST 2: fail-closed (PDP/engine unreachable → blocked)
  ✅ fail-closed: blocked with -32003 (got -32003)
==> TEST 3: demo creds refused (bogus license → blocked, no PII forwarded)
  ✅ demo-creds: blocked with -32003 (got -32003)
  ✅ demo-creds: no PII forwarded under refused creds
==> RESULT: 4 passed, 0 failed
```

The engine masks each value in place (partial mask, e.g. `31**********0001` /
`1*********9`), so the assertions check that the **raw** PII values are absent —
not for a specific token shape. The redact row's `evaluated_policies` is empty
(the *request* was clean); redaction was driven entirely on the response side by
`check-output` (`sys_pii_ssn` / `sys_pii_email` + the Indonesia NIK/+62 detector).
