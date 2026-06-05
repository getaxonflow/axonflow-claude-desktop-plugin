# runtime-e2e — Claude Desktop governance proxy

End-to-end test that drives the **real** proxy (over stdio, exactly as Claude
Desktop launches it) in front of a **real** stub backend MCP server, against a
**live** AxonFlow Decision API. No mocked verdicts — every allow / deny / redact
assertion is a genuine PDP decision, and the audit checks read the proxy's
actual Layer-1 JSONL.

## What it asserts (issue #2520 acceptance criteria)

| # | Behaviour | How |
|---|-----------|-----|
| 1 | **allow** | a benign tool call (`export_ledger`) is forwarded to the backend |
| 2 | **deny** | a SQL-injection tool call is blocked with JSON-RPC `-32001`; the backend is never reached |
| 3 | **redact** | a request carrying RBI India PII (Aadhaar) returns a `redact_pii` obligation, and the backend's PII-bearing response (NIK + email + phone) is stripped — `[REDACTED:*]` tokens replace the values before they reach Claude's context |
| 4 | **fail-closed** | with the PDP unreachable the call is blocked (`-32003`), never forwarded |

Plus: `tools/list` aggregates the backend's tools, and exactly one Layer-1 audit
row is written per call carrying `session_id` / `leader_email` / `decision_id` /
`trace_id` / `gateway_id` (`claude_desktop.*`) and a non-zero `redaction_count`
on the redacted call.

## Run

```bash
docker compose up -d        # boots postgres + a live community agent (Decision Mode)
./run.sh                    # builds proxy + stub, runs all assertions
docker compose down -v
```

The agent is pinned to a deterministic posture in `docker-compose.yml`
(`SQLI_ACTION=block`, `PII_ACTION=redact`) so the deny/redact verdicts are
reproducible. Override the agent image with `AXONFLOW_AGENT_IMAGE=...` to run
against a freshly built tag.

## Components

- `stub-mcp-server/` — a minimal stdio MCP backend that returns PII-bearing
  records (`lookup_customer`) and a configurable-size record array
  (`export_ledger`), so redaction and `response_record_count` are observable.
- `run.sh` — builds the binaries, boots them, drives the JSON-RPC exchange, and
  parses the proxy's stdout + audit JSONL with inline Python assertions.

## Sample evidence

```
==> TEST 1: live allow / deny / redact
  ✅ tools/list aggregated backend tools: ['export_ledger', 'lookup_customer']
  ✅ allow: benign call forwarded (result, no error)
  ✅ deny: SQLi blocked with -32001 (got -32001)
  ✅ redact: NIK + email stripped from response
  ✅ redact: redaction tokens present in response
  ✅ audit: exactly one row recorded redactions (got 1)
==> TEST 2: fail-closed (PDP unreachable → blocked)
  ✅ fail-closed: blocked with -32003 (got -32003)
==> RESULT: 3 passed, 0 failed
```

The deny row records the blocking policy (`sys_sqli_stacked_drop`); the redact
row records `sys_pii_aadhaar` with `redaction_count: 3`.
