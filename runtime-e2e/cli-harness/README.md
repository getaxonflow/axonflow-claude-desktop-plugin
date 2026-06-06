# CLI-harness runtime-e2e — Claude Code as a real MCP client

This harness drives the **real** AxonFlow governance proxy with a **real MCP
client** — Claude Code, pointed at the proxy via `claude --mcp-config
--strict-mcp-config` — in front of a **real backend MCP server** (built on the
official MCP Go SDK), against a **live in-vpc-enterprise** AxonFlow agent
(Decision Mode). No mocked verdicts, no fixtures, no stub.

It is the CLI-based plugin-E2E methodology (the rigor used for the other AxonFlow
plugins) applied to the Desktop proxy, and it deliberately **exceeds** the
sibling `../` runtime-e2e on three axes:

| | `../` (issue #2520 baseline) | this harness (#2528) |
|---|---|---|
| MCP client | hand-fed JSON-RPC over a pipe | **Claude Code** (`--mcp-config --strict-mcp-config`) |
| backend | hand-rolled JSON-RPC stub | **official MCP Go SDK** server (`backend/`) |
| PDP | community agent (no auth) | **in-vpc-enterprise** + Enterprise license (HTTP Basic auth) |

## What it proves (each assertion backed by paste-evidence)

For every case the harness cross-checks three independent records: what **Claude
Code** (the client) received, the **proxy's Layer-1 audit JSONL**, and the
**platform `audit_logs` DB row** (queried live via `psql`), correlated by
`decision_id`.

| Case | Behaviour |
|---|---|
| **allow** | benign `export_ledger` forwarded; 3 records; DB row `allow` + `gateway_id=claude_desktop.*` + leader |
| **deny** | `run_sql_report` with a stacked `DROP TABLE` → JSON-RPC `-32001`; backend never reached; policy `sys_sqli_drop_table` in both proxy + DB |
| **redact** | `lookup_customer` with an Aadhaar → `allow` + `redact_pii` (`sys_pii_aadhaar`); the response's NIK / email / phone **and the NIK-keyed `related_accounts` KEY** come back `[REDACTED:*]` (the §4.3 key-redaction fix); real NIK/email never reach Claude's context |
| **fail-closed** | PDP unreachable → JSON-RPC `-32003`, blocked |

## Run

```bash
# Build an EDITION=enterprise agent image at/after #2526 from the axonflow-enterprise repo:
#   docker build -f platform/agent/Dockerfile --build-arg EDITION=enterprise -t axonflow-agent:sh-e2e .
# Generate an Enterprise license (org must match AXONFLOW_ORG_ID, default "bukuwarung"):
#   AXONFLOW_ENT_SIGNING_KEY=... keygen -tier Enterprise -org bukuwarung -days 365 -quiet > bukuwarung.license

export AXONFLOW_AGENT_IMAGE=axonflow-agent:sh-e2e
export AXONFLOW_LICENSE_KEY="$(cat bukuwarung.license)"
./run.sh                 # builds, boots the stack, drives Claude Code, asserts, tears down
KEEP_STACK=1 ./run.sh    # leave the stack up for inspection
```

`run.sh` requires `docker`, the `claude` CLI (logged in), and an Enterprise
license. It boots postgres + the agent (`docker-compose.yml`), waits for
`/health` → `tier: Enterprise`, then runs the four cases and prints
`RESULT: N passed, 0 failed`.

## Components

- `backend/` — a real BukuWarung-shaped MCP server on the **official MCP Go SDK**
  (separate Go module so the proxy's zero-dependency `go.mod` stays clean). Tools:
  `export_ledger` (allow), `lookup_customer` (PII + a NIK-keyed map → redact),
  `run_sql_report` (deny path; never reached when the SQL is blocked).
- `docker-compose.yml` — postgres + a live **in-vpc-enterprise** agent.
- `run.sh` — builds, boots, drives Claude Code as the MCP client, asserts.
- `assert.py` — cross-checks Claude output + proxy JSONL + live `psql` audit_logs.
- `DESKTOP_SMOKE.md` — verifying the shipped `.mcpb` binary under Claude Desktop's
  launch contract (`PROXY_BIN` + `BACKENDS_MODE=file`) **and** the manual GUI
  install runbook.

## No mocks

Every verdict is a real decision from the live PDP; the proxy is the real built
binary; the backend is a real SDK MCP server; the client is real Claude Code. If
Claude fails to make the expected call, the per-case audit file is empty and the
assertion fails loudly — there is no path to a green run without a real call
reaching the real PDP.
