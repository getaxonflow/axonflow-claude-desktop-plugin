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
| **deny** | `run_sql_report` with a stacked `DROP TABLE` → JSON-RPC `-32001`; backend never reached; SQLi drop policy in both proxy + DB |
| **redact** | `lookup_customer` with a **clean `customer_id`** (NO PII in the request) → `allow` with **NO** `redact_pii` obligation; the response's NIK / email / phone **and the NIK-keyed `related_accounts` KEY** come back `[REDACTED:*]` anyway. This is the **#2530 regression case**: the old proxy gated redaction on the obligation, so this exact clean-request call leaked PII into Claude's context. The fixed proxy scans every response unconditionally. |
| **fail-closed** | PDP unreachable → JSON-RPC `-32003`, blocked |

A **universal PII-leak detector** runs on **every** case's response-to-Claude (not just the redact one) — a leak in a case that wasn't looking is exactly how the §4.3 hole hid.

## The deterministic matrix (`matrix.sh`)

`run.sh` proves the chain through a real LLM client on a happy path. `matrix.sh`
drives the **same** real proxy + real SDK backend + live in-vpc-enterprise PDP
through a **deterministic** MCP client (exact JSON-RPC over stdio), so every
governance behaviour is exercised with its trigger **present *and* absent** — the
discipline that was missing when the §4.3 response-only leak survived 30/0
(#2530). An LLM client can't be trusted to emit an exact `DELETE` string or a
foreign tenant id on demand; this harness can.

16 core cases + fail-closed + tenant-isolation + a negative control:

- **allow** (neither): `export_ledger`, `get_sales_summary`
- **redact, response-only** (the fix): `lookup_customer(customer_id)`, `get_bank_details`, `list_contacts` (array/nested)
- **redact, both**: `lookup_customer(customer_id + aadhaar)`
- **request-only PII**: `export_ledger(aadhaar arg)` — obligation fires, response is clean, no false redaction
- **deny (system policies)**: DROP, UNION, OR-true, injection-override, injection-reveal, dangerous-command
- **deny (BukuWarung bundle read-only)**: DELETE, UPDATE, INSERT — blocked by `buku_org_readonly_write_block`
- **fail-closed**: dead PDP → `-32003`
- **tenant-isolation**: a foreign tenant id → PDP `403` (tenant mismatch) → blocked, backend untouched
- **negative control**: the clean-request lookup driven with the legacy
  `AXONFLOW_REDACT_RESPONSES=on-obligation` mode — it **must** leak, proving the
  universal detector is not vacuous *and* reproducing the old bug.

```bash
export AXONFLOW_LICENSE_KEY="$(cat bukuwarung.license)"
./matrix.sh                                            # builds, boots/reuses stack, seeds bundle, asserts
COMPOSE_PROJECT=cd-live AXONFLOW_ENDPOINT=http://localhost:8080 KEEP_STACK=1 ./matrix.sh  # reuse a running stack
```

`matrix.sh` requires the BukuWarung policy bundle SQL (the DELETE/UPDATE/INSERT
read-only cases need it; default path is a sibling `axonflow-enterprise` checkout,
override with `AXONFLOW_BUNDLE_SQL`). It also **neutralises the agent's anti-abuse
circuit breaker** for the test org (the matrix generates 9 denies per run, which
would trip the per-client 5-violations-in-5-min breaker and turn later calls into
fail-closed 503s). The breaker is an agent feature orthogonal to the proxy
behaviour under test; the harness raises only the test org's violation threshold
and clears stale circuit state — it never weakens a governance verdict.

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
  `export_ledger` / `get_sales_summary` (allow, no PII), `lookup_customer`
  (PII + a NIK-keyed map → redact; takes a **clean `customer_id`** so the
  response-only path is exercised), `get_bank_details` / `list_contacts` (more
  redact shapes), `run_sql_report` / `run_command` (deny paths; never reached
  when blocked).
- `docker-compose.yml` — postgres + a live **in-vpc-enterprise** agent.
- `run.sh` — builds, boots, drives Claude Code as the MCP client, asserts.
- `assert.py` — cross-checks Claude output + proxy JSONL + live `psql` audit_logs,
  with the universal leak detector on every case.
- `matrix.sh` + `matrix_gen.py` + `matrix_assert.py` — the deterministic ≥15-case
  governance matrix (above).
- `DESKTOP_SMOKE.md` — verifying the shipped `.mcpb` binary under Claude Desktop's
  launch contract (`PROXY_BIN` + `BACKENDS_MODE=file`) **and** the manual GUI
  install runbook.

## No mocks

Every verdict is a real decision from the live PDP; the proxy is the real built
binary; the backend is a real SDK MCP server; the client is real Claude Code. If
Claude fails to make the expected call, the per-case audit file is empty and the
assertion fails loudly — there is no path to a green run without a real call
reaching the real PDP.
