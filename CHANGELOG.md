# Changelog

All notable changes to the AxonFlow Governance Claude Desktop extension are
documented here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- **Response PII redaction is now unconditional (the §4.3 control).** The proxy
  previously redacted a tool response **only** when the request tripped a
  `redact_pii` obligation. A clean request (e.g. `lookup_customer
  {customer_id:"CUST-001"}`) returns `allow` with no obligation, so its PII-laden
  response — NIK, email, `+62` phone, NIK-keyed map — was forwarded to Claude
  **raw**. Since the agent never sees the response, stripping PII out of it is
  unconditionally the proxy's job: the proxy now scans **every** tool response by
  default. Verified live against in-vpc-enterprise (#2530).

### Added
- **`AXONFLOW_REDACT_RESPONSES`** config knob: `always` (default — scan every
  response), `on-obligation` (legacy: scan only on a `redact_pii` obligation or a
  fail-open forward), `off` (explicit opt-out). An unknown value is rejected at
  boot, never silently ignored.
- **Deterministic governance matrix** (`runtime-e2e/cli-harness/matrix.sh` +
  `matrix_gen.py` + `matrix_assert.py`) — drives the real proxy + real SDK
  backend + live in-vpc-enterprise PDP through a deterministic MCP client over 16
  core cases + fail-closed + tenant-isolation, every governance behaviour
  exercised with its trigger **present and absent**. A **universal PII-leak
  detector** runs on every case's response-to-Claude (not just the redact ones),
  plus a **negative control** that reproduces the old leak under the legacy mode
  to prove the detector is not vacuous.
- Backend (`runtime-e2e/cli-harness/backend`) gained `get_sales_summary`,
  `get_bank_details`, `list_contacts`, `run_command`; `lookup_customer` now takes
  a clean `customer_id` (the response-only redaction case) instead of requiring an
  Aadhaar in the request — the schema that structurally hid the §4.3 leak.

## [0.1.0] - 2026-06-06

First release. The AxonFlow MCP governance proxy as a one-click `.mcpb` Claude
Desktop Extension.

### Fixed
- **Enterprise PDP authentication.** The proxy now authenticates to
  `POST /api/v1/decide` with HTTP **Basic auth** (`base64(clientID:clientSecret)`),
  matching the canonical Decision Mode client. It previously sent custom
  `X-Client-Id` / `X-Client-Secret` headers, which the agent ignores in
  enterprise / **in-vpc-enterprise** mode (BukuWarung's deployment mode) — so
  every decide call returned `401` and the proxy fail-closed-denied *every* tool
  call. `clientID` must be the license's org id; `clientSecret` is the Enterprise
  license key. Community mode (no secret) sends no auth header, unchanged.
  Surfaced by the #2528 CLI harness against a live in-vpc-enterprise agent.

### Added
- **CLI-harness runtime-e2e** (`runtime-e2e/cli-harness/`) — drives the real
  proxy with **Claude Code as a real MCP client** (`--mcp-config
  --strict-mcp-config`) in front of a **real backend MCP server built on the
  official MCP Go SDK**, against a **live in-vpc-enterprise** agent. Asserts
  allow / deny (`-32001`) / redact (incl. a NIK-keyed map, the §4.3 key
  redaction) / fail-closed (`-32003`), each cross-checked against the proxy's
  Layer-1 JSONL **and** the platform `audit_logs` DB row (`gateway_id`,
  `x_leader_identity`) correlated by `decision_id`. `DESKTOP_SMOKE.md` adds a
  shipped-`.mcpb`-binary launch-contract check plus the manual GUI runbook.
- **AxonFlow MCP governance proxy** (`cmd/axonflow-mcp-proxy`) — a stdio MCP
  server that Claude Desktop launches via a `.mcpb` Desktop Extension. It fronts
  one or more backend MCP servers, aggregates and re-exposes their tools, and
  governs every `tools/call`:
  - calls AxonFlow Decision Mode (`POST /api/v1/decide`) before forwarding;
  - maps verdicts allow → forward, deny → `-32001`, needs_approval → `-32002`;
  - **fails closed by default** (PDP unreachable → block); opt-in fail-open;
  - applies the `redact_pii` obligation to tool responses, masking PII before it
    reaches Claude's context;
  - writes a Layer-1 audit row per call (`session_id`, `leader_email`,
    `tool_name`, `parameters_hash`, `response_record_count`, `duration_ms`,
    `decision_id`, `trace_id`, `gateway_id=claude_desktop.*`).
- **Backend transports**: stdio (the proxy launches the backend) and http, each
  bounded by a per-call timeout (`AXONFLOW_BACKEND_TIMEOUT`, default 30s) so a
  hung backend can't wedge a tool call.
- Redaction masks PII in string and numeric **values** and in object **keys**
  (a record keyed by a NIK can't leak the key), and runs unconditionally on a
  fail-open forward. Known limits (array-split / base64-encoded PII) are stated
  in `redact.go` and the README "Scope & boundaries".
- **Aggregation** with `<id>__<tool>` namespacing for multiple backends;
  unprefixed pass-through for the single-backend (per-server) mode.
- **`.mcpb` packaging** (`manifest.json` + `build.sh`) producing multi-arch
  binaries: macOS universal (arm64 + amd64), Linux amd64 + arm64, Windows amd64.
- **runtime-e2e** harness asserting allow / deny / redact / fail-closed against a
  live AxonFlow agent with real Layer-1 audit rows.
- Unit tests (≥80% coverage) for verdict mapping, aggregation/routing,
  fail-closed posture, PII redaction, audit schema, and both backend transports.

[Unreleased]: https://github.com/getaxonflow/axonflow-claude-desktop-plugin/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/getaxonflow/axonflow-claude-desktop-plugin/releases/tag/v0.1.0
