# Changelog

All notable changes to the AxonFlow Governance Claude Desktop extension are
documented here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] - 2026-06-09

### Changed
- **Response PII redaction now runs through AxonFlow's authoritative engine
  (`POST /api/v1/mcp/check-output`) instead of a local regex.** The proxy
  submits each allowed backend response to the engine (HTTP Basic auth, the same
  credentials as the decide call) and forwards the engine's redacted text, so
  redaction coverage now tracks the platform's detectors (NIK + SSN + email +
  phone …, #2565) and improves with the platform — with no proxy change. The
  divergent hand-rolled redactor (`redact.go`, a regex subset that missed
  whole categories such as US SSN) is **deleted**. (#2563)

### Security
- **The response plane is now unconditionally fail-CLOSED.** Because redaction is
  a network call, an unreachable/erroring engine means the (already-executed)
  response is **not forwarded** — a network hiccup can never leak un-redacted PII
  into Claude's context. This holds even under request-plane fail-open
  (`AXONFLOW_FAIL_MODE=open`). The deleted local redactor used to "redact" even
  with the PDP down, which masked this failure mode. An engine hard-block on a
  response (critical-PII deny / response SQLi / exfiltration) surfaces as a deny
  (`-32001`); engine-unavailable surfaces as `-32003`.

## [0.1.3] - 2026-06-09

### Fixed
- **Stateful HTTP backend MCP servers no longer fail with `400` after a `200`
  initialize.** The MCP Streamable HTTP spec lets a server run stateful: it
  returns an `Mcp-Session-Id` header on the `initialize` response and then
  rejects any later request that doesn't echo it with **`400 Bad Request`**
  ("No valid session ID provided"). The official MCP SDK does this by default.
  The proxy treated HTTP backends as stateless — it never captured or replayed
  the session id — so `initialize` succeeded (200) but `tools/list` was
  rejected (400), the backend was skipped, and **0 tools** were exposed (Claude
  Desktop showed the extension enabled but with no tools). The proxy now
  captures `Mcp-Session-Id` from the `initialize` response, replays it on every
  subsequent request, and sends the `notifications/initialized` lifecycle
  notification (matching the stdio backend). Stateless backends omit the header
  and are unaffected. Follow-on to the v0.1.2 `406` fix.

## [0.1.2] - 2026-06-09

### Fixed
- **HTTP backends with spec-compliant MCP servers no longer fail with `406 Not
  Acceptable`.** The proxy sent `Accept: application/json` to HTTP backend MCP
  servers, but the MCP Streamable HTTP spec requires the client to accept
  `text/event-stream` too — so a strict server (the official MCP SDK transport)
  returned **406 Not Acceptable**, the backend's `initialize`/`tools/list`
  failed, the backend was skipped, and **zero tools were exposed**. In Claude
  Desktop that surfaced as the extension being installed + enabled but Claude
  seeing no tools ("never heard of it"). The proxy now sends
  `Accept: application/json, text/event-stream` and parses **both** an
  `application/json` single response and a `text/event-stream` SSE response
  (extracting the JSON-RPC message from the `data:` field). No configuration
  change needed; re-enable the extension after upgrading.
- Corrected a version drift: the proxy binary now reports its real version
  (`0.1.2`) instead of a stale `0.1.0`.

## [0.1.1] - 2026-06-06

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

[Unreleased]: https://github.com/getaxonflow/axonflow-claude-desktop-plugin/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/getaxonflow/axonflow-claude-desktop-plugin/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/getaxonflow/axonflow-claude-desktop-plugin/releases/tag/v0.1.0
