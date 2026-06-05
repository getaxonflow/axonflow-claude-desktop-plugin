# Changelog

All notable changes to the AxonFlow Governance Claude Desktop extension are
documented here. The format follows [Keep a Changelog](https://keepachangelog.com/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
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

[Unreleased]: https://github.com/getaxonflow/axonflow-claude-desktop-plugin
