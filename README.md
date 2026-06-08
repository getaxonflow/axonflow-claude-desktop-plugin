# AxonFlow Governance for Claude Desktop

Runtime governance for **Claude Desktop** at the MCP layer: an AxonFlow MCP
proxy, packaged as a one-click `.mcpb` Desktop Extension, that fronts your
internal MCP servers and enforces policy on every tool call — **block**
policy-violating calls, **redact** PII from responses before it reaches the
conversation, and **audit** everything.

> Source-available (MIT). Self-hosted: tool calls are evaluated by *your*
> AxonFlow deployment — no data leaves your infrastructure.

## Quickstart

```text
1. Build the extension:        ./build.sh        →  build/axonflow-governance-<v>.mcpb
2. Claude Desktop → Settings → Extensions → Install from file → pick the .mcpb
3. Fill the config fields:      AxonFlow endpoint, Client ID/secret, Tenant,
                                Fail mode (keep "closed"), Backend servers file
4. Point "Backend MCP servers" at a JSON file (see config.example.json)
5. Restart Claude Desktop. Your backend tools now appear — governed.
```

That's it. Every `tools/call` is now checked against AxonFlow Decision Mode
before it runs.

## Why a proxy, not a hook

Claude **Desktop has no PreToolUse/PostToolUse hooks** — those are a Claude
**Code** feature. On Desktop the only pre-execution interception point is the
**MCP layer**. So enforcement cannot be a hook; it is this proxy, which sits
between Claude Desktop and your backend MCP servers:

```
Claude Desktop ──stdio MCP──▶ AxonFlow proxy ──POST /api/v1/decide──▶ AxonFlow (PDP)
                                   │  allow → forward, redact response
                                   │  deny  → block (-32001)
                                   ▼
                            backend MCP servers (CRM / BigQuery / back-office)
```

The proxy is **both** an MCP server (to Claude Desktop) and an MCP client (to
each backend). It aggregates the backends' tools and re-exposes them as one
extension.

## What it enforces

| On every `tools/call` | Behaviour |
|---|---|
| **allow** | forwarded to the backend unchanged |
| **deny** | blocked with JSON-RPC `-32001`; the deny reason + `decision_id`/`trace_id` surface to the user; the backend is never called |
| **needs_approval** | held with `-32002` (HITL); not forwarded |
| **redact_pii obligation** | the backend's response is scanned and PII masked (`[REDACTED:*]`) before it reaches Claude's context — the cross-border-data control |
| **PDP unreachable** | **fail-closed by default** (`-32003`): the call is blocked. Opt into fail-open only with eyes open. |

Every call writes one **Layer-1 audit row** (`session_id`, `leader_email`,
`tool_name`, `parameters_hash`, `response_record_count`, `duration_ms`, plus
`decision_id` / `trace_id` / `gateway_id` for SIEM correlation).

## Configuration

Configured entirely through the Desktop Extension UI, which maps to these
environment variables (see `manifest.json`):

| Field | Env var | Notes |
|---|---|---|
| AxonFlow endpoint | `AXONFLOW_ENDPOINT` | e.g. `https://app.getaxonflow.com:8090` |
| Client ID / secret | `AXONFLOW_CLIENT_ID` / `AXONFLOW_CLIENT_SECRET` | secret is masked + stored securely |
| User token (JWT) | `AXONFLOW_USER_TOKEN` | optional; enterprise validated-user audit |
| Tenant / Org | `AXONFLOW_TENANT_ID` / `AXONFLOW_ORG_ID` | |
| Fail mode | `AXONFLOW_FAIL_MODE` | `closed` (default) or `open` |
| Leader email | `AXONFLOW_LEADER_EMAIL` | stamped on audit rows |
| Backend servers file | `AXONFLOW_BACKENDS_FILE` | JSON map — see `config.example.json` |
| Audit log path | `AXONFLOW_AUDIT_LOG` | optional JSONL sink |

### Backend map

Each backend is fronted over **stdio** (the proxy launches it: `command` +
`args` + `env`) or **http** (`url`). With more than one backend, tool names are
namespaced `<id>__<tool>` to avoid collisions; with a single backend, names pass
through unchanged. See [`config.example.json`](./config.example.json).

## Aggregation vs. per-server

The proxy ships as an **aggregator** (one extension fronts N backends — the
recommended mode). The aggregation contract (initialize → `tools/list` →
`tools/call` routing across backends) is validated end-to-end in
[`runtime-e2e/`](./runtime-e2e). If you prefer **one proxy per backend** (e.g.
to isolate a high-risk server), run the same binary with a single-backend config
— no code change; tool names are then unprefixed. The choice is config, not a
rebuild.

## Scope & boundaries (be honest with your Risk Committee)

- AxonFlow on a **Team** plan governs the **MCP/tool surface** — which is where
  the data-exfiltration and tool-action risk lives.
- Plain **chat** content (no MCP) is **not** interceptable without Anthropic's
  **Enterprise Compliance API**. This proxy does not claim otherwise.
- The redaction patterns here are a defense-in-depth **mirror** of AxonFlow's
  platform PII detectors — a regex filter, **not a complete DLP engine**. It
  masks PII in string and numeric **values** and in object **keys**, at any
  depth. It does **not** catch PII split across separate JSON array elements
  (`["3174","0125",…]`), nor base64/hex-encoded PII. The platform (PDP) at the
  gate remains the authoritative detector; block-at-the-gate (or a backend that
  never emits the data) is the fix for those gaps, not this last-line filter.
- HTTP backends speak MCP Streamable HTTP: the proxy accepts both
  `application/json` and `text/event-stream` responses (sending an `Accept`
  header that covers both, so spec-compliant servers don't reject with 406).
- If a backend MCP server dies **mid-session**, calls routed to it fail with a
  "backend connection closed" error (the other backends keep working), and its
  tools may still appear in the (cached) tool list until the proxy restarts. The
  proxy does **not** auto-respawn a dead backend within a session — restart the
  backend, or Claude Desktop, to restore it. (Backends down at *startup* are
  skipped cleanly and never exposed.)

## Build & test

```bash
go test ./cmd/... -cover          # unit tests
./build.sh                        # multi-arch .mcpb (darwin universal, linux amd64/arm64, win amd64)
cd runtime-e2e && docker compose up -d && ./run.sh   # live end-to-end
```

## Repository layout

```
cmd/axonflow-mcp-proxy/   the proxy (stdio MCP server + aggregation + decide enforcement + redaction + audit)
manifest.json             .mcpb Desktop Extension manifest
build.sh                  multi-arch build + .mcpb packaging
config.example.json       backend-map example
runtime-e2e/              live end-to-end test (proxy + stub backend + real AxonFlow agent)
```

## License

MIT — see [LICENSE](./LICENSE).
