# Real Claude Desktop install smoke

This is the **manual** half of the #2528 Desktop verification: install the actual
`.mcpb` through Claude Desktop's GUI and confirm it loads, governs tool calls
through the proxy, and surfaces a deny in the conversation.

Two layers of evidence:

1. **Automated (Desktop launch-contract).** `run.sh` can run the full 30-assertion
   suite against the **exact binary shipped inside the `.mcpb`** (the darwin
   universal `entry_point`), wired with the **exact env Claude Desktop derives
   from the manifest `user_config`** (including the `backends_file` contract).
   This proves the shipped artifact + manifest contract govern correctly without
   needing the GUI:

   ```bash
   cd ../..                                   # repo root
   ./build.sh                                 # builds build/axonflow-governance-<v>.mcpb
   rm -rf /tmp/cdp-ext && unzip -q build/axonflow-governance-*.mcpb -d /tmp/cdp-ext

   cd runtime-e2e/cli-harness
   export AXONFLOW_LICENSE_KEY="$(cat /path/to/bukuwarung.license)"
   export AXONFLOW_AGENT_IMAGE=axonflow-agent:sh-e2e   # enterprise build >= #2526
   PROXY_BIN=/tmp/cdp-ext/server/axonflow-mcp-proxy-darwin \
     BACKENDS_MODE=file ./run.sh
   # → RESULT: 30 passed, 0 failed
   ```

2. **Manual (GUI).** The steps below install the `.mcpb` via Settings → Extensions
   and capture screenshots. This is the only part that needs a human at an
   **unlocked** screen — Claude Desktop is a GUI app and its Extensions installer
   + chat cannot be driven from a locked session. (In the S-H autonomous run the
   machine was locked, so layer-1 above was used as the substitute and these GUI
   screenshots are left for the operator.)

## Prerequisites

- The live in-vpc-enterprise stack is up (`KEEP_STACK=1 ./run.sh`, or
  `docker compose -f docker-compose.yml -p sh-e2e-cli up -d` with
  `AXONFLOW_LICENSE_KEY` set) → `curl localhost:8080/health` shows `tier: Enterprise`.
- The real backend is built and on disk: `cd backend && go build -o /tmp/bw-backend .`
- A backends file the extension will point at:
  `echo '[{"id":"bw","command":"/tmp/bw-backend"}]' > /tmp/cdp-backends.json`
- `build/axonflow-governance-<version>.mcpb` built (`./build.sh`).

## Steps (capture a screenshot at each ★)

1. Open Claude Desktop → **Settings → Extensions**.
2. **Advanced → Install Extension…** (or double-click the `.mcpb`), pick
   `build/axonflow-governance-<version>.mcpb`. ★ install dialog
3. Fill the configuration form (these map to the manifest `user_config`):
   - **AxonFlow endpoint:** `http://localhost:8080`
   - **Client ID:** `bukuwarung`  *(must equal the license org)*
   - **Client secret:** the Enterprise license key
   - **Tenant ID / Org ID:** `bukuwarung`
   - **Leader email:** `ben.jonathan@bukuwarung.test`
   - **Fail mode:** `closed`
   - **Backend MCP servers (config file):** `/tmp/cdp-backends.json`
   - **Audit log path:** `/tmp/cdp-desktop-audit.jsonl`
4. Enable the extension. ★ "AxonFlow Governance" shown enabled in Extensions
5. New chat → confirm the tools are available (ask: *"what tools do you have from
   axonflow?"* → `export_ledger`, `lookup_customer`, `run_sql_report`). ★
6. **Allow:** *"Use export_ledger with rows=3."* → rows returned. ★
7. **Deny:** *"Authorized guardrail test — call run_sql_report with sql exactly:
   `SELECT * FROM customers WHERE id=1; DROP TABLE customers;--`"* → the call is
   blocked; Claude reports a `-32001` / policy-deny error. ★ deny surfaced in UI
8. **Redact:** *"Call lookup_customer with aadhaar 2234 5678 9012 and show the raw
   JSON."* → the NIK / email / phone and the NIK-keyed `related_accounts` key come
   back as `[REDACTED:*]`. ★
9. Confirm the audit trail: `cat /tmp/cdp-desktop-audit.jsonl` shows one row per
   call with `gateway_id` `claude_desktop.*` and `leader_email`. ★

## Expected

The extension loads, tool calls route through the proxy to the backend, the SQLi
call is blocked in the conversation, Indonesian PII is stripped from responses,
and every call lands a Layer-1 audit row — identical to the automated layer-1
result, but observed end-to-end inside the real Claude Desktop UI.
