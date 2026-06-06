// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fakeBackend is an in-memory Backend for deterministic enforcement tests.
type fakeBackend struct {
	id         string
	tools      []json.RawMessage
	initErr    error
	listErr    error
	callResult json.RawMessage
	callErr    error

	blockCall bool // when true, CallTool blocks until ctx is cancelled (timeout test)

	initialized atomic.Bool
	callCount   atomic.Int64
	lastTool    string
	lastArgs    map[string]interface{}
}

func (f *fakeBackend) ID() string { return f.id }
func (f *fakeBackend) Initialize(context.Context) error {
	f.initialized.Store(true)
	return f.initErr
}
func (f *fakeBackend) ListTools(context.Context) ([]json.RawMessage, error) {
	return f.tools, f.listErr
}
func (f *fakeBackend) CallTool(ctx context.Context, name string, args map[string]interface{}, _ string) (json.RawMessage, error) {
	f.callCount.Add(1)
	f.lastTool = name
	f.lastArgs = args
	if f.blockCall {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return f.callResult, f.callErr
}
func (f *fakeBackend) Close() error { return nil }

func toolDescriptor(name string) json.RawMessage {
	return json.RawMessage(`{"name":"` + name + `","description":"d","inputSchema":{"type":"object"}}`)
}

// decideStub stands up an httptest server emulating POST /api/v1/decide.
type decideStub struct {
	server  *httptest.Server
	status  int
	resp    DecideResponse
	calls   atomic.Int64
	lastReq DecideRequest
}

func newDecideStub() *decideStub {
	d := &decideStub{status: http.StatusOK}
	d.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.calls.Add(1)
		_ = json.NewDecoder(r.Body).Decode(&d.lastReq)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(d.status)
		_ = json.NewEncoder(w).Encode(d.resp)
	}))
	return d
}
func (d *decideStub) close() { d.server.Close() }

// newTestProxy builds a Proxy pointed at the decide stub with the given
// backends already aggregated, so enforce() tests skip the network handshake.
func newTestProxy(t *testing.T, endpoint string, backends ...*fakeBackend) *Proxy {
	t.Helper()
	cfg := Config{
		Endpoint:    endpoint,
		ClientID:    "test",
		TenantID:    "tenant-test",
		OrgID:       "org-test",
		GatewayID:   "claude_desktop.test",
		Timeout:     2 * time.Second,
		LeaderEmail: "leader@bukuwarung.test",
		AIAgent:     "claude-desktop",
		SessionID:   "sess-test",
		// Match the production default: scan every response unconditionally.
		RedactResponses: redactAlways,
	}
	p := &Proxy{
		cfg:      cfg,
		decide:   NewDecideClient(cfg),
		audit:    newSilentAudit(),
		backends: map[string]Backend{},
		routes:   map[string]route{},
	}
	for _, b := range backends {
		cfg.Backends = append(cfg.Backends, BackendConfig{ID: b.id})
		p.backends[b.id] = b
		p.backendOrder = append(p.backendOrder, b.id)
	}
	p.cfg.Backends = cfg.Backends
	if err := p.Aggregate(context.Background()); err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	return p
}

// newSilentAudit returns an AuditLogger whose stderr echo is a no-op (keeps
// test output clean) but still records rows.
func newSilentAudit() *AuditLogger {
	return &AuditLogger{out: func(string) {}}
}

func mustParseError(t *testing.T, resp JSONRPCResponse) *JSONRPCError {
	t.Helper()
	if resp.Error == nil {
		t.Fatalf("expected error response, got result=%s", string(resp.Result))
	}
	return resp.Error
}

func TestEnforce_Allow_ForwardsAndAudits(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-1", TraceID: strings.Repeat("a", 32), EvaluatedPolicies: []string{}}

	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")},
		callResult: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)}
	p := newTestProxy(t, d.server.URL, be)

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`1`), ToolCallParams{Name: "lookup", Arguments: map[string]interface{}{"id": "c1"}})
	if resp.Error != nil {
		t.Fatalf("expected allow result, got error %+v", resp.Error)
	}
	if be.callCount.Load() != 1 {
		t.Fatalf("expected backend called once, got %d", be.callCount.Load())
	}
	if be.lastTool != "lookup" {
		t.Fatalf("backend got tool %q, want lookup", be.lastTool)
	}
	// caller_identity + context must carry the Desktop origin.
	if d.lastReq.CallerIdentity.GatewayID != "claude_desktop.test" {
		t.Fatalf("gateway_id not forwarded: %q", d.lastReq.CallerIdentity.GatewayID)
	}
	if d.lastReq.Context["x-session-id"] != "sess-test" {
		t.Fatalf("session id not in decide context: %v", d.lastReq.Context["x-session-id"])
	}
}

func TestEnforce_Deny_BlocksWithCode32001(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictDeny, DecisionID: "dec-2", TraceID: strings.Repeat("b", 32),
		Reasons: []string{"sql_injection detected"}, EvaluatedPolicies: []string{"security-sqli"}}

	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("run_query")},
		callResult: json.RawMessage(`{"content":[]}`)}
	p := newTestProxy(t, d.server.URL, be)

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`2`), ToolCallParams{Name: "run_query", Arguments: map[string]interface{}{"q": "DROP TABLE"}})
	e := mustParseError(t, resp)
	if e.Code != codePolicyDeny {
		t.Fatalf("deny code = %d, want %d", e.Code, codePolicyDeny)
	}
	if !strings.Contains(e.Message, "sql_injection") {
		t.Fatalf("deny message lost reason: %q", e.Message)
	}
	if be.callCount.Load() != 0 {
		t.Fatalf("DENY must not reach backend; got %d calls", be.callCount.Load())
	}
	// decision evidence present in error data.
	var data map[string]interface{}
	if err := json.Unmarshal(e.Data, &data); err != nil {
		t.Fatalf("deny data not JSON: %v", err)
	}
	if data["decision_id"] != "dec-2" {
		t.Fatalf("deny data missing decision_id: %v", data)
	}
}

func TestEnforce_NeedsApproval_Code32002(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictNeedsApproval, DecisionID: "dec-3", TraceID: strings.Repeat("c", 32)}
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("refund")}}
	p := newTestProxy(t, d.server.URL, be)

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`3`), ToolCallParams{Name: "refund"})
	e := mustParseError(t, resp)
	if e.Code != codeNeedsApproval {
		t.Fatalf("needs_approval code = %d, want %d", e.Code, codeNeedsApproval)
	}
	if be.callCount.Load() != 0 {
		t.Fatalf("needs_approval must not reach backend")
	}
}

func TestEnforce_RedactObligation_StripsPII(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-4", TraceID: strings.Repeat("d", 32),
		Obligations: []DecisionObligation{{Type: "redact_pii", Detail: "indonesia pii"}}}

	// Backend returns NIK + email inside a content text block.
	piiResult := `{"content":[{"type":"text","text":"nik 3174012509900001 email budi@example.co.id"}]}`
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")},
		callResult: json.RawMessage(piiResult)}
	p := newTestProxy(t, d.server.URL, be)

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`4`), ToolCallParams{Name: "lookup"})
	if resp.Error != nil {
		t.Fatalf("expected allow, got %+v", resp.Error)
	}
	body := string(resp.Result)
	if strings.Contains(body, "3174012509900001") || strings.Contains(body, "budi@example.co.id") {
		t.Fatalf("PII not redacted from response: %s", body)
	}
	if !strings.Contains(body, "[REDACTED:nik]") || !strings.Contains(body, "[REDACTED:email]") {
		t.Fatalf("redaction tokens missing: %s", body)
	}
}

// TestEnforce_CleanRequest_ResponseOnlyPII_DefaultRedacts is the #2530
// regression guard: an ALLOW verdict with NO redact_pii obligation — i.e. a
// clean, non-PII request — whose RESPONSE nonetheless carries PII must still be
// redacted under the default (always) mode. This is the exact case the old
// obligation-gated proxy leaked: lookup_customer {customer_id:"CUST-001"} →
// allow|obligations=none → PII forwarded raw. The proxy is the only component
// that ever sees the response, so the scan can't be gated on the request.
func TestEnforce_CleanRequest_ResponseOnlyPII_DefaultRedacts(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	// allow, NO obligations — exactly what the live PDP returns for a clean
	// customer_id lookup.
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-5", TraceID: strings.Repeat("e", 32),
		Obligations: []DecisionObligation{}}
	// Response carries NIK + email + a NIK-keyed map (the §4.3 key case) even
	// though the request (below) is clean.
	piiResult := `{"content":[{"type":"text","text":"{\"nik\":\"3174012509900001\",\"email\":\"budi@example.co.id\",\"related\":{\"3174012509900001\":{\"bank\":\"BCA\"}}}"}]}`
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup_customer")}, callResult: json.RawMessage(piiResult)}
	p := newTestProxy(t, d.server.URL, be)

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`5`),
		ToolCallParams{Name: "lookup_customer", Arguments: map[string]interface{}{"customer_id": "CUST-001"}})
	if resp.Error != nil {
		t.Fatalf("expected allow result, got error %+v", resp.Error)
	}
	body := string(resp.Result)
	if strings.Contains(body, "3174012509900001") || strings.Contains(body, "budi@example.co.id") {
		t.Fatalf("response-only PII leaked despite no obligation (the #2530 bug): %s", body)
	}
	if !strings.Contains(body, "[REDACTED:nik]") || !strings.Contains(body, "[REDACTED:email]") {
		t.Fatalf("expected redaction tokens in clean-request response: %s", body)
	}
}

// TestEnforce_OnObligationMode_NoObligation_PassesThrough documents the legacy
// (opt-in) mode: with AXONFLOW_REDACT_RESPONSES=on-obligation and no obligation,
// the response is NOT scanned. This is the behaviour that used to be the default
// and silently leaked — it is now an explicit opt-in, retained only for parity.
func TestEnforce_OnObligationMode_NoObligation_PassesThrough(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-5b", TraceID: strings.Repeat("e", 32)}
	piiResult := `{"content":[{"type":"text","text":"email keep@example.com"}]}`
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}, callResult: json.RawMessage(piiResult)}
	p := newTestProxy(t, d.server.URL, be)
	p.cfg.RedactResponses = redactOnObligation

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`5`), ToolCallParams{Name: "lookup"})
	if !strings.Contains(string(resp.Result), "keep@example.com") {
		t.Fatalf("on-obligation mode without obligation must pass through: %s", string(resp.Result))
	}
}

// TestEnforce_OnObligationMode_WithObligation_Redacts confirms the legacy mode
// still honours an explicit redact_pii obligation.
func TestEnforce_OnObligationMode_WithObligation_Redacts(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-5c", TraceID: strings.Repeat("e", 32),
		Obligations: []DecisionObligation{{Type: "redact_pii"}}}
	piiResult := `{"content":[{"type":"text","text":"email strip@example.com"}]}`
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}, callResult: json.RawMessage(piiResult)}
	p := newTestProxy(t, d.server.URL, be)
	p.cfg.RedactResponses = redactOnObligation

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`5`), ToolCallParams{Name: "lookup"})
	if strings.Contains(string(resp.Result), "strip@example.com") {
		t.Fatalf("on-obligation mode with obligation must redact: %s", string(resp.Result))
	}
}

// TestEnforce_OffMode_NeverRedacts confirms the explicit opt-out: with
// AXONFLOW_REDACT_RESPONSES=off, even a redact_pii obligation does not scan the
// response (the documented footgun).
func TestEnforce_OffMode_NeverRedacts(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-5d", TraceID: strings.Repeat("e", 32),
		Obligations: []DecisionObligation{{Type: "redact_pii"}}}
	piiResult := `{"content":[{"type":"text","text":"email leak@example.com"}]}`
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}, callResult: json.RawMessage(piiResult)}
	p := newTestProxy(t, d.server.URL, be)
	p.cfg.RedactResponses = redactOff

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`5`), ToolCallParams{Name: "lookup"})
	if !strings.Contains(string(resp.Result), "leak@example.com") {
		t.Fatalf("off mode must never redact (even with obligation): %s", string(resp.Result))
	}
	if resp.Error != nil {
		t.Fatalf("off mode should still forward: %+v", resp.Error)
	}
}

// TestEnforce_DefaultAlways_NonPII_NotOverRedacted is the defensive guard: a
// clean response under default-always must be forwarded byte-for-byte, with zero
// redactions — always-scan must not corrupt or over-mask benign data.
func TestEnforce_DefaultAlways_NonPII_NotOverRedacted(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-5e", TraceID: strings.Repeat("e", 32)}
	clean := `{"content":[{"type":"text","text":"{\"period\":\"2026-Q2\",\"order_count\":1320,\"status\":\"ok\"}"}]}`
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("get_sales_summary")}, callResult: json.RawMessage(clean)}
	p := newTestProxy(t, d.server.URL, be)

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`5`), ToolCallParams{Name: "get_sales_summary"})
	if resp.Error != nil {
		t.Fatalf("expected allow, got %+v", resp.Error)
	}
	if strings.Contains(string(resp.Result), "[REDACTED:") {
		t.Fatalf("benign response over-redacted under default-always: %s", string(resp.Result))
	}
	for _, want := range []string{"2026-Q2", "1320", "ok"} {
		if !strings.Contains(string(resp.Result), want) {
			t.Fatalf("benign field %q lost: %s", want, string(resp.Result))
		}
	}
}

func TestEnforce_FailClosed_PDPUnreachable(t *testing.T) {
	// Point at a closed port so the decide call errors (transport failure).
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	p := newTestProxy(t, "http://127.0.0.1:1", be)
	p.cfg.FailOpen = false

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`6`), ToolCallParams{Name: "lookup"})
	e := mustParseError(t, resp)
	if e.Code != codePolicyUnavailable {
		t.Fatalf("fail-closed code = %d, want %d", e.Code, codePolicyUnavailable)
	}
	if be.callCount.Load() != 0 {
		t.Fatalf("fail-closed must not reach backend")
	}
}

func TestEnforce_FailClosed_On503(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.status = http.StatusServiceUnavailable
	d.resp = DecideResponse{Verdict: verdictDeny, TraceID: strings.Repeat("f", 32)}
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	p := newTestProxy(t, d.server.URL, be)

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`7`), ToolCallParams{Name: "lookup"})
	e := mustParseError(t, resp)
	if e.Code != codePolicyUnavailable {
		t.Fatalf("503 fail-closed code = %d, want %d", e.Code, codePolicyUnavailable)
	}
	if be.callCount.Load() != 0 {
		t.Fatalf("503 fail-closed must not reach backend")
	}
}

func TestEnforce_FailOpen_On503_Forwards(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.status = http.StatusServiceUnavailable
	d.resp = DecideResponse{Verdict: verdictDeny, TraceID: strings.Repeat("1", 32)}
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")},
		callResult: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)}
	p := newTestProxy(t, d.server.URL, be)
	p.cfg.FailOpen = true

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`8`), ToolCallParams{Name: "lookup"})
	if resp.Error != nil {
		t.Fatalf("fail-open on 503 should forward, got %+v", resp.Error)
	}
	if be.callCount.Load() != 1 {
		t.Fatalf("fail-open should reach backend once, got %d", be.callCount.Load())
	}
}

func TestEnforce_ClientError_NeverFailOpen(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.status = http.StatusUnauthorized // 401 — misconfig, not degradation
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	p := newTestProxy(t, d.server.URL, be)
	p.cfg.FailOpen = true // even with fail-open, a 4xx must NOT forward

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`9`), ToolCallParams{Name: "lookup"})
	e := mustParseError(t, resp)
	if e.Code != codePolicyUnavailable {
		t.Fatalf("client error code = %d, want %d", e.Code, codePolicyUnavailable)
	}
	if be.callCount.Load() != 0 {
		t.Fatalf("4xx must never reach backend even with fail-open")
	}
}

func TestEnforce_UnknownTool(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	p := newTestProxy(t, d.server.URL, be)

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`10`), ToolCallParams{Name: "nonexistent"})
	e := mustParseError(t, resp)
	if e.Code != codeInvalidParams {
		t.Fatalf("unknown tool code = %d, want %d", e.Code, codeInvalidParams)
	}
	if d.calls.Load() != 0 {
		t.Fatalf("unknown tool must not call PDP")
	}
}

func TestEnforce_BackendRPCError_Propagated(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-11", TraceID: strings.Repeat("2", 32)}
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")},
		callErr: &rpcError{Code: -32050, Message: "backend boom"}}
	p := newTestProxy(t, d.server.URL, be)

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`11`), ToolCallParams{Name: "lookup"})
	e := mustParseError(t, resp)
	if e.Code != -32050 || !strings.Contains(e.Message, "boom") {
		t.Fatalf("backend rpc error not propagated: %+v", e)
	}
}

func TestAggregation_NamespacesMultipleBackends(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	be1 := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	be2 := &fakeBackend{id: "bq", tools: []json.RawMessage{toolDescriptor("lookup")}} // same tool name → must namespace
	p := newTestProxy(t, d.server.URL, be1, be2)

	got := p.sortedRoutes()
	want := []string{"bq__lookup", "crm__lookup"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("namespaced routes = %v, want %v", got, want)
	}
	// Routing resolves to the right backend + original name.
	r := p.routes["crm__lookup"]
	if r.backendID != "crm" || r.originalName != "lookup" {
		t.Fatalf("route crm__lookup = %+v", r)
	}
}

func TestAggregation_SingleBackend_NoPrefix(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	p := newTestProxy(t, d.server.URL, be)
	if got := p.sortedRoutes(); len(got) != 1 || got[0] != "lookup" {
		t.Fatalf("single-backend route = %v, want [lookup]", got)
	}
}

func TestAggregation_SkipsUnhealthyBackend(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	good := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	bad := &fakeBackend{id: "bq", initErr: context.DeadlineExceeded}
	p := newTestProxy(t, d.server.URL, good, bad)
	// With one unhealthy backend, multiBackend() is true so the healthy one is
	// still namespaced; routes contain only the healthy backend's tools.
	if got := p.sortedRoutes(); len(got) != 1 || got[0] != "crm__lookup" {
		t.Fatalf("routes after skip = %v, want [crm__lookup]", got)
	}
}

func TestServe_InitializeToolsListCall(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-s", TraceID: strings.Repeat("3", 32)}
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")},
		callResult: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)}
	p := newTestProxy(t, d.server.URL, be)

	in := strings.NewReader(strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"lookup","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":4,"method":"ping"}`,
	}, "\n") + "\n")
	var out strings.Builder
	if err := p.Serve(context.Background(), in, &out); err != nil {
		t.Fatalf("serve: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	// initialize, tools/list, tools/call, ping → 4 responses (notification: none)
	if len(lines) != 4 {
		t.Fatalf("expected 4 responses, got %d: %v", len(lines), lines)
	}
	if !strings.Contains(lines[0], "axonflow-mcp-proxy") {
		t.Fatalf("initialize response missing serverInfo: %s", lines[0])
	}
	if !strings.Contains(lines[1], "\"lookup\"") {
		t.Fatalf("tools/list missing tool: %s", lines[1])
	}
}

func TestServe_MethodNotFound(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	p := newTestProxy(t, d.server.URL, be)
	in := strings.NewReader(`{"jsonrpc":"2.0","id":9,"method":"resources/list"}` + "\n")
	var out strings.Builder
	_ = p.Serve(context.Background(), in, &out)
	if !strings.Contains(out.String(), "method not found") {
		t.Fatalf("expected method-not-found, got %s", out.String())
	}
}

func TestCountRecords(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"empty", ``, 0},
		{"single text", `{"content":[{"type":"text","text":"hello"}]}`, 1},
		{"json array text", `{"content":[{"type":"text","text":"[{\"a\":1},{\"a\":2},{\"a\":3}]"}]}`, 3},
		{"structured array", `{"content":[],"structuredContent":[1,2,3,4]}`, 4},
		{"two text blocks", `{"content":[{"type":"text","text":"x"},{"type":"text","text":"y"}]}`, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := countRecords(json.RawMessage(c.in)); got != c.want {
				t.Fatalf("countRecords(%s) = %d, want %d", c.in, got, c.want)
			}
		})
	}
}
