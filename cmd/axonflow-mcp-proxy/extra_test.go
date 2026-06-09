// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewProxy_BuildsBackends(t *testing.T) {
	cfg := Config{
		Endpoint: "http://localhost:8080",
		Timeout:  time.Second,
		Backends: []BackendConfig{
			{ID: "crm", URL: "http://localhost:9000"},
			{ID: "bq", Command: "node", Args: []string{"s.js"}},
		},
	}
	p, err := NewProxy(cfg)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}
	if len(p.backends) != 2 || len(p.backendOrder) != 2 {
		t.Fatalf("backends not wired: %d", len(p.backends))
	}
	p.Close() // exercises Proxy.Close + backend Close
}

func TestNewProxy_BadBackend(t *testing.T) {
	_, err := NewProxy(Config{Backends: []BackendConfig{{ID: "x"}}}) // no transport
	if err == nil {
		t.Fatalf("expected error for transportless backend")
	}
}

func TestDispatch_BadToolsCallParams(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	p := newTestProxy(t, d.server.URL, be)

	// malformed params
	resp, respond := p.dispatch(context.Background(), &JSONRPCRequest{Method: "tools/call", ID: json.RawMessage(`1`), Params: json.RawMessage(`"notanobject"`)})
	if !respond || resp.Error == nil || resp.Error.Code != codeInvalidParams {
		t.Fatalf("bad params should yield invalid-params error, got %+v", resp)
	}
	// missing name
	resp2, _ := p.dispatch(context.Background(), &JSONRPCRequest{Method: "tools/call", ID: json.RawMessage(`2`), Params: json.RawMessage(`{"arguments":{}}`)})
	if resp2.Error == nil || !strings.Contains(resp2.Error.Message, "missing tool name") {
		t.Fatalf("missing name should error, got %+v", resp2)
	}
}

func TestDispatch_NotificationNoResponse(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	p := newTestProxy(t, d.server.URL, be)
	_, respond := p.dispatch(context.Background(), &JSONRPCRequest{Method: "notifications/initialized"})
	if respond {
		t.Fatalf("notification must not be answered")
	}
	// Unknown notification (no id) also yields no response.
	_, respond2 := p.dispatch(context.Background(), &JSONRPCRequest{Method: "some/unknown"})
	if respond2 {
		t.Fatalf("unknown notification must not be answered")
	}
}

func TestServe_ParseErrorLine(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	p := newTestProxy(t, d.server.URL, be)
	in := strings.NewReader("this is not json\n")
	var out strings.Builder
	_ = p.Serve(context.Background(), in, &out)
	if !strings.Contains(out.String(), "invalid JSON-RPC") {
		t.Fatalf("expected parse error response, got %q", out.String())
	}
}

func TestHandleToolsList_AggregateError(t *testing.T) {
	// All backends unhealthy → ToolsList returns error → handler surfaces it.
	bad := &fakeBackend{id: "x", initErr: context.Canceled}
	cfg := Config{Endpoint: "http://localhost:8080", Timeout: time.Second}
	p := &Proxy{cfg: cfg, decide: NewDecideClient(cfg), audit: newSilentAudit(),
		backends: map[string]Backend{"x": bad}, routes: map[string]route{}, backendOrder: []string{"x"}}
	resp := p.handleToolsList(context.Background(), &JSONRPCRequest{ID: json.RawMessage(`1`), Method: "tools/list"})
	if resp.Error == nil {
		t.Fatalf("expected error when no backend is reachable")
	}
}

func TestFailModeLabel(t *testing.T) {
	if failModeLabel(true) != "open" {
		t.Fatalf("open label wrong")
	}
	if !strings.Contains(failModeLabel(false), "closed") {
		t.Fatalf("closed label wrong")
	}
}

func TestRPCError_Error(t *testing.T) {
	e := &rpcError{Code: -1, Message: "x"}
	if !strings.Contains(e.Error(), "x") {
		t.Fatalf("rpcError.Error lost message")
	}
}

func TestClientError_Error(t *testing.T) {
	e := &clientError{StatusCode: 403, Body: "nope"}
	if !strings.Contains(e.Error(), "403") {
		t.Fatalf("clientError.Error lost status")
	}
}

func TestHelpers(t *testing.T) {
	if firstNonEmpty("", "b") != "b" || firstNonEmpty("a", "b") != "a" {
		t.Fatalf("firstNonEmpty wrong")
	}
	if mustJSONString("a\"b") == "" {
		t.Fatalf("mustJSONString empty")
	}
	if string(mustRaw(nil)) != "" {
		t.Fatalf("mustRaw(nil) should be empty")
	}
	if string(mustRaw(map[string]int{"a": 1})) != `{"a":1}` {
		t.Fatalf("mustRaw object wrong")
	}
	if randomHex(4) == randomHex(4) {
		t.Fatalf("randomHex not random")
	}
}

func TestBackendIDAccessors(t *testing.T) {
	if newStdioBackend(BackendConfig{ID: "s"}).ID() != "s" {
		t.Fatalf("stdio ID wrong")
	}
	if newHTTPBackend(BackendConfig{ID: "h"}).ID() != "h" {
		t.Fatalf("http ID wrong")
	}
}

func TestEnforce_FailOpen_TransportError_StillFailsClosedOnRedaction(t *testing.T) {
	// The decide FailOpen posture governs the REQUEST plane only. With the whole
	// endpoint dead, fail-open forwards the call to the backend — but the RESPONSE
	// plane is unconditionally fail-closed: check-output is also unreachable, so
	// the PII-bearing response must NOT be forwarded. A network hiccup must never
	// leak un-redacted PII into the context window, regardless of the decide
	// posture. (This replaces the old "fail-open forwards AND redacts locally"
	// test — there is no local redactor to fall back to anymore.)
	piiResult := `{"content":[{"type":"text","text":"nik 3174012509900001"}]}`
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")},
		callResult: json.RawMessage(piiResult)}
	p := newTestProxy(t, "http://127.0.0.1:1", be) // dead endpoint (decide AND check-output)
	p.cfg.FailOpen = true

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`1`), ToolCallParams{Name: "lookup"})
	e := mustParseError(t, resp)
	if e.Code != codePolicyUnavailable {
		t.Fatalf("fail-open + redaction-unreachable must fail closed, code = %d want %d", e.Code, codePolicyUnavailable)
	}
	if be.callCount.Load() != 1 {
		t.Fatalf("fail-open should still reach the backend once, got %d", be.callCount.Load())
	}
	if strings.Contains(string(resp.Result)+e.Message, "3174012509900001") {
		t.Fatalf("PII must not leak when redaction is unreachable: %s / %s", string(resp.Result), e.Message)
	}
}

func TestEnforce_BackendTimeout(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dt", TraceID: strings.Repeat("a", 32)}
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}, blockCall: true}
	p := newTestProxy(t, d.server.URL, be)
	p.cfg.BackendTimeout = 50 * time.Millisecond

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`1`), ToolCallParams{Name: "lookup"})
	e := mustParseError(t, resp)
	if e.Code != codeInternalError {
		t.Fatalf("hung backend should yield internal error, got code %d", e.Code)
	}
}

func TestHandleToolsCallMessage_MalformedParams_Audited(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")}}
	p := newTestProxy(t, d.server.URL, be)
	var audited int
	p.audit = &AuditLogger{out: func(string) { audited++ }}

	// malformed params
	r1 := p.handleToolsCallMessage(context.Background(), &JSONRPCRequest{ID: json.RawMessage(`1`), Method: "tools/call", Params: json.RawMessage(`"x"`)})
	// missing name
	r2 := p.handleToolsCallMessage(context.Background(), &JSONRPCRequest{ID: json.RawMessage(`2`), Method: "tools/call", Params: json.RawMessage(`{"arguments":{}}`)})
	if r1.Error == nil || r2.Error == nil {
		t.Fatalf("both malformed calls should error")
	}
	if audited != 2 {
		t.Fatalf("both malformed tools/call should write an audit row, got %d", audited)
	}
}

func TestLoadConfig_BadBackendTimeout_Errors(t *testing.T) {
	t.Setenv("AXONFLOW_BACKEND_TIMEOUT", "nope")
	t.Setenv("AXONFLOW_BACKENDS", `[{"id":"x","url":"http://a"}]`)
	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected backend-timeout parse error")
	}
}
