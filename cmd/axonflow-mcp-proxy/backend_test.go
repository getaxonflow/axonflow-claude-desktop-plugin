// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain doubles the test binary as a stdio MCP stub when PROXY_TEST_STDIO_STUB
// is set, so the stdioBackend transport is exercised against a REAL child
// process (exec + pipes + reader goroutine) rather than a mock.
func TestMain(m *testing.M) {
	// PROXY_TEST_STDIO_DIE makes the re-exec'd binary exit immediately, before any
	// handshake — emulating a backend whose process is permanently down (every
	// (re)spawn dies), so the bounded-backoff / stays-down path can be tested.
	if os.Getenv("PROXY_TEST_STDIO_DIE") == "1" {
		os.Exit(0)
	}
	if os.Getenv("PROXY_TEST_STDIO_STUB") == "1" {
		runStdioStub()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// runStdioStub is a minimal stdio MCP server: initialize, tools/list (one tool
// "echo"), tools/call (echo returns the args; "boom" returns a JSON-RPC error).
func runStdioStub() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req JSONRPCRequest
		if json.Unmarshal(line, &req) != nil {
			continue
		}
		switch req.Method {
		case "initialize":
			writeStub(req.ID, json.RawMessage(`{"protocolVersion":"2025-06-18","capabilities":{},"serverInfo":{"name":"stub","version":"0"}}`), nil)
		case "notifications/initialized":
			// no response
		case "tools/list":
			writeStub(req.ID, json.RawMessage(`{"tools":[{"name":"echo","description":"echoes"}]}`), nil)
		case "tools/call":
			var p ToolCallParams
			_ = json.Unmarshal(req.Params, &p)
			if p.Name == "boom" {
				writeStub(req.ID, nil, &JSONRPCError{Code: -32070, Message: "kaboom"})
				continue
			}
			if p.Name == "slow" {
				// Sleep before responding so a test can kill the process while the
				// request is in flight, exercising the in-flight reconnect+retry path.
				time.Sleep(250 * time.Millisecond)
			}
			args, _ := json.Marshal(p.Arguments)
			writeStub(req.ID, json.RawMessage(`{"content":[{"type":"text","text":`+mustJSONString(string(args))+`}]}`), nil)
		default:
			writeStub(req.ID, nil, &JSONRPCError{Code: codeMethodNotFound, Message: "nope"})
		}
	}
}

func writeStub(id json.RawMessage, result json.RawMessage, e *JSONRPCError) {
	resp := JSONRPCResponse{JSONRPC: "2.0", ID: id, Result: result, Error: e}
	b, _ := json.Marshal(resp)
	os.Stdout.Write(append(b, '\n'))
}

func newStdioStubBackend() *stdioBackend {
	return newStdioBackend(BackendConfig{
		ID:      "stub",
		Command: os.Args[0],
		Env:     map[string]string{"PROXY_TEST_STDIO_STUB": "1"},
	})
}

func TestStdioBackend_InitializeListCall(t *testing.T) {
	b := newStdioStubBackend()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := b.Initialize(ctx); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	tools, err := b.ListTools(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(tools) != 1 || !strings.Contains(string(tools[0]), "echo") {
		t.Fatalf("tools = %v", tools)
	}
	result, err := b.CallTool(ctx, "echo", map[string]interface{}{"x": "y"}, "")
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if !strings.Contains(string(result), "x") {
		t.Fatalf("echo lost args: %s", string(result))
	}
}

func TestStdioBackend_RPCErrorPropagated(t *testing.T) {
	b := newStdioStubBackend()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := b.Initialize(ctx); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	_, err := b.CallTool(ctx, "boom", nil, "")
	var re *rpcError
	if !asRPCError(err, &re) || re.Code != -32070 {
		t.Fatalf("expected rpcError -32070, got %v", err)
	}
}

func TestStdioBackend_BadCommand(t *testing.T) {
	b := newStdioBackend(BackendConfig{ID: "x", Command: "/nonexistent/binary/xyz"})
	defer b.Close()
	if err := b.Initialize(context.Background()); err == nil {
		t.Fatalf("expected error launching bad command")
	}
}

func TestHTTPBackend_ListAndCall(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "initialize":
			writeHTTP(w, req.ID, json.RawMessage(`{"protocolVersion":"2025-06-18"}`), nil)
		case "tools/list":
			writeHTTP(w, req.ID, json.RawMessage(`{"tools":[{"name":"fetch"}]}`), nil)
		case "tools/call":
			writeHTTP(w, req.ID, json.RawMessage(`{"content":[{"type":"text","text":"hi"}]}`), nil)
		}
	}))
	defer srv.Close()

	b := newHTTPBackend(BackendConfig{ID: "h", URL: srv.URL})
	ctx := context.Background()
	if err := b.Initialize(ctx); err != nil {
		t.Fatalf("init: %v", err)
	}
	tools, err := b.ListTools(ctx)
	if err != nil || len(tools) != 1 {
		t.Fatalf("list: %v %v", err, tools)
	}
	res, err := b.CallTool(ctx, "fetch", nil, "00-"+strings.Repeat("a", 32)+"-"+strings.Repeat("b", 16)+"-01")
	if err != nil || !strings.Contains(string(res), "hi") {
		t.Fatalf("call: %v %s", err, string(res))
	}
}

// Regression: spec-compliant MCP servers (the official SDK Streamable-HTTP
// transport) return 406 Not Acceptable unless the client accepts
// text/event-stream, and may reply with an SSE stream. The proxy must accept
// both and parse the SSE body — otherwise every real backend lists 0 tools.
func TestHTTPBackend_StreamableHTTP_AcceptAndSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			http.Error(w, "Not Acceptable: requires text/event-stream", http.StatusNotAcceptable)
			return
		}
		var req JSONRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		var result string
		switch req.Method {
		case "initialize":
			result = `{"protocolVersion":"2025-06-18"}`
		case "tools/list":
			result = `{"tools":[{"name":"get_user"}]}`
		default:
			result = `{}`
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// SSE framing: an unrelated notification event first, then the response.
		_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\"}\n\n"))
		_, _ = w.Write([]byte("event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":" + string(req.ID) + ",\"result\":" + result + "}\n\n"))
	}))
	defer srv.Close()

	b := newHTTPBackend(BackendConfig{ID: "strict", URL: srv.URL})
	ctx := context.Background()
	if err := b.Initialize(ctx); err != nil {
		t.Fatalf("initialize against strict SSE backend failed (406/accept regression): %v", err)
	}
	tools, err := b.ListTools(ctx)
	if err != nil || len(tools) != 1 {
		t.Fatalf("tools/list against strict SSE backend: err=%v tools=%v (want 1)", err, tools)
	}
}

func TestDecodeBackendResponse(t *testing.T) {
	// application/json single response
	r, err := decodeBackendResponse("application/json", strings.NewReader(`{"jsonrpc":"2.0","id":7,"result":{"ok":true}}`), "7")
	if err != nil || r.Result == nil {
		t.Fatalf("json: err=%v r=%+v", err, r)
	}
	// SSE: skip a notification, return the id-matched response
	sse := "event: message\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"}\n\n" +
		"event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"ok\":true}}\n\n"
	r, err = decodeBackendResponse("text/event-stream; charset=utf-8", strings.NewReader(sse), "7")
	if err != nil || r.Result == nil || string(r.ID) != "7" {
		t.Fatalf("sse: err=%v r=%+v", err, r)
	}
	// SSE multi-line data field (joined with "\n" per the spec)
	multi := "data: {\"jsonrpc\":\"2.0\",\"id\":7,\n" + "data: \"result\":{\"ok\":true}}\n\n"
	if r, err = decodeBackendResponse("text/event-stream", strings.NewReader(multi), "7"); err != nil || r.Result == nil {
		t.Fatalf("sse multiline: err=%v r=%+v", err, r)
	}
	// SSE with no response payload → explicit error, not a nil deref
	if _, err = decodeBackendResponse("text/event-stream", strings.NewReader("event: ping\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"n\"}\n\n"), "7"); err == nil {
		t.Fatalf("expected error when SSE carries no response")
	}
}

// Regression: a STATEFUL Streamable-HTTP backend (official MCP SDK default)
// returns an Mcp-Session-Id on initialize and 400s any later request that
// doesn't echo it. The proxy must capture and replay the session id — symptom
// otherwise is "200 (initialize) then 400 (tools/list) → 0 tools".
func TestHTTPBackend_StatefulSession(t *testing.T) {
	const sid = "sess-abc123"
	var sawInitialized bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.isNotification() { // notifications/initialized → 202, no body
			if req.Method == "notifications/initialized" {
				sawInitialized = true
			}
			w.WriteHeader(http.StatusAccepted)
			return
		}
		if req.Method == "initialize" {
			w.Header().Set("Mcp-Session-Id", sid)
			writeHTTP(w, req.ID, json.RawMessage(`{"protocolVersion":"2025-06-18"}`), nil)
			return
		}
		if r.Header.Get("Mcp-Session-Id") != sid {
			http.Error(w, `{"jsonrpc":"2.0","error":{"code":-32600,"message":"No valid session ID provided"}}`, http.StatusBadRequest)
			return
		}
		if req.Method == "tools/list" {
			writeHTTP(w, req.ID, json.RawMessage(`{"tools":[{"name":"lookup_customer"}]}`), nil)
		}
	}))
	defer srv.Close()

	b := newHTTPBackend(BackendConfig{ID: "stateful", URL: srv.URL})
	ctx := context.Background()
	if err := b.Initialize(ctx); err != nil {
		t.Fatalf("initialize against stateful backend: %v", err)
	}
	if b.getSession() != sid {
		t.Fatalf("session id not captured: got %q want %q", b.getSession(), sid)
	}
	if !sawInitialized {
		t.Fatalf("notifications/initialized was not sent")
	}
	tools, err := b.ListTools(ctx)
	if err != nil || len(tools) != 1 {
		t.Fatalf("tools/list against stateful backend (session-id replay): err=%v tools=%v", err, tools)
	}
}

func TestHTTPBackend_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	b := newHTTPBackend(BackendConfig{ID: "h", URL: srv.URL})
	if _, err := b.ListTools(context.Background()); err == nil {
		t.Fatalf("expected error on HTTP 500")
	}
}

func TestHTTPBackend_RPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		writeHTTP(w, req.ID, nil, &JSONRPCError{Code: -32080, Message: "denied"})
	}))
	defer srv.Close()
	b := newHTTPBackend(BackendConfig{ID: "h", URL: srv.URL})
	_, err := b.CallTool(context.Background(), "x", nil, "")
	var re *rpcError
	if !asRPCError(err, &re) || re.Code != -32080 {
		t.Fatalf("expected rpcError -32080, got %v", err)
	}
}

func writeHTTP(w http.ResponseWriter, id json.RawMessage, result json.RawMessage, e *JSONRPCError) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(JSONRPCResponse{JSONRPC: "2.0", ID: id, Result: result, Error: e})
}

func TestNewBackend_Transport(t *testing.T) {
	if _, err := NewBackend(BackendConfig{ID: "a", Command: "node"}); err != nil {
		t.Fatalf("stdio: %v", err)
	}
	if _, err := NewBackend(BackendConfig{ID: "b", URL: "http://x"}); err != nil {
		t.Fatalf("http: %v", err)
	}
	if _, err := NewBackend(BackendConfig{ID: "c"}); err == nil {
		t.Fatalf("expected error for no transport")
	}
}
