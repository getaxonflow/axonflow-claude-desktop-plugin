// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// backendProtocolVersion is the MCP protocol version the proxy advertises to
// its backends during the initialize handshake. Backends that negotiate a
// different supported version echo their own; we don't hard-fail on a mismatch
// (forward-compat) — we only need tools/list + tools/call to work.
const backendProtocolVersion = "2025-06-18"

// rpcError wraps a JSON-RPC error returned BY a backend so the proxy can
// propagate it to Claude Desktop faithfully (same code + message) instead of
// flattening every backend failure into a generic internal error.
type rpcError struct {
	Code    int
	Message string
	Data    json.RawMessage
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("backend rpc error %d: %s", e.Code, e.Message)
}

// Backend is one MCP server the proxy fronts. Implementations are the stdio
// (launched subprocess) and http (remote URL) transports. All methods are
// safe for concurrent use.
type Backend interface {
	ID() string
	// Initialize performs the MCP initialize handshake. Idempotent: safe to
	// call once at startup.
	Initialize(ctx context.Context) error
	// ListTools returns the backend's raw tool descriptors (each element is one
	// entry of the tools/list result's "tools" array, preserved verbatim).
	ListTools(ctx context.Context) ([]json.RawMessage, error)
	// CallTool invokes a tool by its ORIGINAL (un-namespaced) name and returns
	// the raw "result" object. A backend-side JSON-RPC error is returned as a
	// *rpcError; a transport failure as a plain error.
	CallTool(ctx context.Context, name string, args map[string]interface{}, traceparent string) (json.RawMessage, error)
	Close() error
}

// NewBackend constructs the right transport for a BackendConfig.
func NewBackend(c BackendConfig) (Backend, error) {
	switch c.transport() {
	case "stdio":
		return newStdioBackend(c), nil
	case "http":
		return newHTTPBackend(c), nil
	default:
		return nil, fmt.Errorf("backend %q has no transport", c.ID)
	}
}

// ---------------------------------------------------------------------------
// stdio backend
// ---------------------------------------------------------------------------

// stdioBackend launches a backend MCP server as a child process and speaks
// newline-delimited JSON-RPC over its stdin/stdout. A single reader goroutine
// demultiplexes responses to per-request channels keyed by request id; server
// notifications (no id) are logged and dropped.
type stdioBackend struct {
	cfg BackendConfig

	startOnce sync.Once
	startErr  error

	cmd    *exec.Cmd
	stdin  io.WriteCloser
	writeM sync.Mutex // serializes line writes to the child's stdin

	idM     sync.Mutex
	nextID  int
	pending map[string]chan *JSONRPCResponse

	closed chan struct{}
}

func newStdioBackend(c BackendConfig) *stdioBackend {
	return &stdioBackend{
		cfg:     c,
		pending: map[string]chan *JSONRPCResponse{},
		closed:  make(chan struct{}),
	}
}

func (b *stdioBackend) ID() string { return b.cfg.ID }

// start launches the child process and the reader goroutine exactly once.
func (b *stdioBackend) start() error {
	b.startOnce.Do(func() {
		cmd := exec.Command(b.cfg.Command, b.cfg.Args...)
		// Inherit the proxy env and layer the backend's env on top so a backend
		// can receive its own credentials without leaking the proxy's.
		cmd.Env = os.Environ()
		for k, v := range b.cfg.Env {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
		stdin, err := cmd.StdinPipe()
		if err != nil {
			b.startErr = fmt.Errorf("backend %q stdin pipe: %w", b.cfg.ID, err)
			return
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			b.startErr = fmt.Errorf("backend %q stdout pipe: %w", b.cfg.ID, err)
			return
		}
		// Forward the child's stderr to ours, prefixed, so backend logs are
		// visible during the demo without polluting the JSON-RPC stdout channel.
		stderr, err := cmd.StderrPipe()
		if err != nil {
			b.startErr = fmt.Errorf("backend %q stderr pipe: %w", b.cfg.ID, err)
			return
		}
		if err := cmd.Start(); err != nil {
			b.startErr = fmt.Errorf("backend %q start %q: %w", b.cfg.ID, b.cfg.Command, err)
			return
		}
		b.cmd = cmd
		b.stdin = stdin
		go b.readLoop(stdout)
		go forwardStderr(b.cfg.ID, stderr)
	})
	return b.startErr
}

// readLoop demultiplexes backend responses to the pending channels. It runs
// until the child's stdout closes (process exit), then fails any still-pending
// requests so a caller never blocks forever on a dead backend.
func (b *stdioBackend) readLoop(stdout io.Reader) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), maxDecideResponseBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var resp JSONRPCResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			logStderr("backend %q: undecodable line dropped: %v", b.cfg.ID, err)
			continue
		}
		if len(resp.ID) == 0 || string(resp.ID) == "null" {
			// Server-initiated notification/request — out of scope for the
			// proxy's request/response use; log and drop.
			continue
		}
		key := string(resp.ID)
		b.idM.Lock()
		ch, ok := b.pending[key]
		if ok {
			delete(b.pending, key)
		}
		b.idM.Unlock()
		if ok {
			ch <- &resp
		}
	}
	// stdout closed → the backend process exited (crash or normal exit). Drain
	// pending callers with a synthetic error so none block forever. The proxy
	// does NOT auto-respawn within a session: subsequent calls routed here keep
	// returning "backend closed" until the proxy (Claude Desktop) restarts —
	// the degraded-until-restart contract documented in the README.
	close(b.closed)
	b.idM.Lock()
	for key, ch := range b.pending {
		delete(b.pending, key)
		ch <- &JSONRPCResponse{Error: &JSONRPCError{Code: codeInternalError, Message: "backend connection closed"}}
	}
	b.idM.Unlock()
}

// call sends a JSON-RPC request and waits for the matching response or ctx
// cancellation. Notifications (initialized) go through send with no wait.
func (b *stdioBackend) call(ctx context.Context, method string, params interface{}) (*JSONRPCResponse, error) {
	if err := b.start(); err != nil {
		return nil, err
	}

	b.idM.Lock()
	b.nextID++
	id := b.nextID
	b.idM.Unlock()
	idRaw := json.RawMessage(strconv.Itoa(id))
	key := string(idRaw)

	ch := make(chan *JSONRPCResponse, 1)
	b.idM.Lock()
	b.pending[key] = ch
	b.idM.Unlock()

	if err := b.writeMessage(JSONRPCRequest{JSONRPC: "2.0", ID: idRaw, Method: method, Params: mustRaw(params)}); err != nil {
		b.idM.Lock()
		delete(b.pending, key)
		b.idM.Unlock()
		return nil, err
	}

	select {
	case <-ctx.Done():
		b.idM.Lock()
		delete(b.pending, key)
		b.idM.Unlock()
		return nil, ctx.Err()
	case <-b.closed:
		b.idM.Lock()
		delete(b.pending, key)
		b.idM.Unlock()
		return nil, fmt.Errorf("backend %q closed before responding", b.cfg.ID)
	case resp := <-ch:
		return resp, nil
	}
}

// notify sends a JSON-RPC notification (no id, no response expected).
func (b *stdioBackend) notify(method string, params interface{}) error {
	if err := b.start(); err != nil {
		return err
	}
	return b.writeMessage(JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: mustRaw(params)})
}

// writeMessage marshals one JSON-RPC message to a single newline-terminated
// line. The write mutex guarantees lines never interleave on the child's stdin.
func (b *stdioBackend) writeMessage(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	data = append(data, '\n')
	b.writeM.Lock()
	defer b.writeM.Unlock()
	if _, err := b.stdin.Write(data); err != nil {
		return fmt.Errorf("write to backend %q: %w", b.cfg.ID, err)
	}
	return nil
}

func (b *stdioBackend) Initialize(ctx context.Context) error {
	resp, err := b.call(ctx, "initialize", map[string]interface{}{
		"protocolVersion": backendProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]string{"name": "axonflow-mcp-proxy", "version": proxyVersion},
	})
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return &rpcError{Code: resp.Error.Code, Message: resp.Error.Message, Data: resp.Error.Data}
	}
	// MCP requires the client to confirm initialization before normal use.
	if err := b.notify("notifications/initialized", map[string]interface{}{}); err != nil {
		return fmt.Errorf("backend %q initialized notification: %w", b.cfg.ID, err)
	}
	return nil
}

func (b *stdioBackend) ListTools(ctx context.Context) ([]json.RawMessage, error) {
	resp, err := b.call(ctx, "tools/list", map[string]interface{}{})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, &rpcError{Code: resp.Error.Code, Message: resp.Error.Message, Data: resp.Error.Data}
	}
	var result ToolsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("backend %q tools/list decode: %w", b.cfg.ID, err)
	}
	return result.Tools, nil
}

func (b *stdioBackend) CallTool(ctx context.Context, name string, args map[string]interface{}, _ string) (json.RawMessage, error) {
	resp, err := b.call(ctx, "tools/call", ToolCallParams{Name: name, Arguments: args})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, &rpcError{Code: resp.Error.Code, Message: resp.Error.Message, Data: resp.Error.Data}
	}
	return resp.Result, nil
}

func (b *stdioBackend) Close() error {
	if b.stdin != nil {
		_ = b.stdin.Close()
	}
	if b.cmd != nil && b.cmd.Process != nil {
		_ = b.cmd.Process.Kill()
		_ = b.cmd.Wait()
	}
	return nil
}

// forwardStderr copies a child's stderr to the proxy's stderr, line-prefixed.
func forwardStderr(id string, r io.Reader) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for scanner.Scan() {
		logStderr("[backend %s] %s", id, scanner.Text())
	}
}

// ---------------------------------------------------------------------------
// http backend
// ---------------------------------------------------------------------------

// httpBackend POSTs JSON-RPC to a backend MCP server's URL (MCP Streamable
// HTTP). It accepts both response shapes the spec allows — a single JSON
// object (application/json) and an SSE stream (text/event-stream) — and sends
// an Accept header covering both, so spec-compliant servers (the official MCP
// SDK transport) don't reject the request with 406 Not Acceptable.
type httpBackend struct {
	cfg    BackendConfig
	client *http.Client
	idM    sync.Mutex
	nextID int
}

func newHTTPBackend(c BackendConfig) *httpBackend {
	return &httpBackend{cfg: c, client: &http.Client{}}
}

func (b *httpBackend) ID() string { return b.cfg.ID }

// Initialize is a no-op handshake for the stateless HTTP shape: each POST is
// self-contained, so there's no session to establish. We still validate
// reachability by issuing the initialize call and surfacing a transport error.
func (b *httpBackend) Initialize(ctx context.Context) error {
	resp, err := b.post(ctx, "initialize", map[string]interface{}{
		"protocolVersion": backendProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo":      map[string]string{"name": "axonflow-mcp-proxy", "version": proxyVersion},
	}, "")
	if err != nil {
		return err
	}
	if resp.Error != nil {
		return &rpcError{Code: resp.Error.Code, Message: resp.Error.Message, Data: resp.Error.Data}
	}
	return nil
}

func (b *httpBackend) ListTools(ctx context.Context) ([]json.RawMessage, error) {
	resp, err := b.post(ctx, "tools/list", map[string]interface{}{}, "")
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, &rpcError{Code: resp.Error.Code, Message: resp.Error.Message, Data: resp.Error.Data}
	}
	var result ToolsListResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, fmt.Errorf("backend %q tools/list decode: %w", b.cfg.ID, err)
	}
	return result.Tools, nil
}

func (b *httpBackend) CallTool(ctx context.Context, name string, args map[string]interface{}, tp string) (json.RawMessage, error) {
	resp, err := b.post(ctx, "tools/call", ToolCallParams{Name: name, Arguments: args}, tp)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, &rpcError{Code: resp.Error.Code, Message: resp.Error.Message, Data: resp.Error.Data}
	}
	return resp.Result, nil
}

func (b *httpBackend) post(ctx context.Context, method string, params interface{}, traceparent string) (*JSONRPCResponse, error) {
	b.idM.Lock()
	b.nextID++
	id := b.nextID
	b.idM.Unlock()

	reqBody, err := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(strconv.Itoa(id)),
		Method:  method,
		Params:  mustRaw(params),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.cfg.URL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// MCP Streamable HTTP requires the client to accept BOTH a single JSON
	// response and an SSE stream. Spec-compliant servers (the official MCP
	// SDK transport) return 406 Not Acceptable if "text/event-stream" is
	// absent, so accepting only application/json silently breaks every real
	// backend — the symptom is a backend that never lists any tools.
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	if traceparent != "" {
		httpReq.Header.Set("Traceparent", traceparent)
	}

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("backend %q post: %w", b.cfg.ID, err)
	}
	defer resp.Body.Close()

	// Bound total bytes read regardless of response shape.
	limited := io.LimitReader(resp.Body, maxDecideResponseBytes)
	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(limited)
		return nil, fmt.Errorf("backend %q returned HTTP %d: %s", b.cfg.ID, resp.StatusCode, string(errBody))
	}
	// The server picks the response shape: a single JSON object
	// (application/json) or an SSE stream (text/event-stream) carrying the
	// JSON-RPC message in a `data:` field. For SSE we stream and return on the
	// FIRST matching response event rather than reading to stream close — so a
	// backend that holds the POST-response stream open (idle keep-alive) can't
	// wedge the proxy (the deferred Body.Close aborts the remainder).
	rpcResp, err := decodeBackendResponse(resp.Header.Get("Content-Type"), limited, strconv.Itoa(id))
	if err != nil {
		return nil, fmt.Errorf("backend %q decode: %w", b.cfg.ID, err)
	}
	return rpcResp, nil
}

// decodeBackendResponse parses a backend's JSON-RPC reply from either a single
// JSON body (application/json) or an SSE stream (text/event-stream). For SSE it
// reads the stream incrementally — joining a multi-line event's `data:` fields
// with "\n" per the SSE spec — and returns the FIRST event that parses as the
// JSON-RPC response for this request (matching id, or carrying a result/error),
// so the caller can stop reading (and close) without waiting for stream close.
func decodeBackendResponse(contentType string, r io.Reader, wantID string) (*JSONRPCResponse, error) {
	if !strings.Contains(strings.ToLower(contentType), "text/event-stream") {
		body, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		var rpcResp JSONRPCResponse
		if err := json.Unmarshal(body, &rpcResp); err != nil {
			return nil, err
		}
		return &rpcResp, nil
	}

	var dataLines []string
	flush := func() *JSONRPCResponse {
		if len(dataLines) == 0 {
			return nil
		}
		payload := strings.Join(dataLines, "\n")
		dataLines = nil
		var rpcResp JSONRPCResponse
		if json.Unmarshal([]byte(payload), &rpcResp) != nil {
			return nil
		}
		if string(rpcResp.ID) == wantID || rpcResp.Result != nil || rpcResp.Error != nil {
			return &rpcResp
		}
		return nil
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), int(maxDecideResponseBytes))
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "": // event boundary — dispatch
			if rr := flush(); rr != nil {
				return rr, nil // first matching event; caller closes the body
			}
		case strings.HasPrefix(line, "data:"):
			dataLines = append(dataLines, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
		// other SSE fields (event:, id:, retry:, comments) are ignored
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read SSE stream: %w", err)
	}
	if rr := flush(); rr != nil { // final event with no trailing blank line
		return rr, nil
	}
	return nil, fmt.Errorf("no JSON-RPC response found in SSE stream")
}

func (b *httpBackend) Close() error { return nil }

// mustRaw marshals params to json.RawMessage; on the impossible marshal error
// it returns an empty object so a malformed param never crashes the proxy.
func mustRaw(v interface{}) json.RawMessage {
	if v == nil {
		return nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return data
}
