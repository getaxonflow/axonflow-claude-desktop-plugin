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
	"time"
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

// reconnect tuning. A backend MCP server restarted out-of-band (an operator
// redeploy, a crash) drops its stdio session; the proxy re-spawns and
// re-handshakes it transparently on the next call. To avoid busy-respawning a
// backend that is genuinely down, consecutive failed (re)connects back off
// exponentially from reconnectBackoffBase up to reconnectBackoffMax — a call
// arriving inside the backoff window gets a fast, clean "unavailable" error
// instead of triggering another spawn. A successful connect resets the backoff.
const (
	reconnectBackoffBase = 500 * time.Millisecond
	reconnectBackoffMax  = 30 * time.Second
	// handshakeTimeout bounds a single spawn+initialize so a backend that starts
	// but never finishes the MCP handshake can't wedge the (mutex-held) reconnect.
	handshakeTimeout = 15 * time.Second
)

// backendUnavailableError is returned when the proxy cannot (re)establish a
// backend stdio session — either the backend is down and the call arrived inside
// the reconnect backoff window, or a fresh spawn/handshake just failed. It is a
// distinct, clean error type (not a bare dead-pipe / EOF error) so the proxy can
// surface a RETRYABLE failure to Claude rather than a hard dead-session: the next
// tools/call attempts the reconnect again once the backoff elapses.
type backendUnavailableError struct {
	id         string
	retryAfter time.Duration
	cause      error
}

func (e *backendUnavailableError) Error() string {
	if e.retryAfter > 0 {
		return fmt.Sprintf("backend %q is unavailable (restarting); retry in %s", e.id, e.retryAfter.Round(100*time.Millisecond))
	}
	if e.cause != nil {
		return fmt.Sprintf("backend %q is unavailable: %v", e.id, e.cause)
	}
	return fmt.Sprintf("backend %q is unavailable", e.id)
}

func (e *backendUnavailableError) Unwrap() error { return e.cause }

// stdioConn is ONE live connection to a backend stdio MCP server: a child
// process plus the reader goroutine that demultiplexes its responses. A backend
// restart kills the process, the reader hits EOF and marks this conn dead, and
// stdioBackend then spawns a fresh stdioConn. Each connection owns its own
// request-id space, pending map, and closed signal, so a stale conn can never
// deliver a response onto a fresh one.
type stdioConn struct {
	id     string // backend id, for log/error messages
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	writeM sync.Mutex // serializes line writes to the child's stdin

	idM     sync.Mutex
	nextID  int
	pending map[string]chan *JSONRPCResponse

	closed   chan struct{}
	deadOnce sync.Once
}

// stdioBackend fronts a backend stdio MCP server, transparently reconnecting a
// dropped session. The current live connection is held in conn (nil when none
// has been established or the last one died); mu serializes (re)connect so a
// burst of concurrent calls against a dead backend triggers exactly one respawn.
type stdioBackend struct {
	cfg BackendConfig

	mu        sync.Mutex // guards conn + backoff state; serializes (re)connect
	conn      *stdioConn
	backoff   time.Duration // current backoff after consecutive connect failures
	nextRetry time.Time     // earliest wall-clock time a (re)connect may be attempted

	// now is the clock, injectable so backoff behaviour is deterministic in tests.
	now func() time.Time
}

func newStdioBackend(c BackendConfig) *stdioBackend {
	return &stdioBackend{cfg: c, now: time.Now}
}

func (b *stdioBackend) ID() string { return b.cfg.ID }

// ---- connection lifecycle ----

// alive reports whether the connection's reader goroutine is still running (the
// child process has not exited).
func (c *stdioConn) alive() bool {
	select {
	case <-c.closed:
		return false
	default:
		return true
	}
}

// markDead closes the conn exactly once, unblocking every pending caller (each
// waits on c.closed and returns a "closed before responding" error). Idempotent
// so the reader goroutine and an explicit shutdown can both call it.
func (c *stdioConn) markDead() {
	c.deadOnce.Do(func() { close(c.closed) })
}

// shutdown kills the child process (best effort) and marks the conn dead. The
// reader goroutine reaps the process via cmd.Wait when stdout closes, so this
// does NOT Wait (avoiding a double-Wait race). Safe to call more than once.
func (c *stdioConn) shutdown() {
	if c.stdin != nil {
		_ = c.stdin.Close()
	}
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
	}
	c.markDead()
}

// readLoop demultiplexes backend responses to the pending channels until the
// child's stdout closes (process exit), then reaps the child and marks the conn
// dead so waiting callers unblock and the backend can be reconnected.
func (c *stdioConn) readLoop(stdout io.Reader) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), maxDecideResponseBytes)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var resp JSONRPCResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			logStderr("backend %q: undecodable line dropped: %v", c.id, err)
			continue
		}
		if len(resp.ID) == 0 || string(resp.ID) == "null" {
			// Server-initiated notification/request — out of scope for the
			// proxy's request/response use; log and drop.
			continue
		}
		key := string(resp.ID)
		c.idM.Lock()
		ch, ok := c.pending[key]
		if ok {
			delete(c.pending, key)
		}
		c.idM.Unlock()
		if ok {
			ch <- &resp
		}
	}
	// stdout closed → the backend process exited (crash, restart, or normal
	// exit). Reap it to avoid a zombie, then mark the conn dead so every pending
	// caller unblocks via the c.closed select branch. Unlike the old
	// degraded-until-Claude-restart contract, stdioBackend now establishes a
	// fresh connection on the next call (see ensureConn).
	if c.cmd != nil {
		_ = c.cmd.Wait()
	}
	c.markDead()
}

// call sends a JSON-RPC request on this connection and waits for the matching
// response, ctx cancellation, or the connection dropping (c.closed).
func (c *stdioConn) call(ctx context.Context, method string, params interface{}) (*JSONRPCResponse, error) {
	c.idM.Lock()
	c.nextID++
	id := c.nextID
	c.idM.Unlock()
	idRaw := json.RawMessage(strconv.Itoa(id))
	key := string(idRaw)

	ch := make(chan *JSONRPCResponse, 1)
	c.idM.Lock()
	c.pending[key] = ch
	c.idM.Unlock()

	if err := c.writeMessage(JSONRPCRequest{JSONRPC: "2.0", ID: idRaw, Method: method, Params: mustRaw(params)}); err != nil {
		c.idM.Lock()
		delete(c.pending, key)
		c.idM.Unlock()
		return nil, err
	}

	select {
	case <-ctx.Done():
		c.idM.Lock()
		delete(c.pending, key)
		c.idM.Unlock()
		return nil, ctx.Err()
	case <-c.closed:
		c.idM.Lock()
		delete(c.pending, key)
		c.idM.Unlock()
		return nil, fmt.Errorf("backend %q closed before responding", c.id)
	case resp := <-ch:
		return resp, nil
	}
}

// notify sends a JSON-RPC notification (no id, no response expected).
func (c *stdioConn) notify(method string, params interface{}) error {
	return c.writeMessage(JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: mustRaw(params)})
}

// writeMessage marshals one JSON-RPC message to a single newline-terminated
// line. The write mutex guarantees lines never interleave on the child's stdin.
func (c *stdioConn) writeMessage(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}
	data = append(data, '\n')
	c.writeM.Lock()
	defer c.writeM.Unlock()
	if _, err := c.stdin.Write(data); err != nil {
		return fmt.Errorf("write to backend %q: %w", c.id, err)
	}
	return nil
}

// initialize runs the MCP lifecycle handshake on a freshly-spawned connection:
// the initialize request followed by the notifications/initialized confirmation.
// A backend that has just (re)started must complete this before tools/* work, so
// reconnect re-runs it automatically.
func (c *stdioConn) initialize(ctx context.Context) error {
	resp, err := c.call(ctx, "initialize", map[string]interface{}{
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
	if err := c.notify("notifications/initialized", map[string]interface{}{}); err != nil {
		return fmt.Errorf("backend %q initialized notification: %w", c.id, err)
	}
	return nil
}

// ---- backend (re)connect orchestration ----

// spawn launches the child process and its reader + stderr goroutines, returning
// an un-initialized connection.
func (b *stdioBackend) spawn() (*stdioConn, error) {
	cmd := exec.Command(b.cfg.Command, b.cfg.Args...)
	// Inherit the proxy env and layer the backend's env on top so a backend can
	// receive its own credentials without leaking the proxy's.
	cmd.Env = os.Environ()
	for k, v := range b.cfg.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("backend %q stdin pipe: %w", b.cfg.ID, err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("backend %q stdout pipe: %w", b.cfg.ID, err)
	}
	// Forward the child's stderr to ours, prefixed, so backend logs are visible
	// without polluting the JSON-RPC stdout channel.
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("backend %q stderr pipe: %w", b.cfg.ID, err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("backend %q start %q: %w", b.cfg.ID, b.cfg.Command, err)
	}
	conn := &stdioConn{
		id:      b.cfg.ID,
		cmd:     cmd,
		stdin:   stdin,
		pending: map[string]chan *JSONRPCResponse{},
		closed:  make(chan struct{}),
	}
	go conn.readLoop(stdout)
	go forwardStderr(b.cfg.ID, stderr)
	return conn, nil
}

// connect spawns the backend and runs the handshake, returning a ready
// connection. The handshake is bounded by handshakeTimeout from a fresh context
// (not a caller's) so one caller cancelling can't poison the shared reconnect.
func (b *stdioBackend) connect() (*stdioConn, error) {
	conn, err := b.spawn()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	if err := conn.initialize(ctx); err != nil {
		conn.shutdown()
		return nil, err
	}
	return conn, nil
}

// ensureConn returns a live, initialized connection, (re)spawning the backend if
// the current connection is missing or dead. Concurrent callers serialize on mu
// so a dead backend triggers exactly one respawn. A (re)connect attempt arriving
// inside the backoff window returns a clean backendUnavailableError immediately
// instead of spawning; a successful connect resets the backoff.
func (b *stdioBackend) ensureConn() (*stdioConn, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.conn != nil && b.conn.alive() {
		return b.conn, nil
	}
	// Drop a dead connection before attempting a fresh one.
	if b.conn != nil {
		b.conn.shutdown()
		b.conn = nil
	}
	// Backoff gate: a recent failed connect means the backend is down — don't
	// hammer it. Surface a retryable error until the window elapses.
	if now := b.now(); now.Before(b.nextRetry) {
		return nil, &backendUnavailableError{id: b.cfg.ID, retryAfter: b.nextRetry.Sub(now)}
	}

	conn, err := b.connect()
	if err != nil {
		b.advanceBackoff()
		logStderr("backend %q (re)connect failed (backoff %s): %v", b.cfg.ID, b.backoff, err)
		return nil, &backendUnavailableError{id: b.cfg.ID, cause: err}
	}
	b.resetBackoff()
	b.conn = conn
	return conn, nil
}

// advanceBackoff grows the reconnect backoff (exponential, capped) and arms the
// next-retry gate. Called under b.mu after a failed connect.
func (b *stdioBackend) advanceBackoff() {
	switch {
	case b.backoff == 0:
		b.backoff = reconnectBackoffBase
	default:
		b.backoff *= 2
		if b.backoff > reconnectBackoffMax {
			b.backoff = reconnectBackoffMax
		}
	}
	b.nextRetry = b.now().Add(b.backoff)
}

// resetBackoff clears the backoff after a successful connect. Called under b.mu.
func (b *stdioBackend) resetBackoff() {
	b.backoff = 0
	b.nextRetry = time.Time{}
}

// invalidate force-drops a specific dead connection so the next ensureConn
// respawns, even if alive() has not flipped yet (e.g. a write failed before the
// reader goroutine observed EOF). No-op if conn has already been replaced.
func (b *stdioBackend) invalidate(dead *stdioConn) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn == dead {
		b.conn.shutdown()
		b.conn = nil
	}
}

// callWithReconnect issues one JSON-RPC call, transparently reconnecting and
// retrying ONCE if the connection had dropped (a backend restart). It does NOT
// retry on caller ctx cancellation/timeout (not a backend death) nor more than
// once (the backoff gate bounds repeated failures). Governance is unaffected:
// callWithReconnect runs only AFTER the proxy's decide verdict, so a reconnect
// can never forward an ungoverned call.
func (b *stdioBackend) callWithReconnect(ctx context.Context, method string, params interface{}) (*JSONRPCResponse, error) {
	conn, err := b.ensureConn()
	if err != nil {
		return nil, err
	}
	resp, err := conn.call(ctx, method, params)
	if err == nil {
		return resp, nil
	}
	// Caller cancelled/timed out — not a backend death; surface it as-is.
	if ctx.Err() != nil {
		return nil, err
	}
	// The connection dropped (EOF / closed / broken pipe). Re-establish it and
	// retry once so a backend restart is transparent to Claude.
	logStderr("backend %q call %s failed (%v) — reconnecting and retrying once", b.cfg.ID, method, err)
	b.invalidate(conn)
	conn, err = b.ensureConn()
	if err != nil {
		return nil, err
	}
	return conn.call(ctx, method, params)
}

func (b *stdioBackend) Initialize(context.Context) error {
	// Establish (and handshake) the first connection eagerly so Aggregate can
	// list tools. The handshake uses connect's own bounded context.
	_, err := b.ensureConn()
	return err
}

func (b *stdioBackend) ListTools(ctx context.Context) ([]json.RawMessage, error) {
	resp, err := b.callWithReconnect(ctx, "tools/list", map[string]interface{}{})
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
	resp, err := b.callWithReconnect(ctx, "tools/call", ToolCallParams{Name: name, Arguments: args})
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, &rpcError{Code: resp.Error.Code, Message: resp.Error.Message, Data: resp.Error.Data}
	}
	return resp.Result, nil
}

func (b *stdioBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		b.conn.shutdown()
		b.conn = nil
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

	sessM     sync.Mutex
	sessionID string // Mcp-Session-Id assigned by a stateful backend at initialize
}

func newHTTPBackend(c BackendConfig) *httpBackend {
	return &httpBackend{cfg: c, client: &http.Client{}}
}

func (b *httpBackend) ID() string { return b.cfg.ID }

func (b *httpBackend) getSession() string {
	b.sessM.Lock()
	defer b.sessM.Unlock()
	return b.sessionID
}

func (b *httpBackend) setSession(id string) {
	b.sessM.Lock()
	defer b.sessM.Unlock()
	b.sessionID = id
}

// Initialize runs the MCP lifecycle handshake against an HTTP backend. The MCP
// Streamable HTTP spec lets a server run STATEFUL: it returns an
// `Mcp-Session-Id` header on the initialize response and then 400s any later
// request that doesn't echo it (the official MCP SDK does this by default).
// post() captures that id and replays it on every subsequent request, and we
// send the `notifications/initialized` lifecycle notification here (matching
// the stdio backend). Stateless servers omit the header and are unaffected.
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
	// Best-effort lifecycle notification (carries the captured session id). A
	// server that doesn't require it returns 202/empty; a failure here must not
	// block tool aggregation.
	if err := b.postNotify(ctx, "notifications/initialized", map[string]interface{}{}); err != nil {
		logStderr("backend %q initialized notification (non-fatal): %v", b.cfg.ID, err)
	}
	return nil
}

// postNotify sends a JSON-RPC notification (no id, no response expected) to an
// HTTP backend, echoing the session id. Notifications get 202 Accepted (often
// with an empty body), so unlike post() it does not parse a JSON-RPC response.
func (b *httpBackend) postNotify(ctx context.Context, method string, params interface{}) error {
	reqBody, err := json.Marshal(JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: mustRaw(params)})
	if err != nil {
		return fmt.Errorf("marshal notification: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, b.cfg.URL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("create notification request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json, text/event-stream")
	if sid := b.getSession(); sid != "" {
		httpReq.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := b.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("post notification: %w", err)
	}
	// A notification expects no JSON-RPC response (servers return 202/empty).
	// Don't drain the body — a misbehaving server that holds the response
	// stream open could otherwise block aggregation (no client timeout); just
	// close it (the connection won't be pooled, which is fine for a one-shot).
	_ = resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notification returned HTTP %d", resp.StatusCode)
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
	// Echo the session id on every request after initialize. A stateful
	// Streamable-HTTP backend assigns it at initialize and 400s requests that
	// omit it; stateless backends never set one, so this is empty and harmless.
	if sid := b.getSession(); sid != "" {
		httpReq.Header.Set("Mcp-Session-Id", sid)
	}
	if traceparent != "" {
		httpReq.Header.Set("Traceparent", traceparent)
	}

	resp, err := b.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("backend %q post: %w", b.cfg.ID, err)
	}
	defer resp.Body.Close()

	// Capture the session id a stateful backend hands back (typically on the
	// initialize response) so subsequent requests can replay it.
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" && b.getSession() == "" {
		b.setSession(sid)
	}

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
