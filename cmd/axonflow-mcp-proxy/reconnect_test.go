// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

// newStdioDieBackend returns a backend whose child process exits immediately
// (before completing the handshake) on every spawn — a backend that is
// permanently down. Used to exercise the bounded-backoff / stays-down path.
func newStdioDieBackend() *stdioBackend {
	return newStdioBackend(BackendConfig{
		ID:      "dead",
		Command: os.Args[0],
		Env:     map[string]string{"PROXY_TEST_STDIO_DIE": "1"},
	})
}

// currentConn reads the backend's live connection under its lock.
func currentConn(b *stdioBackend) *stdioConn {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conn
}

// waitDead polls until the connection's reader goroutine has observed the
// process exit (or the deadline elapses).
func waitDead(t *testing.T, c *stdioConn) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c == nil || !c.alive() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("connection did not become dead within deadline")
}

// TestStdioBackend_ReconnectsAfterBackendRestart is the core DoD case: a backend
// MCP server restarted out-of-band (here: its process is killed between calls)
// must be transparently reconnected on the NEXT call — no Claude restart, no
// dead-session 404.
func TestStdioBackend_ReconnectsAfterBackendRestart(t *testing.T) {
	b := newStdioStubBackend()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := b.Initialize(ctx); err != nil {
		t.Fatalf("initialize: %v", err)
	}
	if _, err := b.CallTool(ctx, "echo", map[string]interface{}{"x": "1"}, ""); err != nil {
		t.Fatalf("first call: %v", err)
	}

	// Simulate the operator restarting the backend: kill the current process.
	old := currentConn(b)
	if old == nil || old.cmd == nil || old.cmd.Process == nil {
		t.Fatal("no live connection to kill")
	}
	_ = old.cmd.Process.Kill()
	waitDead(t, old)

	// The next call must reconnect transparently and succeed.
	result, err := b.CallTool(ctx, "echo", map[string]interface{}{"x": "2"}, "")
	if err != nil {
		t.Fatalf("call after restart should reconnect and succeed, got: %v", err)
	}
	if !strings.Contains(string(result), `\"x\"`) {
		t.Fatalf("reconnected call lost args: %s", string(result))
	}
	// It must be a genuinely fresh connection, not the dead one.
	fresh := currentConn(b)
	if fresh == nil || fresh == old {
		t.Fatalf("expected a fresh connection after reconnect, got %p (old %p)", fresh, old)
	}
	if !fresh.alive() {
		t.Fatalf("reconnected connection is not alive")
	}
}

// TestStdioBackend_ReconnectsDuringInFlightCall covers the harder timing: the
// backend dies WHILE a tools/call is in flight. The call sees the dropped
// session, reconnects, and retries once on the fresh process — the caller still
// gets a successful result.
func TestStdioBackend_ReconnectsDuringInFlightCall(t *testing.T) {
	b := newStdioStubBackend()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := b.Initialize(ctx); err != nil {
		t.Fatalf("initialize: %v", err)
	}

	type res struct {
		out json.RawMessage
		err error
	}
	done := make(chan res, 1)
	go func() {
		out, err := b.CallTool(ctx, "slow", map[string]interface{}{"k": "v"}, "")
		done <- res{out, err}
	}()

	// Let the "slow" request reach the backend (it sleeps 250ms), then kill the
	// process mid-flight.
	time.Sleep(60 * time.Millisecond)
	old := currentConn(b)
	if old == nil || old.cmd == nil || old.cmd.Process == nil {
		t.Fatal("no live connection to kill")
	}
	_ = old.cmd.Process.Kill()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("in-flight call should reconnect+retry and succeed, got: %v", r.err)
		}
		if !strings.Contains(string(r.out), `\"k\"`) {
			t.Fatalf("retried call lost args: %s", string(r.out))
		}
	case <-time.After(8 * time.Second):
		t.Fatal("in-flight reconnect call did not complete")
	}
	if currentConn(b) == old {
		t.Fatal("expected a fresh connection after in-flight reconnect")
	}
}

// fakeClock is a manually-advanced clock for deterministic backoff testing.
type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time      { return f.t }
func (f *fakeClock) add(d time.Duration) { f.t = f.t.Add(d) }

// TestStdioBackend_StaysDown_BoundedBackoffCleanError proves the proxy does NOT
// busy-respawn a backend that's genuinely down: a (re)connect attempt inside the
// backoff window returns a clean, retryable backendUnavailableError WITHOUT
// spawning, the backoff grows exponentially between attempts, and every failure
// is the typed unavailable error (never a raw dead-pipe error).
func TestStdioBackend_StaysDown_BoundedBackoffCleanError(t *testing.T) {
	b := newStdioDieBackend()
	defer b.Close()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	b.now = clk.now

	// Attempt 1 (clock T0): a spawn is attempted, the process dies, the handshake
	// fails. Error is a typed unavailable carrying the underlying cause; backoff
	// arms to reconnectBackoffBase.
	_, err := b.ensureConn()
	var ue *backendUnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("attempt 1: want *backendUnavailableError, got %T: %v", err, err)
	}
	if ue.cause == nil {
		t.Fatalf("attempt 1 (spawn attempted) should carry a cause, got %+v", ue)
	}
	if b.backoff != reconnectBackoffBase {
		t.Fatalf("attempt 1 backoff = %s, want %s", b.backoff, reconnectBackoffBase)
	}

	// Attempt 2, still inside the backoff window (clock unchanged): the gate must
	// short-circuit — a retryAfter error with NO spawn (cause == nil), and the
	// backoff must NOT have advanced.
	_, err = b.ensureConn()
	if !errors.As(err, &ue) {
		t.Fatalf("attempt 2: want *backendUnavailableError, got %T: %v", err, err)
	}
	if ue.cause != nil {
		t.Fatalf("attempt 2 was inside the backoff window and must NOT spawn (cause must be nil), got: %v", ue.cause)
	}
	if ue.retryAfter <= 0 {
		t.Fatalf("attempt 2 should report a positive retryAfter, got %s", ue.retryAfter)
	}
	if b.backoff != reconnectBackoffBase {
		t.Fatalf("attempt 2 must not advance backoff, got %s", b.backoff)
	}

	// Advance past the window: the next attempt spawns again (and fails again),
	// growing the backoff to 2× base.
	clk.add(reconnectBackoffBase + time.Millisecond)
	_, err = b.ensureConn()
	if !errors.As(err, &ue) || ue.cause == nil {
		t.Fatalf("attempt 3 (after window) should spawn and fail with a cause, got %T: %v", err, err)
	}
	if want := 2 * reconnectBackoffBase; b.backoff != want {
		t.Fatalf("attempt 3 backoff = %s, want %s (exponential growth)", b.backoff, want)
	}
}

// TestProxy_ReconnectAfterBackendRestart_StillGoverned wires a REAL stdio backend
// behind the full Proxy enforce pipeline. After the backend is restarted
// out-of-band, a tools/call must (a) still be governed — the decide PDP is
// consulted — and (b) reconnect and succeed. This is the end-to-end DoD: the
// reconnect window never forwards ungoverned, and a restart is transparent.
func TestProxy_ReconnectAfterBackendRestart_StillGoverned(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-rc", TraceID: strings.Repeat("a", 32)}

	be := newStdioStubBackend()
	p := newProxyWithBackend(t, d.server.URL, be)
	defer p.Close()

	// Warm path: first call succeeds and PDP is consulted once.
	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`1`), ToolCallParams{Name: "echo", Arguments: map[string]interface{}{"a": "1"}})
	if resp.Error != nil {
		t.Fatalf("first call error: %+v", resp.Error)
	}
	if d.calls.Load() != 1 {
		t.Fatalf("first call: decide consulted %d times, want 1", d.calls.Load())
	}

	// Restart the backend out-of-band.
	old := currentConn(be)
	_ = old.cmd.Process.Kill()
	waitDead(t, old)

	// Next call must be governed AND reconnect+succeed.
	resp = p.HandleToolsCall(context.Background(), json.RawMessage(`2`), ToolCallParams{Name: "echo", Arguments: map[string]interface{}{"a": "2"}})
	if resp.Error != nil {
		t.Fatalf("call after restart should reconnect and succeed, got error: %+v", resp.Error)
	}
	if d.calls.Load() != 2 {
		t.Fatalf("post-restart call must still consult decide (governed): calls=%d, want 2", d.calls.Load())
	}
	if !strings.Contains(string(resp.Result), `\"a\"`) {
		t.Fatalf("reconnected call lost args: %s", string(resp.Result))
	}
}

// TestProxy_BackendUnavailable_GovernedCleanError proves that when the backend is
// down (CallTool returns a backendUnavailableError after its own reconnect
// attempt failed), the proxy: (a) still consulted the PDP first — the call was
// governed, nothing forwarded ungoverned; (b) surfaces a clean, retryable error,
// not a forwarded result.
func TestProxy_BackendUnavailable_GovernedCleanError(t *testing.T) {
	d := newDecideStub()
	defer d.close()
	d.resp = DecideResponse{Verdict: verdictAllow, DecisionID: "dec-bu", TraceID: strings.Repeat("b", 32)}

	be := &fakeBackend{
		id:      "crm",
		tools:   []json.RawMessage{toolDescriptor("lookup")},
		callErr: &backendUnavailableError{id: "crm", retryAfter: 500 * time.Millisecond},
	}
	p := newTestProxy(t, d.server.URL, be)

	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`1`), ToolCallParams{Name: "lookup"})
	e := mustParseError(t, resp)
	if e.Code != codeInternalError {
		t.Fatalf("backend-unavailable code = %d, want %d", e.Code, codeInternalError)
	}
	if !strings.Contains(e.Message, "unavailable") || !strings.Contains(e.Message, "retry") {
		t.Fatalf("expected a clean retryable message, got %q", e.Message)
	}
	if resp.Result != nil {
		t.Fatalf("a down backend must not forward a result, got %s", string(resp.Result))
	}
	// The PDP WAS consulted: the call was governed even though the backend is down.
	if d.calls.Load() != 1 {
		t.Fatalf("backend-down call must still be governed (decide consulted): calls=%d, want 1", d.calls.Load())
	}
	if be.callCount.Load() != 1 {
		t.Fatalf("forward was attempted exactly once, got %d", be.callCount.Load())
	}
}

// newProxyWithBackend builds a Proxy around a single real Backend (not a
// fakeBackend) and aggregates it, so a test can exercise the full enforce →
// forward path against an actual stdio child process.
func newProxyWithBackend(t *testing.T, endpoint string, b Backend) *Proxy {
	t.Helper()
	cfg := Config{
		Endpoint:        endpoint,
		ClientID:        "test",
		TenantID:        "tenant-test",
		OrgID:           "org-test",
		GatewayID:       "claude_desktop.test",
		Timeout:         2 * time.Second,
		BackendTimeout:  5 * time.Second,
		LeaderEmail:     "leader@bukuwarung.test",
		AIAgent:         "claude-desktop",
		SessionID:       "sess-test",
		RedactResponses: redactOff, // isolate the reconnect path from response governance
	}
	p := &Proxy{
		cfg:         cfg,
		decide:      NewDecideClient(cfg),
		checkOutput: NewCheckOutputClient(cfg),
		audit:       newSilentAudit(),
		backends:    map[string]Backend{b.ID(): b},
		routes:      map[string]route{},
	}
	p.cfg.Backends = []BackendConfig{{ID: b.ID()}}
	p.backendOrder = []string{b.ID()}
	if err := p.Aggregate(context.Background()); err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	return p
}
