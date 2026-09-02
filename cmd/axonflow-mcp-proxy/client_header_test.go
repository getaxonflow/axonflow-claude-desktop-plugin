// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
	"time"
)

// Version identifier on the proxy's platform-bound HTTP calls (#2860). The
// proxy historically carried proxyVersion only inside the MCP handshake
// (clientInfo/serverInfo), so the engine had zero visibility into which
// desktop-proxy versions are deployed. These tests pin that BOTH governed
// calls — decide and check-output — now emit
// X-Axonflow-Client: claude-desktop-plugin/<proxyVersion>, that the value is derived from
// the single proxyVersion source, and that it is sent unconditionally (it is
// telemetry, not identity — there is no omit branch).

// captureClientHeader stands up an httptest server recording the last
// request's X-Axonflow-Client and returns a minimal valid JSON body.
func captureClientHeader(t *testing.T, body string) (url string, got *string) {
	t.Helper()
	var v string
	got = &v
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v = r.Header.Get("X-Axonflow-Client")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, got
}

func TestDecide_EmitsClientVersionHeader(t *testing.T) {
	url, got := captureClientHeader(t, `{"verdict":"allow"}`)
	c := NewDecideClient(Config{Endpoint: url, ClientID: "org", ClientSecret: "s", Timeout: time.Second})
	if _, _, err := c.Decide(context.Background(), DecideRequest{Stage: "tool"}, ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if want := "claude-desktop-plugin/" + proxyVersion; *got != want {
		t.Errorf("decide X-Axonflow-Client = %q, want %q", *got, want)
	}
}

func TestCheckOutput_EmitsClientVersionHeader(t *testing.T) {
	url, got := captureClientHeader(t, `{"allowed":true}`)
	c := NewCheckOutputClient(Config{Endpoint: url, ClientID: "org", ClientSecret: "s", Timeout: time.Second})
	if _, err := c.CheckOutput(context.Background(), "hello", ""); err != nil {
		t.Fatalf("CheckOutput: %v", err)
	}
	if want := "claude-desktop-plugin/" + proxyVersion; *got != want {
		t.Errorf("check-output X-Axonflow-Client = %q, want %q", *got, want)
	}
}

// TestClientVersionHeader_SentWithEmptyIdentityConfig pins the "always sent"
// contract: unlike X-User-Email / X-Session-Id (omitted when unconfigured),
// the version identifier has no omit branch — a fleet-default install with no
// leader email still reports its version.
func TestClientVersionHeader_SentWithEmptyIdentityConfig(t *testing.T) {
	url, got := captureClientHeader(t, `{"verdict":"allow"}`)
	c := NewDecideClient(Config{Endpoint: url, ClientID: "org", ClientSecret: "", LeaderEmail: "", SessionID: "", Timeout: time.Second})
	if _, _, err := c.Decide(context.Background(), DecideRequest{Stage: "tool"}, ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if *got == "" {
		t.Errorf("X-Axonflow-Client must be sent even with an empty identity config")
	}
}

// TestClientVersionHeaderValue_Shape guards the wire format the engine-side
// parser (ParseClient: last-"/" split) and the enterprise capture's validation
// expect: exactly "claude-desktop-plugin/<semver>". A malformed version
// constant would silently land in the engine's drop bucket.
//
// The id itself is pinned here rather than left to the constant, and that is
// the point: an id the server's vocabulary does not know is dropped SILENTLY,
// so a rename must be a deliberate edit to this line paired with the
// server-side allowlist, never a quiet drift. This id was "mcp-proxy" through
// 0.3.2; the enterprise validator keeps accepting that value for one release
// so proxies already in the field are not dropped mid-upgrade.
func TestClientVersionHeaderValue_Shape(t *testing.T) {
	shape := regexp.MustCompile(`^claude-desktop-plugin/[0-9]+\.[0-9]+\.[0-9]+([0-9A-Za-z.+-]*)$`)
	if !shape.MatchString(axonflowClientValue) {
		t.Fatalf("axonflowClientValue %q does not match claude-desktop-plugin/<semver>", axonflowClientValue)
	}
}
