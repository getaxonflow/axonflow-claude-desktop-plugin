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
// X-Axonflow-Client: mcp-proxy/<proxyVersion>, that the value is derived from
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
	if want := "mcp-proxy/" + proxyVersion; *got != want {
		t.Errorf("decide X-Axonflow-Client = %q, want %q", *got, want)
	}
}

func TestCheckOutput_EmitsClientVersionHeader(t *testing.T) {
	url, got := captureClientHeader(t, `{"allowed":true}`)
	c := NewCheckOutputClient(Config{Endpoint: url, ClientID: "org", ClientSecret: "s", Timeout: time.Second})
	if _, err := c.CheckOutput(context.Background(), "hello", ""); err != nil {
		t.Fatalf("CheckOutput: %v", err)
	}
	if want := "mcp-proxy/" + proxyVersion; *got != want {
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
// parser (ParseClient: last-"/" split) and the enterprise capture's
// validation expect: exactly "mcp-proxy/<semver>". A rename or a malformed
// version constant would silently land in the engine's drop bucket.
func TestClientVersionHeaderValue_Shape(t *testing.T) {
	shape := regexp.MustCompile(`^mcp-proxy/[0-9]+\.[0-9]+\.[0-9]+([0-9A-Za-z.+-]*)$`)
	if !shape.MatchString(axonflowClientValue) {
		t.Fatalf("axonflowClientValue %q does not match mcp-proxy/<semver>", axonflowClientValue)
	}
}
