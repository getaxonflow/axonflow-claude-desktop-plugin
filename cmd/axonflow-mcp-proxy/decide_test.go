// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func testDecideClient(endpoint string) *DecideClient {
	return NewDecideClient(Config{Endpoint: endpoint, ClientID: "t", ClientSecret: "s", Timeout: time.Second})
}

func TestDecide_AllowParsesResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The PDP authenticates from the Authorization: Basic header only — the
		// agent ignores any custom X-Client-* headers (see decide.go). Assert the
		// canonical Basic credential reaches the server and that the legacy
		// X-Client-Secret header is NOT used to carry the secret.
		if got, want := r.Header.Get("Authorization"), "Basic "+basicAuth("t", "s"); got != want {
			t.Errorf("Authorization header = %q, want %q", got, want)
		}
		if r.Header.Get("X-Client-Secret") != "" {
			t.Errorf("secret leaked via X-Client-Secret header: %q", r.Header.Get("X-Client-Secret"))
		}
		_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: "allow", DecisionID: "d1", TraceID: strings.Repeat("a", 32),
			Obligations: []DecisionObligation{{Type: "redact_pii"}}})
	}))
	defer srv.Close()

	resp, status, err := testDecideClient(srv.URL).Decide(context.Background(), DecideRequest{Stage: "tool", Query: "q"}, "")
	if err != nil || status != 200 {
		t.Fatalf("decide err=%v status=%d", err, status)
	}
	if resp.Verdict != "allow" || !resp.hasObligation("redact_pii") {
		t.Fatalf("unexpected resp %+v", resp)
	}
	if resp.hasObligation("nope") {
		t.Fatalf("false obligation match")
	}
}

// TestDecide_CommunityNoSecretNoAuthHeader asserts that with no client secret
// (community mode) the proxy sends NO Authorization header — community PDPs
// require no auth, and an empty-secret Basic header would be malformed.
func TestDecide_CommunityNoSecretNoAuthHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := r.Header.Get("Authorization"); h != "" {
			t.Errorf("community mode must not send Authorization, got %q", h)
		}
		_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: "allow", DecisionID: "d1"})
	}))
	defer srv.Close()
	c := NewDecideClient(Config{Endpoint: srv.URL, ClientID: "claude-desktop-proxy", Timeout: time.Second})
	_, status, err := c.Decide(context.Background(), DecideRequest{Stage: "tool", Query: "q"}, "")
	if err != nil || status != 200 {
		t.Fatalf("decide err=%v status=%d", err, status)
	}
}

// TestBasicAuth pins the exact base64(clientID:clientSecret) encoding the agent
// splits on the first ":" — a secret that itself contains ":" must round-trip.
func TestBasicAuth(t *testing.T) {
	if got, want := basicAuth("org", "AXON-abc.def"), "b3JnOkFYT04tYWJjLmRlZg=="; got != want {
		t.Fatalf("basicAuth = %q, want %q", got, want)
	}
	// A license key with a ':' must remain intact (agent uses SplitN(...,2)).
	raw, _ := base64.StdEncoding.DecodeString(basicAuth("org", "a:b:c"))
	if string(raw) != "org:a:b:c" {
		t.Fatalf("basicAuth lost data: %q", raw)
	}
}

func TestDecide_ClientError4xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad creds", http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, status, err := testDecideClient(srv.URL).Decide(context.Background(), DecideRequest{Stage: "tool", Query: "q"}, "")
	if status != 401 {
		t.Fatalf("status = %d, want 401", status)
	}
	if !isClientError(err) {
		t.Fatalf("expected clientError, got %v", err)
	}
}

func TestDecide_503PassesThrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(DecideResponse{Verdict: "deny", TraceID: strings.Repeat("b", 32)})
	}))
	defer srv.Close()
	resp, status, err := testDecideClient(srv.URL).Decide(context.Background(), DecideRequest{Stage: "tool", Query: "q"}, "")
	if err != nil || status != 503 || resp == nil {
		t.Fatalf("503 should return resp with no error: resp=%v status=%d err=%v", resp, status, err)
	}
}

func TestDecide_TransportError(t *testing.T) {
	_, _, err := testDecideClient("http://127.0.0.1:1").Decide(context.Background(), DecideRequest{Stage: "tool", Query: "q"}, "")
	if err == nil {
		t.Fatalf("expected transport error")
	}
	if isClientError(err) {
		t.Fatalf("transport error must not be a clientError")
	}
}

func TestBuildDecideQuery(t *testing.T) {
	if got := buildDecideQuery("lookup", nil); got != "tool_call: lookup" {
		t.Fatalf("no-args query = %q", got)
	}
	got := buildDecideQuery("lookup", map[string]interface{}{"id": "c1"})
	if !strings.Contains(got, "tool_call: lookup") || !strings.Contains(got, `"id":"c1"`) {
		t.Fatalf("args query = %q", got)
	}
}

func TestTraceparent(t *testing.T) {
	if got := traceparent("short"); got != "" {
		t.Fatalf("invalid trace id should yield empty traceparent, got %q", got)
	}
	tp := traceparent(strings.Repeat("a", 32))
	if !strings.HasPrefix(tp, "00-"+strings.Repeat("a", 32)+"-") || !strings.HasSuffix(tp, "-01") {
		t.Fatalf("traceparent malformed: %q", tp)
	}
	if traceparent(strings.Repeat("z", 32)) != "" {
		t.Fatalf("non-hex trace id should be rejected")
	}
}

func TestDefaultGatewayID(t *testing.T) {
	id := defaultGatewayID()
	if !strings.HasPrefix(id, "claude_desktop.") {
		t.Fatalf("gateway id = %q", id)
	}
}

func TestNewSessionID_Unique(t *testing.T) {
	a, b := newSessionID(), newSessionID()
	if a == b {
		t.Fatalf("session ids collided: %q", a)
	}
	if !strings.HasPrefix(a, "cd-") {
		t.Fatalf("session id prefix wrong: %q", a)
	}
}
