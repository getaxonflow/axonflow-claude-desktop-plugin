// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Per-developer + per-session identity on the Desktop proxy's platform-bound
// HTTP calls (issue #2753/#2754). The proxy historically forwarded the leader
// email only as the opaque x-leader-identity context key (→ policy_details
// JSONB), never as the first-class X-User-Email header the platform maps into
// audit_logs.user_email. These tests pin that both the decide and check-output
// calls now emit X-User-Email + X-Session-Id when configured, and omit them
// when empty (no blank header).

// captureHeaders stands up an httptest server that records the last request's
// X-User-Email / X-Session-Id and returns a minimal valid JSON body.
func captureHeaders(t *testing.T, body string) (url string, gotEmail, gotSession *string) {
	t.Helper()
	var email, session string
	gotEmail, gotSession = &email, &session
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		email = r.Header.Get("X-User-Email")
		session = r.Header.Get("X-Session-Id")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL, gotEmail, gotSession
}

func TestDecide_EmitsIdentityHeaders(t *testing.T) {
	url, gotEmail, gotSession := captureHeaders(t, `{"verdict":"allow"}`)
	c := NewDecideClient(Config{
		Endpoint: url, ClientID: "org", ClientSecret: "s",
		LeaderEmail: "alice@example.com", SessionID: "sess-desktop-1",
		Timeout: time.Second,
	})
	if _, _, err := c.Decide(context.Background(), DecideRequest{Stage: "tool"}, ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if *gotEmail != "alice@example.com" {
		t.Errorf("decide X-User-Email = %q, want alice@example.com", *gotEmail)
	}
	if *gotSession != "sess-desktop-1" {
		t.Errorf("decide X-Session-Id = %q, want sess-desktop-1", *gotSession)
	}
}

// TestDecide_OmitsIdentityHeadersWhenEmpty exercises the omit GUARD directly
// with a hand-built empty-identity Config. LoadConfig never produces
// SessionID=="" (it mints one), so this guard-level test is the only place the
// X-Session-Id omit branch is reachable — kept deliberately.
func TestDecide_OmitsIdentityHeadersWhenEmpty(t *testing.T) {
	url, gotEmail, gotSession := captureHeaders(t, `{"verdict":"allow"}`)
	c := NewDecideClient(Config{
		Endpoint: url, ClientID: "org", ClientSecret: "s",
		LeaderEmail: "", SessionID: "", Timeout: time.Second,
	})
	if _, _, err := c.Decide(context.Background(), DecideRequest{Stage: "tool"}, ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if *gotEmail != "" {
		t.Errorf("decide X-User-Email should be absent, got %q", *gotEmail)
	}
	if *gotSession != "" {
		t.Errorf("decide X-Session-Id should be absent, got %q", *gotSession)
	}
}

// TestLoadConfig_UnsetLeaderEmail_OmitsUserEmailHeader is the PROD-PATH test
// (master R3 M1): it drives the real LoadConfig with AXONFLOW_LEADER_EMAIL
// unset — the state a fleet-default install actually produces after the #2754
// H1 fix (default LeaderEmail "" instead of a sentinel). It asserts LoadConfig
// yields LeaderEmail=="" so both governed calls OMIT X-User-Email (letting the
// platform's neutral synthetic fallback engage), while X-Session-Id is still
// sent because LoadConfig always mints a SessionID.
func TestLoadConfig_UnsetLeaderEmail_OmitsUserEmailHeader(t *testing.T) {
	t.Setenv("AXONFLOW_LEADER_EMAIL", "") // envOr → "" default (H1)
	t.Setenv("AXONFLOW_BACKENDS_FILE", "")
	t.Setenv("AXONFLOW_BACKENDS", `[{"id":"crm","url":"http://localhost:9000"}]`)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.LeaderEmail != "" {
		t.Fatalf("LoadConfig LeaderEmail should default to empty (no sentinel), got %q", cfg.LeaderEmail)
	}
	if cfg.SessionID == "" {
		t.Fatalf("LoadConfig should always mint a SessionID")
	}

	// decide: X-User-Email omitted, X-Session-Id present (minted).
	dURL, dEmail, dSession := captureHeaders(t, `{"verdict":"allow"}`)
	cfg.Endpoint = dURL
	if _, _, err := NewDecideClient(cfg).Decide(context.Background(), DecideRequest{Stage: "tool"}, ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if *dEmail != "" {
		t.Errorf("prod-path decide X-User-Email should be absent (unconfigured leader), got %q", *dEmail)
	}
	if *dSession != cfg.SessionID {
		t.Errorf("prod-path decide X-Session-Id = %q, want minted %q", *dSession, cfg.SessionID)
	}

	// check-output: same contract.
	cURL, cEmail, cSession := captureHeaders(t, `{"allowed":true}`)
	cfg.Endpoint = cURL
	if _, err := NewCheckOutputClient(cfg).CheckOutput(context.Background(), "hello", ""); err != nil {
		t.Fatalf("CheckOutput: %v", err)
	}
	if *cEmail != "" {
		t.Errorf("prod-path check-output X-User-Email should be absent, got %q", *cEmail)
	}
	if *cSession != cfg.SessionID {
		t.Errorf("prod-path check-output X-Session-Id = %q, want minted %q", *cSession, cfg.SessionID)
	}
}

func TestCheckOutput_EmitsIdentityHeaders(t *testing.T) {
	url, gotEmail, gotSession := captureHeaders(t, `{"allowed":true}`)
	c := NewCheckOutputClient(Config{
		Endpoint: url, ClientID: "org", ClientSecret: "s",
		LeaderEmail: "carol@example.com", SessionID: "sess-desktop-2",
		Timeout: time.Second,
	})
	if _, err := c.CheckOutput(context.Background(), "hello", ""); err != nil {
		t.Fatalf("CheckOutput: %v", err)
	}
	if *gotEmail != "carol@example.com" {
		t.Errorf("check-output X-User-Email = %q, want carol@example.com", *gotEmail)
	}
	if *gotSession != "sess-desktop-2" {
		t.Errorf("check-output X-Session-Id = %q, want sess-desktop-2", *gotSession)
	}
}

func TestCheckOutput_OmitsIdentityHeadersWhenEmpty(t *testing.T) {
	url, gotEmail, gotSession := captureHeaders(t, `{"allowed":true}`)
	c := NewCheckOutputClient(Config{
		Endpoint: url, ClientID: "org", ClientSecret: "s",
		LeaderEmail: "", SessionID: "", Timeout: time.Second,
	})
	if _, err := c.CheckOutput(context.Background(), "hello", ""); err != nil {
		t.Fatalf("CheckOutput: %v", err)
	}
	if *gotEmail != "" {
		t.Errorf("check-output X-User-Email should be absent, got %q", *gotEmail)
	}
	if *gotSession != "" {
		t.Errorf("check-output X-Session-Id should be absent, got %q", *gotSession)
	}
}

// Guard: the x-leader-identity context key the SIEM joins on must still be
// present in the decide request body (we ADD the header, never drop the
// context entry). Verified via the enforce path which builds the Context map.
func TestDecideRequest_RetainsLeaderIdentityContext(t *testing.T) {
	var body DecideRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":"allow"}`))
	}))
	t.Cleanup(srv.Close)

	c := NewDecideClient(Config{Endpoint: srv.URL, ClientID: "org", ClientSecret: "s", Timeout: time.Second})
	req := DecideRequest{
		Stage:   "tool",
		Context: map[string]interface{}{"x-leader-identity": "alice@example.com"},
	}
	if _, _, err := c.Decide(context.Background(), req, ""); err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if body.Context["x-leader-identity"] != "alice@example.com" {
		t.Errorf("x-leader-identity context entry dropped: %v", body.Context)
	}
}
