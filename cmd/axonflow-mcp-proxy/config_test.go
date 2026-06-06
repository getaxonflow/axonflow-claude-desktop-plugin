// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// withEnv sets env vars for the duration of a test and restores them after.
func withEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestLoadConfig_MinimalInlineBackends(t *testing.T) {
	withEnv(t, map[string]string{
		"AXONFLOW_ENDPOINT":  "https://app.example.com:8090",
		"AXONFLOW_TENANT_ID": "tenant-1",
		"AXONFLOW_BACKENDS":  `[{"id":"crm","command":"node","args":["server.js"]}]`,
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Endpoint != "https://app.example.com:8090" {
		t.Fatalf("endpoint = %q", cfg.Endpoint)
	}
	if len(cfg.Backends) != 1 || cfg.Backends[0].ID != "crm" {
		t.Fatalf("backends = %+v", cfg.Backends)
	}
	if cfg.FailOpen {
		t.Fatalf("default must be fail-closed")
	}
	if cfg.GatewayID == "" || cfg.GatewayID[:15] != "claude_desktop." {
		t.Fatalf("default gateway id wrong: %q", cfg.GatewayID)
	}
	if cfg.SessionID == "" {
		t.Fatalf("session id must be generated")
	}
}

func TestLoadConfig_FailOpenOptIn(t *testing.T) {
	withEnv(t, map[string]string{
		"AXONFLOW_FAIL_MODE": "open",
		"AXONFLOW_BACKENDS":  `[{"id":"a","url":"http://localhost:9000"}]`,
	})
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !cfg.FailOpen {
		t.Fatalf("AXONFLOW_FAIL_MODE=open should set FailOpen")
	}
}

func TestLoadConfig_NoBackends_Errors(t *testing.T) {
	// Ensure neither backend source is set.
	t.Setenv("AXONFLOW_BACKENDS", "")
	t.Setenv("AXONFLOW_BACKENDS_FILE", "")
	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error when no backends configured")
	}
}

func TestLoadConfig_BackendsFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "backends.json")
	if err := os.WriteFile(path, []byte(`{"backends":[{"id":"bq","url":"http://localhost:9000"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AXONFLOW_BACKENDS", "")
	t.Setenv("AXONFLOW_BACKENDS_FILE", path)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Backends) != 1 || cfg.Backends[0].ID != "bq" {
		t.Fatalf("file backends = %+v", cfg.Backends)
	}
}

func TestLoadConfig_DuplicateBackendID_Errors(t *testing.T) {
	t.Setenv("AXONFLOW_BACKENDS_FILE", "")
	t.Setenv("AXONFLOW_BACKENDS", `[{"id":"x","url":"http://a"},{"id":"x","url":"http://b"}]`)
	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected duplicate-id error")
	}
}

func TestLoadConfig_BadTimeout_Errors(t *testing.T) {
	t.Setenv("AXONFLOW_DECIDE_TIMEOUT", "not-a-duration")
	t.Setenv("AXONFLOW_BACKENDS", `[{"id":"x","url":"http://a"}]`)
	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected timeout parse error")
	}
}

func TestLoadConfig_RedactResponses_DefaultAndParsing(t *testing.T) {
	base := map[string]string{"AXONFLOW_BACKENDS": `[{"id":"x","url":"http://a"}]`, "AXONFLOW_BACKENDS_FILE": ""}

	// Default (unset) → always.
	withEnv(t, base)
	t.Setenv("AXONFLOW_REDACT_RESPONSES", "")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.RedactResponses != redactAlways {
		t.Fatalf("default RedactResponses = %q, want %q", cfg.RedactResponses, redactAlways)
	}

	// Each valid mode parses (case-insensitively).
	for in, want := range map[string]string{"always": redactAlways, "on-obligation": redactOnObligation, "off": redactOff, "OFF": redactOff} {
		t.Setenv("AXONFLOW_REDACT_RESPONSES", in)
		cfg, err := LoadConfig()
		if err != nil {
			t.Fatalf("LoadConfig(%q): %v", in, err)
		}
		if cfg.RedactResponses != want {
			t.Fatalf("RedactResponses(%q) = %q, want %q", in, cfg.RedactResponses, want)
		}
	}

	// An unknown value is rejected at boot, never silently ignored.
	t.Setenv("AXONFLOW_REDACT_RESPONSES", "alway")
	if _, err := LoadConfig(); err == nil {
		t.Fatalf("expected error on invalid AXONFLOW_REDACT_RESPONSES")
	}
}

// TestShouldRedact_Modes covers the decision matrix directly (every mode ×
// obligation present/absent × forced/not), independent of the HTTP path.
func TestShouldRedact_Modes(t *testing.T) {
	withObl := DecideResponse{Obligations: []DecisionObligation{{Type: "redact_pii"}}}
	noObl := DecideResponse{Obligations: []DecisionObligation{}}
	cases := []struct {
		mode   string
		dec    DecideResponse
		forced bool
		want   bool
	}{
		{redactAlways, noObl, false, true},         // clean request → still scan (the fix)
		{redactAlways, withObl, false, true},       // obligation → scan
		{redactAlways, noObl, true, true},          // forced → scan
		{redactOnObligation, noObl, false, false},  // legacy: no obligation → skip
		{redactOnObligation, withObl, false, true}, // legacy: obligation → scan
		{redactOnObligation, noObl, true, true},    // legacy: forced fail-open → scan
		{redactOff, withObl, false, false},         // off: never
		{redactOff, noObl, true, false},            // off: never, even forced
		{"", noObl, false, true},                   // unset/unexpected → fail safe (scan)
	}
	for _, c := range cases {
		p := &Proxy{cfg: Config{RedactResponses: c.mode}}
		if got := p.shouldRedact(c.dec, c.forced); got != c.want {
			t.Fatalf("shouldRedact(mode=%q, obl=%v, forced=%v) = %v, want %v",
				c.mode, c.dec.hasObligation("redact_pii"), c.forced, got, c.want)
		}
	}
}

func TestBackendConfig_Validate(t *testing.T) {
	cases := []struct {
		name    string
		b       BackendConfig
		wantErr bool
	}{
		{"ok stdio", BackendConfig{ID: "crm", Command: "node"}, false},
		{"ok http", BackendConfig{ID: "bq", URL: "http://x"}, false},
		{"missing id", BackendConfig{Command: "node"}, true},
		{"bad slug", BackendConfig{ID: "a b", Command: "node"}, true},
		{"no transport", BackendConfig{ID: "x"}, true},
		{"both transports", BackendConfig{ID: "x", Command: "node", URL: "http://x"}, true},
		{"http with stdio fields", BackendConfig{ID: "x", URL: "http://x", Env: map[string]string{"A": "b"}}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.b.validate()
			if (err != nil) != c.wantErr {
				t.Fatalf("validate(%+v) err=%v wantErr=%v", c.b, err, c.wantErr)
			}
		})
	}
}

func TestParseBackends_BareArrayAndObject(t *testing.T) {
	arr, err := parseBackends([]byte(`[{"id":"a","url":"http://a"}]`))
	if err != nil || len(arr) != 1 {
		t.Fatalf("array parse: %v %+v", err, arr)
	}
	obj, err := parseBackends([]byte(`{"backends":[{"id":"b","url":"http://b"}]}`))
	if err != nil || len(obj) != 1 {
		t.Fatalf("object parse: %v %+v", err, obj)
	}
	if _, err := parseBackends([]byte(`not json`)); err == nil {
		t.Fatalf("expected parse error on garbage")
	}
}
