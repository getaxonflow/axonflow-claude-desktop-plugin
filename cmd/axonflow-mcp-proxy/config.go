// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config is the fully-resolved proxy configuration. It is assembled from
// environment variables (the .mcpb manifest maps Claude Desktop's user_config
// fields onto these env vars) plus a backend-server map supplied either inline
// as JSON (AXONFLOW_BACKENDS) or via a config file (AXONFLOW_BACKENDS_FILE).
type Config struct {
	// AxonFlow Decision Mode (PDP) connection.
	Endpoint       string        // AXONFLOW_ENDPOINT, e.g. https://app.getaxonflow.com:8090
	ClientID       string        // AXONFLOW_CLIENT_ID (X-Client-Id)
	ClientSecret   string        // AXONFLOW_CLIENT_SECRET (X-Client-Secret)
	UserToken      string        // AXONFLOW_USER_TOKEN (enterprise JWT, optional)
	TenantID       string        // AXONFLOW_TENANT_ID
	OrgID          string        // AXONFLOW_ORG_ID
	GatewayID      string        // caller_identity.gateway_id — defaults to claude_desktop.<host>
	Timeout        time.Duration // AXONFLOW_DECIDE_TIMEOUT (decide call timeout)
	BackendTimeout time.Duration // AXONFLOW_BACKEND_TIMEOUT (per tools/call forward timeout)

	// Enforcement posture. FailOpen is the deliberate opt-in escape hatch; the
	// default is fail-CLOSED (PDP unreachable → block) because this fronts a
	// fintech's tool surface (BukuWarung). Opt in only with eyes open.
	FailOpen bool // AXONFLOW_FAIL_MODE=open

	// Identity stamped onto every Layer-1 audit row + forwarded to the PDP in
	// the decision context map (BukuWarung Layer-2 headers).
	LeaderEmail string // AXONFLOW_LEADER_EMAIL — the Desktop user
	AIAgent     string // AXONFLOW_AI_AGENT — defaults to "claude-desktop"
	SessionID   string // generated per process unless AXONFLOW_SESSION_ID is set

	// Layer-1 audit sink. Empty → audit to stderr only (still structured JSON).
	AuditLogPath string // AXONFLOW_AUDIT_LOG

	// Backend MCP servers this proxy fronts. At least one is required.
	Backends []BackendConfig
}

// BackendConfig describes one backend MCP server the proxy launches/connects
// to and re-exposes through itself. Exactly one transport is configured:
//   - Command set  → stdio transport (proxy launches the process)
//   - URL set      → http transport  (proxy POSTs JSON-RPC to the URL)
type BackendConfig struct {
	// ID is a stable, unique, slug-safe identifier. When the proxy fronts more
	// than one backend it namespaces re-exposed tool names as "<id>__<tool>"
	// to guarantee uniqueness; with a single backend tool names pass through
	// unprefixed (the per-server packaging mode — same binary, one backend).
	ID string `json:"id"`

	// stdio transport.
	Command string            `json:"command,omitempty"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`

	// http transport.
	URL string `json:"url,omitempty"`
}

// defaultBackendTimeout bounds a single backend tools/call forward when
// AXONFLOW_BACKEND_TIMEOUT is unset, so a hung backend can't wedge a tool call.
const defaultBackendTimeout = 30 * time.Second

// slugRE bounds backend IDs to MCP-tool-name-safe characters so the namespaced
// "<id>__<tool>" form is itself a valid tool name (clients constrain tool
// names to [A-Za-z0-9_-]).
var slugRE = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

func (b BackendConfig) transport() string {
	if strings.TrimSpace(b.Command) != "" {
		return "stdio"
	}
	if strings.TrimSpace(b.URL) != "" {
		return "http"
	}
	return ""
}

// validate enforces the single-transport + slug-safe-ID invariants. Returning
// an error here (rather than degrading silently) means a misconfigured backend
// map stops the proxy at boot with a clear message instead of fronting nothing.
func (b BackendConfig) validate() error {
	if strings.TrimSpace(b.ID) == "" {
		return fmt.Errorf("backend is missing required field \"id\"")
	}
	if !slugRE.MatchString(b.ID) {
		return fmt.Errorf("backend id %q must match %s", b.ID, slugRE.String())
	}
	switch b.transport() {
	case "":
		return fmt.Errorf("backend %q must set either \"command\" (stdio) or \"url\" (http)", b.ID)
	case "stdio":
		if strings.TrimSpace(b.URL) != "" {
			return fmt.Errorf("backend %q sets both \"command\" and \"url\"; choose one transport", b.ID)
		}
	case "http":
		if len(b.Args) > 0 || len(b.Env) > 0 {
			return fmt.Errorf("backend %q is http (\"url\") but also sets stdio-only \"args\"/\"env\"", b.ID)
		}
	}
	return nil
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// LoadConfig assembles the proxy configuration from the environment. It returns
// an error (rather than a partially-populated Config) when a required field is
// missing or the backend map is unparseable/empty — fail-fast at boot.
func LoadConfig() (Config, error) {
	cfg := Config{
		Endpoint:     envOr("AXONFLOW_ENDPOINT", "http://localhost:8080"),
		ClientID:     envOr("AXONFLOW_CLIENT_ID", "claude-desktop-proxy"),
		ClientSecret: os.Getenv("AXONFLOW_CLIENT_SECRET"),
		UserToken:    os.Getenv("AXONFLOW_USER_TOKEN"),
		TenantID:     os.Getenv("AXONFLOW_TENANT_ID"),
		OrgID:        os.Getenv("AXONFLOW_ORG_ID"),
		FailOpen:     strings.EqualFold(envOr("AXONFLOW_FAIL_MODE", "closed"), "open"),
		LeaderEmail:  envOr("AXONFLOW_LEADER_EMAIL", "unknown@bukuwarung.local"),
		AIAgent:      envOr("AXONFLOW_AI_AGENT", "claude-desktop"),
		AuditLogPath: os.Getenv("AXONFLOW_AUDIT_LOG"),
	}

	timeout, err := time.ParseDuration(envOr("AXONFLOW_DECIDE_TIMEOUT", "10s"))
	if err != nil || timeout <= 0 {
		return Config{}, fmt.Errorf("invalid AXONFLOW_DECIDE_TIMEOUT %q: %w", os.Getenv("AXONFLOW_DECIDE_TIMEOUT"), err)
	}
	cfg.Timeout = timeout

	backendTimeout, err := time.ParseDuration(envOr("AXONFLOW_BACKEND_TIMEOUT", defaultBackendTimeout.String()))
	if err != nil || backendTimeout <= 0 {
		return Config{}, fmt.Errorf("invalid AXONFLOW_BACKEND_TIMEOUT %q: %w", os.Getenv("AXONFLOW_BACKEND_TIMEOUT"), err)
	}
	cfg.BackendTimeout = backendTimeout

	// gateway_id distinguishes Claude Desktop traffic in the AxonFlow audit
	// trail. Default to claude_desktop.<hostname> so a fleet of 120 desktops is
	// attributable per machine without per-user config; an explicit override
	// wins (e.g. claude_desktop.mac-fleet).
	cfg.GatewayID = envOr("AXONFLOW_GATEWAY_ID", defaultGatewayID())

	cfg.SessionID = envOr("AXONFLOW_SESSION_ID", newSessionID())

	backends, err := loadBackends()
	if err != nil {
		return Config{}, err
	}
	if len(backends) == 0 {
		return Config{}, fmt.Errorf("no backend MCP servers configured: set AXONFLOW_BACKENDS (inline JSON) or AXONFLOW_BACKENDS_FILE")
	}
	seen := map[string]bool{}
	for i := range backends {
		if err := backends[i].validate(); err != nil {
			return Config{}, err
		}
		if seen[backends[i].ID] {
			return Config{}, fmt.Errorf("duplicate backend id %q", backends[i].ID)
		}
		seen[backends[i].ID] = true
	}
	cfg.Backends = backends
	return cfg, nil
}

// loadBackends reads the backend map from AXONFLOW_BACKENDS_FILE (a path) or,
// failing that, AXONFLOW_BACKENDS (inline JSON). Both decode the same array
// shape: [{"id":"crm","command":"node",...}, {"id":"bq","url":"http://..."}].
func loadBackends() ([]BackendConfig, error) {
	if path := strings.TrimSpace(os.Getenv("AXONFLOW_BACKENDS_FILE")); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read AXONFLOW_BACKENDS_FILE %q: %w", path, err)
		}
		return parseBackends(data)
	}
	if inline := strings.TrimSpace(os.Getenv("AXONFLOW_BACKENDS")); inline != "" {
		return parseBackends([]byte(inline))
	}
	return nil, nil
}

// parseBackends decodes the backend array. It accepts either a bare array or a
// {"backends":[...]} wrapper so a hand-written config file can be either shape.
func parseBackends(data []byte) ([]BackendConfig, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "{") {
		var wrapper struct {
			Backends []BackendConfig `json:"backends"`
		}
		if err := json.Unmarshal(data, &wrapper); err != nil {
			return nil, fmt.Errorf("parse backends object: %w", err)
		}
		return wrapper.Backends, nil
	}
	var arr []BackendConfig
	if err := json.Unmarshal(data, &arr); err != nil {
		return nil, fmt.Errorf("parse backends array: %w", err)
	}
	return arr, nil
}
