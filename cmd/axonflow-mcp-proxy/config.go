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
	ClientID       string        // AXONFLOW_CLIENT_ID (HTTP Basic username; enterprise = license org id)
	ClientSecret   string        // AXONFLOW_CLIENT_SECRET (HTTP Basic password; enterprise = license key)
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

	// RedactResponses controls when the response-governance engine (check-output)
	// runs over a forwarded tool response. The DEFAULT is "always" (default-on):
	// every tool response is sent to the engine before it reaches Claude's
	// context, regardless of whether the PDP attached a redact_pii obligation —
	// because the agent never sees the response, so governing it is
	// unconditionally the proxy's job (the §4.3 control). "on-obligation" restores
	// the legacy obligation-gated behaviour (scan only on a redact_pii obligation
	// or a fail-open forward); "off" disables the response-governance call
	// ENTIRELY — an explicit opt-out footgun that turns off not just PII redaction
	// but also response-side hard-blocks (SQLi / exfiltration) the engine performs,
	// so PII in responses then flows straight to the context window. (Request-plane
	// decide governance is unaffected by this setting.)
	RedactResponses string // AXONFLOW_REDACT_RESPONSES=always|on-obligation|off (default always)

	// PEPAudience opts this proxy into the ADR-065 capability handshake
	// (axonflow-enterprise#3763) and is the audience a decision proof should be
	// bound to.
	//
	// SET AS `AXONFLOW_PEP_AUDIENCE`. Both names are load bearing in different
	// places: the environment variable is what an operator sets, the config
	// field is what a reader of this code finds, and a brief naming only one
	// sends the other party searching for a name that does not appear.
	//
	// EMPTY IS THE DEFAULT AND SENDS NO HEADER, which leaves the proxy behaving
	// byte for byte as it did before the handshake existed. It is opt-in
	// because on an ENTERPRISE deployment the transition it gates is
	// ALLOW -> DENY: a proxy running with AXONFLOW_REDACT_RESPONSES=off
	// honestly declares that it discharges nothing, and the platform then
	// denies a request carrying a mandatory redaction instead of handing over
	// content this proxy was never going to redact. That is the posture an
	// operator almost certainly wants, and it is still a change in what callers
	// see, so it is stated on a knob rather than discovered in production.
	//
	// On a COMMUNITY deployment nothing changes at all: the capability deny is
	// physically absent from that build, so the declaration is read, bound and
	// counted, and acted on by nothing.
	//
	// Same variable name and same semantics as the gateway adapters' knob,
	// deliberately: one contract across the fleet, no per-client dialects.
	PEPAudience string // AXONFLOW_PEP_AUDIENCE — empty → no handshake presented

	// PEPHandshake is the ENCODED header value, DERIVED from PEPAudience and
	// RedactResponses by buildPEPHandshake at the end of loadConfig. Empty when
	// no audience is configured, and every call site omits the header then.
	//
	// Derived once and stored rather than built per request, and stored HERE
	// rather than on each client, because the two governed call paths
	// (decide.go, checkoutput.go) must present the SAME declaration: they are
	// one enforcement point, and a document that differed between them would be
	// a per-call-site dialect the platform would attribute to a single PEP.
	PEPHandshake string

	// Identity stamped onto every Layer-1 audit row + forwarded to the PDP in
	// the decision context map (Layer-2 audit headers).
	LeaderEmail string // AXONFLOW_LEADER_EMAIL — the Desktop user (empty → omitted)
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

// Response-redaction modes (AXONFLOW_REDACT_RESPONSES). The default is
// redactAlways: the proxy is the only thing that ever sees a tool response, so
// it scans every one for PII by default rather than trusting the PDP to flag it.
const (
	redactAlways       = "always"        // default: scan every response
	redactOnObligation = "on-obligation" // legacy: scan only on obligation / fail-open
	redactOff          = "off"           // explicit opt-out (footgun: disables ALL response-plane governance)
)

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
		// Empty by default (no sentinel): an unconfigured proxy sends NO
		// X-User-Email header, so platform audit rows carry the validated
		// identity (license org, or the AXONFLOW_USER_TOKEN user when set)
		// instead of a bogus stamped value (#2754). Operators
		// set AXONFLOW_LEADER_EMAIL to the real Desktop user; the platform
		// attributes it to audit_logs.user_email only when its agent runs with
		// AXONFLOW_TRUST_IDENTITY_HEADERS=true (axonflow-enterprise#2896,
		// platform >= 9.9.0) — see decide.go / checkoutput.go.
		LeaderEmail:  envOr("AXONFLOW_LEADER_EMAIL", ""),
		AIAgent:      envOr("AXONFLOW_AI_AGENT", "claude-desktop"),
		AuditLogPath: os.Getenv("AXONFLOW_AUDIT_LOG"),
	}

	// Response redaction mode. Default-on ("always"): the proxy scans every tool
	// response for PII before it reaches Claude's context, because no other
	// component sees the response. An unknown value is rejected at boot rather
	// than silently defaulting (a typo'd "alway" must not quietly disable a
	// compliance control).
	cfg.RedactResponses = strings.ToLower(envOr("AXONFLOW_REDACT_RESPONSES", redactAlways))
	// Accept the underscore spelling as an alias for the canonical hyphenated
	// value so "on_obligation" and "on-obligation" both resolve identically.
	if cfg.RedactResponses == "on_obligation" {
		cfg.RedactResponses = redactOnObligation
	}
	switch cfg.RedactResponses {
	case redactAlways, redactOnObligation, redactOff:
	default:
		return Config{}, fmt.Errorf("invalid AXONFLOW_REDACT_RESPONSES %q: want %q, %q, or %q",
			cfg.RedactResponses, redactAlways, redactOnObligation, redactOff)
	}

	// ADR-065 capability handshake. Empty (the default) presents no header.
	// The VALUE is validated in buildPEPHandshake, which is called at
	// construction so a malformed audience refuses to start rather than
	// 400-ing every governed call in production.
	cfg.PEPAudience = envOr("AXONFLOW_PEP_AUDIENCE", "")

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

	// ADR-065 capability handshake, rendered ONCE for the whole process.
	//
	// LAST, because it reads RedactResponses: what this proxy can honestly
	// declare depends on whether it will call the fulfillment endpoint at all,
	// and that is decided above. Building it earlier would declare a capability
	// against a config value not yet resolved.
	//
	// A failure here REFUSES TO START. A malformed audience that quietly
	// disabled the handshake would leave an operator believing a control was in
	// force when it was not, which is worse than not starting.
	handshake, err := buildPEPHandshake(cfg)
	if err != nil {
		return Config{}, err
	}
	cfg.PEPHandshake = handshake

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
