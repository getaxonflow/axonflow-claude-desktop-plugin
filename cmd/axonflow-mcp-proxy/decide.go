// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	maxDecideRequestBytes  = 1 << 20 // 1 MB request to the PDP
	maxDecideResponseBytes = 1 << 20 // 1 MB verdict body
)

// DecideRequest mirrors the platform contract at
// platform/agent/decision_handler.go (DecideRequest). The request JSON tags are
// identical to the platform struct so the proxy speaks the exact wire shape the
// PDP expects. (DecideResponse.ExpiresAt is received as a string — the platform
// emits a time.Time, which marshals to an RFC3339 string the proxy never
// re-parses; see that field's note.)
type DecideRequest struct {
	Stage          string                 `json:"stage"`
	CallerIdentity CallerIdentity         `json:"caller_identity"`
	Target         DecisionTarget         `json:"target"`
	Query          string                 `json:"query"`
	UserToken      string                 `json:"user_token,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
}

// CallerIdentity mirrors decision_handler.go:132 (DecisionCallerIdentity).
type CallerIdentity struct {
	GatewayID string `json:"gateway_id,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// DecisionTarget mirrors decision_handler.go:139.
type DecisionTarget struct {
	Type string `json:"type,omitempty"`
	Tool string `json:"tool,omitempty"`
}

// DecideResponse mirrors decision_handler.go:150 (DecideResponse). expires_at
// is read as a raw string — the proxy never re-parses it (the PDP owns the TTL
// semantics); we keep the field so the contract round-trips losslessly.
type DecideResponse struct {
	Verdict           string               `json:"verdict"`
	DecisionID        string               `json:"decision_id"`
	TraceID           string               `json:"trace_id"`
	Reasons           []string             `json:"reasons,omitempty"`
	Obligations       []DecisionObligation `json:"obligations"`
	EvaluatedPolicies []string             `json:"evaluated_policies"`
	Stage             string               `json:"stage,omitempty"`
	ExpiresAt         string               `json:"expires_at,omitempty"`
}

// DecisionObligation mirrors decision_handler.go:163.
type DecisionObligation struct {
	Type   string `json:"type"`
	Detail string `json:"detail,omitempty"`
}

// Verdict constants mirror platform/agent/decision_handler.go:62.
const (
	verdictAllow         = "allow"
	verdictDeny          = "deny"
	verdictNeedsApproval = "needs_approval"
)

// hasObligation reports whether the verdict carries an obligation of the given
// type (e.g. "redact_pii"). Case-insensitive on the type.
func (r DecideResponse) hasObligation(t string) bool {
	for _, o := range r.Obligations {
		if strings.EqualFold(o.Type, t) {
			return true
		}
	}
	return false
}

// clientError marks a 4xx from the PDP. Fail-open never applies to client
// errors — a 4xx means the proxy is misconfigured (bad credentials, bad
// request), not that the PDP is degraded, so forwarding anyway would be
// silently ungoverned. Mirrors the reference adapter's clientError.
type clientError struct {
	StatusCode int
	Body       string
}

func (e *clientError) Error() string {
	return fmt.Sprintf("decision API returned %d: %s", e.StatusCode, e.Body)
}

// DecideClient calls POST {endpoint}/api/v1/decide. It is the single, reused
// decide-client — the proxy never re-implements the verdict transport.
type DecideClient struct {
	cfg    Config
	client *http.Client
}

// NewDecideClient builds a DecideClient with a bounded HTTP timeout. The
// timeout is the circuit-breaker primitive on the request path: a hung PDP
// can never wedge a tools/call beyond cfg.Timeout, after which the configured
// fail posture (closed by default) decides the outcome.
func NewDecideClient(cfg Config) *DecideClient {
	return &DecideClient{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

// Decide calls the PDP and returns (response, httpStatus, error). The caller
// applies the fail posture; Decide itself takes no enforcement decision so the
// posture lives in exactly one place (proxy.enforce).
//
//   - transport/timeout error → (nil, 0, err)
//   - 4xx                     → (nil, status, *clientError)   [never fail-open]
//   - 503                     → (resp, 503, nil)              [breaker tripped]
//   - 200                     → (resp, 200, nil)
//   - other non-2xx           → (nil, status, err)
func (d *DecideClient) Decide(ctx context.Context, req DecideRequest, traceparent string) (*DecideResponse, int, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, 0, fmt.Errorf("marshal decide request: %w", err)
	}
	if len(body) > maxDecideRequestBytes {
		return nil, 0, fmt.Errorf("decide request too large (%d bytes > %d)", len(body), maxDecideRequestBytes)
	}

	url := strings.TrimRight(d.cfg.Endpoint, "/") + "/api/v1/decide"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("create decide request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Client-Id", d.cfg.ClientID)
	if d.cfg.ClientSecret != "" {
		httpReq.Header.Set("X-Client-Secret", d.cfg.ClientSecret)
	}
	if traceparent != "" {
		httpReq.Header.Set("Traceparent", traceparent)
	}

	resp, err := d.client.Do(httpReq)
	if err != nil {
		return nil, 0, fmt.Errorf("decide call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxDecideResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read decide response: %w", err)
	}

	if resp.StatusCode >= 400 && resp.StatusCode < 500 {
		return nil, resp.StatusCode, &clientError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusServiceUnavailable {
		return nil, resp.StatusCode, fmt.Errorf("decide returned %d: %s", resp.StatusCode, string(respBody))
	}

	var decideResp DecideResponse
	if err := json.Unmarshal(respBody, &decideResp); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode decide response: %w", err)
	}
	return &decideResp, resp.StatusCode, nil
}

// isClientError reports whether err is a non-retryable 4xx from the PDP.
func isClientError(err error) bool {
	var ce *clientError
	return errors.As(err, &ce)
}

// buildDecideQuery renders a tool call into the free-text query the PDP's
// policy engine scans. Mirrors the reference adapter's buildQuery so a policy
// authored against the adapter fires identically through the proxy.
func buildDecideQuery(toolName string, args map[string]interface{}) string {
	if len(args) == 0 {
		return fmt.Sprintf("tool_call: %s", toolName)
	}
	argBytes, err := json.Marshal(args)
	if err != nil {
		return fmt.Sprintf("tool_call: %s", toolName)
	}
	return fmt.Sprintf("tool_call: %s args: %s", toolName, string(argBytes))
}

// traceparent renders a W3C traceparent header from a 32-hex trace_id so the
// forwarded backend call (and any downstream span) stitches into the same
// trace the PDP minted. Returns "" for an empty/invalid trace_id.
func traceparent(traceID string) string {
	if len(traceID) != 32 {
		return ""
	}
	if _, err := hex.DecodeString(traceID); err != nil {
		return ""
	}
	return fmt.Sprintf("00-%s-%s-01", traceID, randomHex(8))
}

// randomHex returns n random bytes hex-encoded (2n chars). On the (practically
// impossible) rand failure it returns a fixed non-zero filler so callers never
// emit an all-zero span id.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return strings.Repeat("01", n)
	}
	return hex.EncodeToString(b)
}

// defaultGatewayID returns claude_desktop.<hostname>, the per-machine origin
// tag stamped onto caller_identity.gateway_id so Desktop traffic is
// distinguishable in the AxonFlow audit trail (platform side records it at
// policy_details.gateway_id + the decision.gateway_id span attribute).
func defaultGatewayID() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		return "claude_desktop.unknown"
	}
	// Keep it slug-ish so it reads cleanly in audit dashboards.
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.NewReplacer(" ", "-", ".", "-").Replace(host)
	return "claude_desktop." + host
}

// newSessionID mints a 16-hex session id correlating every Layer-1 audit row
// produced during one Claude Desktop ↔ proxy connection. Forwarded to the PDP
// as x-session-id so the SIEM joins AxonFlow's decision record to BigQuery
// Cloud Audit Logs by session_id (BukuWarung 4-layer audit, Layer 3).
func newSessionID() string {
	return "cd-" + randomHex(8) + fmt.Sprintf("-%d", time.Now().Unix())
}
