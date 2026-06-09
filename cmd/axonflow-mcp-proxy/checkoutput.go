// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const (
	// checkOutputPath is the engine's response-governance endpoint. Submitting a
	// tool response here runs the SAME authoritative PII detectors the platform
	// applies at the gate (NIK + SSN + email + phone + …, epic #2565), so the
	// proxy NEVER re-implements redaction locally — the divergent local regex
	// engine this client replaces is exactly what the epic exists to kill.
	checkOutputPath = "/api/v1/mcp/check-output"

	// checkOutputConnectorType is the sentinel connector_type the proxy stamps on
	// every check-output call. check-output is connector-agnostic for PEP/gateway
	// callers (isGateway), so the platform's MCP connector allowlist does NOT gate
	// PII detection for this sentinel (#2565, mcp_handler.go:839,2101) — any value
	// works; this one just tags the origin in the audit trail.
	checkOutputConnectorType = "claude-desktop-proxy"

	// maxCheckOutputBytes bounds both the submitted message and the redacted body.
	// A response larger than this can't be scanned, so the caller fails CLOSED
	// rather than forwarding it unscanned.
	maxCheckOutputBytes = 8 << 20 // 8 MB
)

// checkOutputRequest mirrors platform MCPCheckOutputRequest (mcp_handler.go:1670).
// The proxy submits the tool response as the execute-style `message` (a single
// text blob) — it never sends `response_data` rows — so the engine runs its
// message-path PII detectors and returns the redacted text in `redacted_data`.
type checkOutputRequest struct {
	ClientID      string `json:"client_id"`
	UserToken     string `json:"user_token,omitempty"`
	TenantID      string `json:"tenant_id"`
	ConnectorType string `json:"connector_type"`
	Message       string `json:"message"`
}

// checkOutputResponse mirrors platform MCPCheckOutputResponse (mcp_handler.go:1689).
// For the message path, redacted_data is the redacted message STRING
// (RedactedMessage); it is absent when the engine found nothing to redact.
type checkOutputResponse struct {
	Allowed           bool        `json:"allowed"`
	BlockReason       string      `json:"block_reason"`
	RedactedData      interface{} `json:"redacted_data"`
	PoliciesEvaluated int         `json:"policies_evaluated"`
	DecisionID        string      `json:"decision_id"`
}

// CheckOutputResult is the proxy-facing outcome of one check-output call.
type CheckOutputResult struct {
	// RedactedText is the engine's redacted message; only meaningful when
	// WasRedacted is true.
	RedactedText string
	// WasRedacted is true when the engine masked PII (redacted_data present).
	WasRedacted bool

	PoliciesEvaluated int
	DecisionID        string
}

// outputBlockedError marks a policy BLOCK from check-output: the engine refused
// to allow the response (critical-PII hard-deny, response-side SQLi, or
// exfiltration). The caller MUST NOT forward — it surfaces a deny.
type outputBlockedError struct {
	Reason     string
	DecisionID string
}

func (e *outputBlockedError) Error() string {
	if e.Reason != "" {
		return "response blocked by output policy: " + e.Reason
	}
	return "response blocked by output policy"
}

// asOutputBlocked reports whether err is a policy block from check-output.
func asOutputBlocked(err error) (*outputBlockedError, bool) {
	var be *outputBlockedError
	if errors.As(err, &be) {
		return be, true
	}
	return nil, false
}

// CheckOutputClient calls POST {endpoint}/api/v1/mcp/check-output. It is the
// single, reused response-governance client — the proxy never re-implements
// redaction. It authenticates EXACTLY as DecideClient does (HTTP Basic,
// base64(clientID:clientSecret)) because check-output shares the agent's
// enterprise auth path (Authenticate → extractClientID/extractClientSecret):
// custom X-Client-* headers are IGNORED, so an enterprise PDP 401s without this.
// Because the credentials are identical to the decide call, a 403 from
// check-output that arrives AFTER a successful decide is a policy block, not an
// auth failure.
type CheckOutputClient struct {
	cfg    Config
	client *http.Client
}

// NewCheckOutputClient builds a CheckOutputClient with a bounded HTTP timeout
// (the circuit-breaker primitive on the redaction path: a hung engine can never
// wedge a forward beyond cfg.Timeout, after which the fail-closed posture
// blocks the response).
func NewCheckOutputClient(cfg Config) *CheckOutputClient {
	return &CheckOutputClient{
		cfg:    cfg,
		client: &http.Client{Timeout: cfg.Timeout},
	}
}

// CheckOutput submits message to the engine and returns the redaction outcome.
//
// Fail-CLOSED contract — the caller forwards the response to Claude ONLY on a
// (result, nil) return. Every other return means "do not forward unredacted":
//   - transport / timeout error      → (nil, err)
//   - 403 policy block                → (nil, *outputBlockedError)
//   - other 4xx (auth / bad request)  → (nil, *clientError)
//   - 5xx / unexpected status         → (nil, err)
//   - 200 allowed:false (defensive)   → (nil, *outputBlockedError)
//   - non-string redacted_data        → (nil, err)   [a wire shape we never ask for]
//   - 200 allowed:true                → (result, nil)
func (c *CheckOutputClient) CheckOutput(ctx context.Context, message, traceparent string) (*CheckOutputResult, error) {
	reqBody := checkOutputRequest{
		ClientID:      c.cfg.ClientID,
		UserToken:     c.cfg.UserToken,
		TenantID:      c.cfg.TenantID,
		ConnectorType: checkOutputConnectorType,
		Message:       message,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("marshal check-output request: %w", err)
	}
	if len(body) > maxCheckOutputBytes {
		return nil, fmt.Errorf("check-output request too large (%d bytes > %d)", len(body), maxCheckOutputBytes)
	}

	url := strings.TrimRight(c.cfg.Endpoint, "/") + checkOutputPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create check-output request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Identical auth to the decide call (decide.go) — see type doc.
	if c.cfg.ClientSecret != "" {
		httpReq.Header.Set("Authorization", "Basic "+basicAuth(c.cfg.ClientID, c.cfg.ClientSecret))
	}
	if traceparent != "" {
		httpReq.Header.Set("Traceparent", traceparent)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("check-output call: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxCheckOutputBytes))
	if err != nil {
		return nil, fmt.Errorf("read check-output response: %w", err)
	}

	var parsed checkOutputResponse
	parseErr := json.Unmarshal(respBody, &parsed)

	switch {
	case resp.StatusCode == http.StatusOK:
		if parseErr != nil {
			return nil, fmt.Errorf("decode check-output response: %w", parseErr)
		}
		if !parsed.Allowed {
			// 200 + allowed:false shouldn't happen (block paths return 403) but
			// treat it as a block — never forward.
			return nil, &outputBlockedError{Reason: parsed.BlockReason, DecisionID: parsed.DecisionID}
		}
		return c.buildResult(parsed)
	case resp.StatusCode == http.StatusForbidden:
		// 403 is the engine's block status (critical-PII / response SQLi / exfil).
		// Surface the engine's block_reason when the body parses; never forward.
		return nil, &outputBlockedError{Reason: parsed.BlockReason, DecisionID: parsed.DecisionID}
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		// Other 4xx (400 bad request, 401 unauthorized) is misconfiguration, not
		// degradation — still fail-closed, but as a distinct error type.
		return nil, &clientError{StatusCode: resp.StatusCode, Body: string(respBody)}
	default:
		return nil, fmt.Errorf("check-output returned %d: %s", resp.StatusCode, string(respBody))
	}
}

// buildResult interprets a 200 allowed:true response. redacted_data is the
// redacted message STRING for the message path; absent → nothing redacted.
func (c *CheckOutputClient) buildResult(parsed checkOutputResponse) (*CheckOutputResult, error) {
	out := &CheckOutputResult{PoliciesEvaluated: parsed.PoliciesEvaluated, DecisionID: parsed.DecisionID}
	switch v := parsed.RedactedData.(type) {
	case nil:
		return out, nil // no redaction — forward the original response unchanged
	case string:
		if v == "" {
			return out, nil
		}
		out.RedactedText = v
		out.WasRedacted = true
		return out, nil
	default:
		// We only ever submit `message`, so the engine returns a string (or
		// nothing). A non-string redacted_data is an unexpected wire shape; fail
		// closed rather than guess and risk forwarding unredacted data.
		return nil, fmt.Errorf("check-output returned non-string redacted_data (%T); failing closed", v)
	}
}
