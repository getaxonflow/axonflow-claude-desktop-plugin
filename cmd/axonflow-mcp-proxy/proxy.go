// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// route maps an exposed (Claude-Desktop-visible) tool name to the backend and
// original tool name it forwards to.
type route struct {
	backendID    string
	originalName string
}

// Proxy is the governance MCP server. It fronts N backend MCP servers, checks
// every tools/call against Decision Mode before forwarding, redacts PII from
// responses through the authoritative engine (check-output), and audits every
// call. It is BOTH an MCP server to Claude Desktop and an MCP client to each
// backend.
type Proxy struct {
	cfg         Config
	decide      *DecideClient
	checkOutput *CheckOutputClient
	audit       *AuditLogger
	backends    map[string]Backend
	// backendOrder preserves config order so aggregated tool lists are
	// deterministic (config order, then tool order within a backend).
	backendOrder []string

	mu           sync.RWMutex
	exposedTools []json.RawMessage // namespaced tool descriptors for tools/list
	routes       map[string]route  // exposed name → backend + original name
	aggregated   bool
}

// NewProxy wires a Proxy from resolved config. Backends are constructed but not
// yet started — Aggregate (or the first tools/list) starts + initializes them.
func NewProxy(cfg Config) (*Proxy, error) {
	p := &Proxy{
		cfg:         cfg,
		decide:      NewDecideClient(cfg),
		checkOutput: NewCheckOutputClient(cfg),
		audit:       NewAuditLogger(cfg.AuditLogPath),
		backends:    map[string]Backend{},
		routes:      map[string]route{},
	}
	for _, bc := range cfg.Backends {
		b, err := NewBackend(bc)
		if err != nil {
			return nil, err
		}
		p.backends[bc.ID] = b
		p.backendOrder = append(p.backendOrder, bc.ID)
	}
	return p, nil
}

// multiBackend reports whether the proxy fronts more than one backend, which
// is when tool names get namespaced. With a single backend the proxy is in the
// "per-server" packaging mode and tool names pass through unprefixed.
func (p *Proxy) multiBackend() bool { return len(p.backendOrder) > 1 }

// exposedName computes the Claude-Desktop-visible name for a backend tool:
// "<backendID>__<tool>" when fronting multiple backends, the bare tool name
// when fronting one. Namespacing guarantees uniqueness across backends because
// backend IDs are unique (validated at config load) and tool names are unique
// within a backend.
func (p *Proxy) exposedName(backendID, tool string) string {
	if p.multiBackend() {
		return backendID + "__" + tool
	}
	return tool
}

// Aggregate initializes every backend and builds the routing table + exposed
// tool list. Called once at startup; the first tools/list lazily triggers it if
// startup aggregation was skipped (e.g. a backend that's slow to boot).
//
// A backend that fails to initialize or list is logged and SKIPPED rather than
// failing the whole proxy: fronting 2 of 3 healthy backends beats fronting none
// because one is down. The skip is surfaced loudly in the log for operators.
func (p *Proxy) Aggregate(ctx context.Context) error {
	exposed := make([]json.RawMessage, 0)
	routes := map[string]route{}
	var healthy int

	for _, id := range p.backendOrder {
		b := p.backends[id]
		if err := b.Initialize(ctx); err != nil {
			logStderr("backend %q initialize failed — SKIPPED: %v", id, err)
			continue
		}
		tools, err := b.ListTools(ctx)
		if err != nil {
			logStderr("backend %q tools/list failed — SKIPPED: %v", id, err)
			continue
		}
		healthy++
		for _, raw := range tools {
			rewritten, original, exposedName, err := p.rewriteToolName(id, raw)
			if err != nil {
				logStderr("backend %q: tool descriptor skipped: %v", id, err)
				continue
			}
			if _, clash := routes[exposedName]; clash {
				logStderr("backend %q: tool %q collides with an already-exposed name %q — skipped", id, original, exposedName)
				continue
			}
			routes[exposedName] = route{backendID: id, originalName: original}
			exposed = append(exposed, rewritten)
		}
	}

	p.mu.Lock()
	p.exposedTools = exposed
	p.routes = routes
	p.aggregated = true
	p.mu.Unlock()

	logStderr("aggregation complete: %d/%d backends healthy, %d tools exposed", healthy, len(p.backendOrder), len(exposed))
	if healthy == 0 {
		return fmt.Errorf("no backend MCP server is reachable (%d configured)", len(p.backendOrder))
	}
	return nil
}

// rewriteToolName rewrites a raw tool descriptor's "name" to its exposed
// (namespaced) form, preserving every other field (description, inputSchema,
// annotations). Returns (rewritten descriptor, original name, exposed name).
func (p *Proxy) rewriteToolName(backendID string, raw json.RawMessage) (json.RawMessage, string, string, error) {
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, "", "", fmt.Errorf("decode tool descriptor: %w", err)
	}
	original, _ := m["name"].(string)
	if original == "" {
		return nil, "", "", fmt.Errorf("tool descriptor missing name")
	}
	exposed := p.exposedName(backendID, original)
	m["name"] = exposed
	out, err := json.Marshal(m)
	if err != nil {
		return nil, "", "", fmt.Errorf("re-encode tool descriptor: %w", err)
	}
	return out, original, exposed, nil
}

// ToolsList returns the aggregated, namespaced tool descriptors, aggregating
// lazily on first call if startup aggregation was skipped.
func (p *Proxy) ToolsList(ctx context.Context) ([]json.RawMessage, error) {
	p.mu.RLock()
	done := p.aggregated
	p.mu.RUnlock()
	if !done {
		if err := p.Aggregate(ctx); err != nil {
			return nil, err
		}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]json.RawMessage, len(p.exposedTools))
	copy(out, p.exposedTools)
	return out, nil
}

// lookupRoute resolves an exposed tool name to its backend route, aggregating
// lazily if needed (a client that calls tools/call before tools/list).
func (p *Proxy) lookupRoute(ctx context.Context, exposedName string) (route, bool, error) {
	p.mu.RLock()
	done := p.aggregated
	p.mu.RUnlock()
	if !done {
		if err := p.Aggregate(ctx); err != nil {
			return route{}, false, err
		}
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	r, ok := p.routes[exposedName]
	return r, ok, nil
}

// callOutcome is the result of enforcing + (maybe) forwarding one tools/call.
// It carries everything the audit row needs so HandleToolsCall has a single
// place that both responds and audits.
type callOutcome struct {
	response          JSONRPCResponse
	verdict           string
	decisionID        string
	traceID           string
	evaluatedPolicies []string
	recordCount       int
	redactionCount    int
}

// HandleToolsCall enforces Decision Mode on one tools/call and writes exactly
// one Layer-1 audit row. id is the inbound JSON-RPC id to echo on the response.
func (p *Proxy) HandleToolsCall(ctx context.Context, id json.RawMessage, params ToolCallParams) JSONRPCResponse {
	start := time.Now()
	outcome := p.enforce(ctx, id, params)

	row := p.audit.Record(AuditRow{
		SessionID:           p.cfg.SessionID,
		LeaderEmail:         p.cfg.LeaderEmail,
		ToolName:            params.Name,
		ParametersHash:      hashParameters(params.Arguments),
		ResponseRecordCount: outcome.recordCount,
		DurationMs:          time.Since(start).Milliseconds(),
		DecisionID:          outcome.decisionID,
		Verdict:             outcome.verdict,
		EvaluatedPolicies:   outcome.evaluatedPolicies,
		TraceID:             outcome.traceID,
		AIAgent:             p.cfg.AIAgent,
		GatewayID:           p.cfg.GatewayID,
		RedactionCount:      outcome.redactionCount,
	})
	logStderr("%s tool=%s verdict=%s decision_id=%s trace_id=%s records=%d redactions=%d dur=%dms",
		row.Verdict, row.ToolName, row.Verdict, row.DecisionID, row.TraceID, row.ResponseRecordCount, row.RedactionCount, row.DurationMs)

	return outcome.response
}

// enforce runs the decide → verdict → forward → redact pipeline for one call.
// The verdict switch mirrors the reference adapter (decision-mode-mcp-adapter/
// main.go) byte-for-byte in posture: deny→-32001, needs_approval→-32002,
// PDP-unreachable→fail-closed (-32003) unless fail-open is configured.
func (p *Proxy) enforce(ctx context.Context, id json.RawMessage, params ToolCallParams) callOutcome {
	r, ok, err := p.lookupRoute(ctx, params.Name)
	if err != nil {
		return callOutcome{response: errorResponse(id, codeInternalError, "tool routing unavailable: "+err.Error()), verdict: "error"}
	}
	if !ok {
		return callOutcome{response: errorResponse(id, codeInvalidParams, fmt.Sprintf("unknown tool: %s", params.Name)), verdict: "error"}
	}

	decideReq := DecideRequest{
		Stage: "tool",
		CallerIdentity: CallerIdentity{
			GatewayID: p.cfg.GatewayID,
			OrgID:     p.cfg.OrgID,
			TenantID:  p.cfg.TenantID,
		},
		Target: DecisionTarget{Type: "tool", Tool: r.originalName},
		Query:  buildDecideQuery(r.originalName, params.Arguments),
		// Enterprise JWT, optional — a PEP that has the Desktop user's token
		// forwards it so the audit row carries the validated user.
		UserToken: p.cfg.UserToken,
		// BukuWarung Layer-2 audit headers → land in the platform decision
		// record's context map (allowlist covers x-ai-agent / x-session-id /
		// x-leader-identity) so the SIEM joins by session_id.
		Context: map[string]interface{}{
			"tool_name":         r.originalName,
			"exposed_name":      params.Name,
			"backend":           r.backendID,
			"protocol":          "mcp",
			"surface":           "claude_desktop",
			"x-ai-agent":        p.cfg.AIAgent,
			"x-session-id":      p.cfg.SessionID,
			"x-leader-identity": p.cfg.LeaderEmail,
		},
	}

	resp, status, err := p.decide.Decide(ctx, decideReq, "")
	if err != nil {
		logStderr("decide error: %v", err)
		// A 4xx is misconfiguration (bad creds / bad request), not PDP
		// degradation — forwarding would be silently ungoverned, so it is
		// NEVER fail-open regardless of posture.
		if isClientError(err) {
			return callOutcome{verdict: verdictDeny,
				response: errorResponse(id, codePolicyUnavailable, "policy service rejected the request (check proxy credentials/config)")}
		}
		// Transport error / 5xx (PDP unreachable). Honour the posture: fail-open
		// forwards the call (matching the reference adapter), but still runs the
		// defense-in-depth redaction pass via forced=true so a fail-open posture
		// never leaks PII into the context window even without a PDP obligation.
		if p.cfg.FailOpen {
			logStderr("fail-open: PDP unreachable — forwarding ungoverned (redaction still applied)")
			return p.forwardAndRedact(ctx, id, r, params, DecideResponse{}, true)
		}
		return callOutcome{verdict: verdictDeny,
			response: errorResponse(id, codePolicyUnavailable, "policy service unavailable (fail-closed)")}
	}

	out := callOutcome{
		verdict:           resp.Verdict,
		decisionID:        resp.DecisionID,
		traceID:           resp.TraceID,
		evaluatedPolicies: resp.EvaluatedPolicies,
	}

	// 503 = breaker tripped / PDP degraded. Apply the configured posture.
	if status == 503 {
		if p.cfg.FailOpen {
			logStderr("fail-open: forwarding despite PDP 503")
			return p.forwardAndRedact(ctx, id, r, params, *resp, true)
		}
		out.verdict = verdictDeny
		out.response = denyResponse(id, codePolicyUnavailable, "policy service circuit breaker tripped (fail-closed)", resp)
		return out
	}

	switch resp.Verdict {
	case verdictAllow:
		return p.forwardAndRedact(ctx, id, r, params, *resp, false)
	case verdictDeny:
		reason := "request blocked by policy"
		if len(resp.Reasons) > 0 {
			reason = resp.Reasons[0]
		}
		out.response = denyResponse(id, codePolicyDeny, reason, resp)
		return out
	case verdictNeedsApproval:
		out.response = denyResponse(id, codeNeedsApproval, "tool call requires approval", resp)
		return out
	default:
		// Unknown verdict — fail-closed unless configured otherwise.
		if p.cfg.FailOpen {
			return p.forwardAndRedact(ctx, id, r, params, *resp, true)
		}
		out.verdict = verdictDeny
		out.response = denyResponse(id, codePolicyUnavailable, fmt.Sprintf("unknown verdict %q from policy service (fail-closed)", resp.Verdict), resp)
		return out
	}
}

// forwardAndRedact forwards an allowed call to its backend and runs the
// response through the authoritative engine (check-output) for PII redaction
// before returning it to Claude. By default (RedactResponses == "always") the
// scan is UNCONDITIONAL — the proxy is the only component that ever sees a tool
// response, so stripping PII out of it can't be gated on a PDP obligation the
// agent would have to have attached. forced=true marks a fail-open /
// unknown-verdict forward (no explicit allow verdict); it still triggers
// redaction even under the legacy "on-obligation" mode so a fail-open posture
// never leaks PII into the context window.
//
// FAIL-CLOSED: if the engine is unreachable or errors, the (already-executed)
// response is NOT forwarded — a network hiccup must never leak un-redacted PII
// into Claude's context. This is the load-bearing difference from the deleted
// local redactor, which kept "redacting" even with the PDP down.
func (p *Proxy) forwardAndRedact(ctx context.Context, id json.RawMessage, r route, params ToolCallParams, decision DecideResponse, forced bool) callOutcome {
	out := callOutcome{
		verdict:           firstNonEmpty(decision.Verdict, verdictAllow),
		decisionID:        decision.DecisionID,
		traceID:           decision.TraceID,
		evaluatedPolicies: decision.EvaluatedPolicies,
	}
	if forced {
		out.verdict = "allow_failopen"
	}

	// Bound the backend call so a hung/slow backend MCP server can never wedge a
	// Claude Desktop tool call indefinitely (the decide call has its own
	// timeout; the forward needs its own too). A non-positive config value falls
	// back to a sane default rather than an instantly-expired context.
	backendTimeout := p.cfg.BackendTimeout
	if backendTimeout <= 0 {
		backendTimeout = defaultBackendTimeout
	}
	callCtx, cancel := context.WithTimeout(ctx, backendTimeout)
	defer cancel()

	b := p.backends[r.backendID]
	result, err := b.CallTool(callCtx, r.originalName, params.Arguments, traceparent(decision.TraceID))
	if err != nil {
		var re *rpcError
		if asRPCError(err, &re) {
			// Backend returned a JSON-RPC error — propagate code + message.
			out.response = JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: re.Code, Message: re.Message, Data: re.Data}}
			return out
		}
		// A backend that's down / mid-restart (the stdioBackend already tried to
		// reconnect once and a fresh connect is still failing) surfaces a clean,
		// RETRYABLE error rather than a hard dead-session — the next tools/call
		// will attempt the reconnect again. The call WAS governed (decide ran
		// above); nothing is ever forwarded ungoverned during the reconnect
		// window, because this forward step only runs after an allow verdict.
		var unavailable *backendUnavailableError
		if errors.As(err, &unavailable) {
			out.response = errorResponse(id, codeInternalError, unavailable.Error())
			return out
		}
		out.response = errorResponse(id, codeInternalError, fmt.Sprintf("backend %q unavailable: %v", r.backendID, err))
		return out
	}

	// Scan the response for PII through the authoritative engine before it enters
	// Claude's context window. This is the §4.3 control. Default-on: every
	// response is scanned regardless of verdict/obligation, because the agent
	// never sees the response — so the proxy can't outsource the decision to "did
	// the PDP flag the request?". (A clean, allow-with-no-obligation request whose
	// response still carries PII is exactly the case obligation-gating used to
	// leak.) The engine call uses the request context bounded by the client's own
	// timeout, not callCtx, so a slow backend doesn't starve the redaction call.
	if p.shouldRedact(decision, forced) {
		redacted, count, rerr := p.redactResponse(ctx, result, traceparent(decision.TraceID))
		if rerr != nil {
			// Never forward an unredacted (or un-scannable) response.
			return p.redactionFailClosed(id, out, rerr)
		}
		result = redacted
		out.redactionCount = count
		if count > 0 {
			logStderr("engine redacted %d PII span(s) from %s response", count, r.originalName)
		}
	}

	out.recordCount = countRecords(result)
	out.response = JSONRPCResponse{JSONRPC: "2.0", ID: id, Result: result}
	return out
}

// redactResponse submits the tool result to the authoritative engine
// (check-output) and returns the redacted result plus an estimated masked-span
// count. It is FAIL-CLOSED: any error is propagated so the caller blocks rather
// than forwarding an unredacted response.
//
// The whole serialized result is submitted as the execute-style `message`, so
// the engine's PII detectors scan every value (string OR number, at any nesting
// depth — a NIK serialized as a JSON number appears as a digit run in the
// message and is caught) plus object keys. The engine returns the masked text,
// which the proxy re-validates as JSON before forwarding (a mask that broke the
// JSON structure must not corrupt the MCP result, and forwarding the original
// would leak PII — so an invalid result fails closed too).
func (p *Proxy) redactResponse(ctx context.Context, result json.RawMessage, tp string) (json.RawMessage, int, error) {
	if len(bytes.TrimSpace(result)) == 0 {
		return result, 0, nil // empty result — nothing to scan
	}
	res, err := p.checkOutput.CheckOutput(ctx, string(result), tp)
	if err != nil {
		return nil, 0, err
	}
	if !res.WasRedacted {
		return result, 0, nil // engine found nothing to redact
	}
	redacted := []byte(res.RedactedText)
	if !json.Valid(redacted) {
		return nil, 0, fmt.Errorf("engine-redacted response is not valid JSON; failing closed")
	}
	return json.RawMessage(redacted), maskSpanCount(res.RedactedText), nil
}

// redactionFailClosed turns a response-governance failure into a blocked
// outcome — the tool already executed, but its response is NOT forwarded to
// Claude. A policy block surfaces as a deny (-32001) with the engine's reason; a
// transport/availability failure surfaces as policy-unavailable (-32003),
// matching the request-side fail-closed posture so the JSON-RPC contract is
// uniform across both planes.
func (p *Proxy) redactionFailClosed(id json.RawMessage, out callOutcome, err error) callOutcome {
	out.verdict = verdictDeny
	out.redactionCount = 0
	out.recordCount = 0
	if be, ok := asOutputBlocked(err); ok {
		if be.DecisionID != "" {
			out.decisionID = be.DecisionID
		}
		reason := be.Reason
		if reason == "" {
			reason = "response blocked by output policy"
		}
		logStderr("response BLOCKED by output policy (not forwarded): %s", reason)
		out.response = errorResponse(id, codePolicyDeny, reason)
		return out
	}
	logStderr("response governance unavailable — failing closed (response NOT forwarded): %v", err)
	out.response = errorResponse(id, codePolicyUnavailable, "response governance unavailable; response not forwarded (fail-closed)")
	return out
}

// maskSpanCount estimates how many PII spans the engine masked, for the Layer-1
// audit redaction_count. The engine doesn't return a span count, so this counts
// the canonical "[REDACTED" mask tokens the static engine emits; when redaction
// is known to have happened but carried no such token (e.g. the Indonesia
// detector's partial NN****NN mask), the count is reported as at least 1 so the
// audit row still records that redaction occurred. maskSpanCount is only called
// when the engine reported a redaction, so the floor of 1 is never a false
// positive.
func maskSpanCount(redacted string) int {
	if n := strings.Count(redacted, "[REDACTED"); n > 0 {
		return n
	}
	return 1
}

// shouldRedact decides whether the response redactor runs for this forward,
// per the AXONFLOW_REDACT_RESPONSES mode:
//   - "always"        (default) → always scan; the §4.3 baseline.
//   - "on-obligation"           → scan only when the PDP attached a redact_pii
//     obligation OR this is a forced (fail-open) forward with no obligation to
//     honour but where leaking PII would still be unacceptable.
//   - "off"                     → never scan (explicit opt-out footgun).
//
// An unset/unknown mode is treated as "always": loadConfig rejects unknown
// values at boot, so a misconfigured proxy fails safe (scan) here, never open.
func (p *Proxy) shouldRedact(decision DecideResponse, forced bool) bool {
	switch p.cfg.RedactResponses {
	case redactOff:
		return false
	case redactOnObligation:
		return forced || decision.hasObligation("redact_pii")
	default: // redactAlways and any unset/unexpected value → fail safe (scan)
		return true
	}
}

// errorResponse builds a JSON-RPC error response.
func errorResponse(id json.RawMessage, code int, message string) JSONRPCResponse {
	return JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: code, Message: message}}
}

// denyResponse builds a JSON-RPC error response carrying the decision evidence
// (decision_id, trace_id, evaluated_policies, reasons) in the error data so the
// user — and the demo — can see exactly which policy blocked the call.
func denyResponse(id json.RawMessage, code int, message string, decision *DecideResponse) JSONRPCResponse {
	data := map[string]interface{}{}
	if decision != nil {
		data["decision_id"] = decision.DecisionID
		data["trace_id"] = decision.TraceID
		data["evaluated_policies"] = decision.EvaluatedPolicies
		if len(decision.Reasons) > 0 {
			data["reasons"] = decision.Reasons
		}
	}
	dataBytes, _ := json.Marshal(data)
	return JSONRPCResponse{JSONRPC: "2.0", ID: id, Error: &JSONRPCError{Code: code, Message: message, Data: dataBytes}}
}

// countRecords estimates how many records a tool response carried, for the
// Layer-1 response_record_count field. MCP tool results are
// {"content":[{type,text}...], "structuredContent": <any>, "isError": bool}.
// Heuristic, documented in the README:
//   - structuredContent that's a JSON array → its length
//   - else for each content text block that parses as a JSON array → its length
//   - else → number of content blocks
func countRecords(result json.RawMessage) int {
	if len(result) == 0 {
		return 0
	}
	var m struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		StructuredContent json.RawMessage `json:"structuredContent"`
	}
	if err := json.Unmarshal(result, &m); err != nil {
		return 0
	}
	if len(m.StructuredContent) > 0 {
		var arr []json.RawMessage
		if json.Unmarshal(m.StructuredContent, &arr) == nil {
			return len(arr)
		}
	}
	total := 0
	matchedArray := false
	for _, c := range m.Content {
		var arr []json.RawMessage
		if c.Text != "" && json.Unmarshal([]byte(c.Text), &arr) == nil {
			total += len(arr)
			matchedArray = true
		}
	}
	if matchedArray {
		return total
	}
	return len(m.Content)
}

// firstNonEmpty returns a if non-empty else b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// sortedRoutes returns exposed tool names in sorted order (test/debug helper).
func (p *Proxy) sortedRoutes() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	names := make([]string, 0, len(p.routes))
	for n := range p.routes {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Close shuts down every backend (kills stdio children, closes http clients).
func (p *Proxy) Close() {
	for _, id := range p.backendOrder {
		_ = p.backends[id].Close()
	}
	_ = p.audit.Close()
}
