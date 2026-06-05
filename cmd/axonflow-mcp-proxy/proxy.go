// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
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
// responses on the redact_pii obligation, and audits every call. It is BOTH an
// MCP server to Claude Desktop and an MCP client to each backend.
type Proxy struct {
	cfg      Config
	decide   *DecideClient
	audit    *AuditLogger
	backends map[string]Backend
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
		cfg:      cfg,
		decide:   NewDecideClient(cfg),
		audit:    NewAuditLogger(cfg.AuditLogPath),
		backends: map[string]Backend{},
		routes:   map[string]route{},
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

// forwardAndRedact forwards an allowed call to its backend and applies the
// redact_pii obligation to the response before returning it to Claude.
// forced=true means a fail-open / unknown-verdict path chose to forward without
// an explicit allow verdict; on that path redaction runs unconditionally (a
// defense-in-depth safety net) so a fail-open posture never leaks PII into the
// context window even though the (absent) decision carries no obligation.
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
		out.response = errorResponse(id, codeInternalError, fmt.Sprintf("backend %q unavailable: %v", r.backendID, err))
		return out
	}

	// Redact when the PDP attached a redact_pii obligation — OR unconditionally
	// on a forced (fail-open) forward, where there is no obligation to honour but
	// we still must not leak PII into the context window. This is the §4.3
	// control: strip PII before the response enters Claude's context window.
	if forced || decision.hasObligation("redact_pii") {
		redacted, summary := redactResult(result)
		result = redacted
		out.redactionCount = summary.Count
		if summary.Count > 0 {
			logStderr("redacted %d PII span(s) from %s response: %v", summary.Count, r.originalName, redactionByTypeSorted(summary.ByType))
		}
	}

	out.recordCount = countRecords(result)
	out.response = JSONRPCResponse{JSONRPC: "2.0", ID: id, Result: result}
	return out
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

// redactResult walks a tool result and masks PII in every scalar leaf —
// string and numeric VALUES, and object KEYS (a record keyed by a NIK would
// otherwise leak it). This covers content[].text, structuredContent, and any
// nested object/array.
//
// Known limitations (see redact.go "Coverage & limitations" and the README
// "Scope & boundaries" — stated plainly rather than implied away):
//   - PII split across separate array elements (["3174","0125","0990","0001"])
//     reassembles in Claude's reading but is not caught span-by-span.
//   - base64/hex-encoded or otherwise transformed PII is not decoded, so it is
//     not matched.
//
// The platform PDP at the gate remains the authoritative detector; this is a
// last-line response filter, not a complete DLP engine. Returns the redacted
// JSON and a summary.
func redactResult(result json.RawMessage) (json.RawMessage, RedactionResult) {
	var v interface{}
	// UseNumber so numeric leaves keep their exact digits (a 16-digit NIK or a
	// 19-digit card exceeds float64's integer precision) — the redactor matches
	// on the exact digit string, not a rounded float.
	dec := json.NewDecoder(bytes.NewReader(result))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		// Unparseable result (shouldn't happen for valid MCP) — redact the raw
		// string form as a last-line defense rather than passing it through.
		redacted, summary := RedactText(string(result))
		return json.RawMessage(mustJSONString(redacted)), summary
	}
	summary := RedactionResult{ByType: map[string]int{}}
	redacted := redactValue(v, &summary)
	out, err := json.Marshal(redacted)
	if err != nil {
		return result, summary
	}
	return out, summary
}

// redactValue recursively masks PII in scalar leaves, accumulating into
// summary. Strings AND numbers are scanned: a backend that returns a NIK / card
// / phone as a JSON *number* (e.g. {"nik":3174012509900001}) must not slip past
// redaction — otherwise the §4.3 "no PII reaches the context" claim would hold
// only for string-typed PII. A number that matches is replaced with its mask
// token (string); a number that doesn't match is returned unchanged so its type
// and precision are preserved.
func redactValue(v interface{}, summary *RedactionResult) interface{} {
	switch t := v.(type) {
	case string:
		return redactScalarString(t, v, summary)
	case float64:
		return redactScalarString(strconv.FormatFloat(t, 'f', -1, 64), v, summary)
	case json.Number:
		return redactScalarString(t.String(), v, summary)
	case map[string]interface{}:
		// Redact both keys and values. A record keyed by PII — e.g.
		// {"3174012509900001": {...}} — would leak the key if only values were
		// scanned. Build a new map so keys can be rewritten safely; on the rare
		// case where two distinct keys mask to the same token, suffix to avoid
		// silently dropping a record.
		out := make(map[string]interface{}, len(t))
		for k, val := range t {
			rv := redactValue(val, summary)
			rk := redactMapKey(k, summary)
			if _, clash := out[rk]; clash && rk != k {
				for i := 1; ; i++ {
					cand := fmt.Sprintf("%s#%d", rk, i)
					if _, exists := out[cand]; !exists {
						rk = cand
						break
					}
				}
			}
			out[rk] = rv
		}
		return out
	case []interface{}:
		for i, val := range t {
			t[i] = redactValue(val, summary)
		}
		return t
	default:
		return v
	}
}

// redactScalarString runs the redactor over the string form s of leaf value
// orig. If anything matched it accumulates the counts and returns the redacted
// string (the leaf's type may change number→string — acceptable for a mask);
// otherwise it returns orig unchanged so non-PII leaves keep their original
// type and precision.
func redactScalarString(s string, orig interface{}, summary *RedactionResult) interface{} {
	red, r := RedactText(s)
	if r.Count == 0 {
		return orig
	}
	summary.Count += r.Count
	for k, n := range r.ByType {
		summary.ByType[k] += n
	}
	return red
}

// redactMapKey runs the redactor over an object key and returns the masked key
// (accumulating the counts) so a record keyed by PII doesn't leak the key.
// Returns the key unchanged when nothing matched.
func redactMapKey(k string, summary *RedactionResult) string {
	red, r := RedactText(k)
	if r.Count == 0 {
		return k
	}
	summary.Count += r.Count
	for t, n := range r.ByType {
		summary.ByType[t] += n
	}
	return red
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
