// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Wire bodies, with provenance. MEASURED bodies were captured on 2026-09-16
// from an agent built from public getaxonflow/axonflow dcd5f636d (/health:
// edition community, version 11.0.0). SPEC-DERIVED bodies follow
// docs/api/agent-api.yaml at axonflow-enterprise 76fb9d376 where a community
// stack cannot produce the status (a credential rejection, a check-output
// block). SOURCE-DERIVED bodies are what the platform's writer at that commit
// emits. Change a body here only from a new measurement, spec line or source
// read, and say which.
const (
	// MEASURED: decide, a malformed body.
	wireDecide400 = `{"decision_id":"5bb5741d-cb86-457b-9c4d-e55fffe8a7ff","error":"Invalid request body","trace_id":"9277f2cd19f68849627db7d709cc2523","verdict":"deny"}`
	// MEASURED: decide, an admitted client whose caller_identity names another org.
	wireDecide403OrgMismatch = `{"decision_id":"a28a841c-e2bb-4a0e-a9ed-9cdbfff3ad66","error":"caller_identity.org_id does not match authenticated identity","trace_id":"2dafc44a006b8d088f1c11c146ed6100","verdict":"deny"}`
	// MEASURED: decide at the service-principal ceiling (the middleware JSONError).
	wireDecide402 = `{"error":{"code":402,"message":"ERR_TIER_LIMIT_SERVICE_PRINCIPAL: the community edition admits at most 5 service_principal(s) per organization and 5 are already admitted. Upgrade at https://getaxonflow.com/enterprise"}}`
	// SPEC-DERIVED: decide 401, a DecideErrorResponse (it says verdict deny too).
	wireDecide401 = `{"decision_id":"dec-401","error":"invalid client credentials","trace_id":"00000000000000000000000000000401","verdict":"deny"}`
	// SPEC-DERIVED: the middleware's JSONError 401 (check-output's MCPPerUserTokenUnauthorized).
	wireJSONError401 = `{"error":{"code":401,"message":"invalid user token"}}`
	// SOURCE-DERIVED: writeRateLimitError, platform/agent/community_saas_ratelimit_response.go
	// at axonflow-enterprise 76fb9d376 (Community SaaS only; the upgrade URLs abridged).
	wireDailyQuota429 = `{"error":"Daily request limit reached. Resets at midnight UTC.","limit_type":"daily_quota","tier":"Free","limit":200,"remaining":0,"window":"daily_utc","resets_at":"2026-09-17T00:00:00Z","upgrade":{"tier":"Pro","wording":"Daily limit reached on Free tier (200 events). Pro raises this to 2,000/day. Resets at midnight UTC.","compare_url":"https://getaxonflow.com/pricing","buy_url":"https://getaxonflow.com/pricing"}}`
	// SPEC SHAPE, SOURCE TEXT: the spec gives the REST per-minute 429 a plain
	// {"error": ...} body; the message is the auth path's (auth.go, Community
	// SaaS per-minute limit). How that AuthError is rendered varies by route, so
	// the middleware envelope shape is covered separately (wireJSONError401).
	wirePerMinute429 = `{"error":"Rate limit exceeded (60 req/min). Try again shortly."}`
	// SOURCE-DERIVED: writeFreeLimitError with limit_type feature_pro_only (same file).
	wireFeatureProOnly403 = `{"error":"LLM cost pre-flight is a Pro feature — see what a multi-step plan will cost before it runs.","limit_type":"feature_pro_only","tier":"Free","limit":0,"remaining":0,"upgrade":{"tier":"Pro"}}`
	// MEASURED: check-output, a malformed body.
	wireCheckOutput400 = `{"success":false,"error":"Invalid request body","blocked":false}`
	// SPEC-DERIVED: check-output 403 "Output blocked by policy" (MCPCheckOutputResponse).
	wireCheckOutput403Block = `{"allowed":false,"block_reason":"explicit_constraint","decision_id":"co-dec-403","policies_evaluated":81}`
	// SUITE-DERIVED: decide's unknown_constraint deny. axonflow-enterprise
	// runtime-e2e/3564_per_plane_enforcement asserts reasons are exactly this
	// pair (E7); the sentence is the one axonflow-internal-docs#145 recorded
	// on Community.
	unknownConstraintSentence = "ceiling.refund (organization, document version 1) could not be evaluated: no value was supplied for args.request_type, which the document requires"
)

// ─── refusalMessage: one text per refusal, every field on its own ────────────

func TestRefusalMessage_EachStatusNamesItsCause(t *testing.T) {
	cases := []struct {
		name string
		ce   clientError
		want string
	}{
		{"401 DecideErrorResponse (verdict deny ignored)", clientError{StatusCode: 401, Body: wireDecide401},
			"policy service rejected the proxy's credentials (HTTP 401): invalid client credentials. Check AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN"},
		{"401 middleware JSONError", clientError{StatusCode: 401, Body: wireJSONError401},
			"policy service rejected the proxy's credentials (HTTP 401): invalid user token. Check AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN"},
		{"401 plain-text body", clientError{StatusCode: 401, Body: "bad creds\n"},
			"policy service rejected the proxy's credentials (HTTP 401): bad creds. Check AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN"},
		{"401 no body", clientError{StatusCode: 401, Body: ""},
			"policy service rejected the proxy's credentials (HTTP 401): (the response carried no error text). Check AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN"},
		{"402 measured decide ceiling", clientError{StatusCode: 402, Body: wireDecide402},
			"policy service refused the request: a tier limit of this deployment was reached (HTTP 402): ERR_TIER_LIMIT_SERVICE_PRINCIPAL: the community edition admits at most 5 service_principal(s) per organization and 5 are already admitted. Upgrade at https://getaxonflow.com/enterprise"},
		{"429 envelope with Retry-After", clientError{StatusCode: 429, Body: wireDailyQuota429, RetryAfter: "3600"},
			`policy service refused the request: a rate limit was reached (HTTP 429, limit_type "daily_quota", resets at 2026-09-17T00:00:00Z, retry after 3600 s): Daily request limit reached. Resets at midnight UTC.`},
		{"429 no envelope, Retry-After only", clientError{StatusCode: 429, Body: wirePerMinute429, RetryAfter: "60"},
			"policy service refused the request: a rate limit was reached (HTTP 429, retry after 60 s): Rate limit exceeded (60 req/min). Try again shortly."},
		{"429 neither envelope nor Retry-After", clientError{StatusCode: 429, Body: wirePerMinute429},
			"policy service refused the request: a rate limit was reached (HTTP 429): Rate limit exceeded (60 req/min). Try again shortly."},
		{"429 malformed resets_at, non-numeric Retry-After", clientError{StatusCode: 429, Body: `{"error":"quota","resets_at":"tomorrow-ish"}`, RetryAfter: "soon"},
			`policy service refused the request: a rate limit was reached (HTTP 429, resets_at "tomorrow-ish" (not a date)): quota`},
		{"429 present-but-empty limit_type and resets_at", clientError{StatusCode: 429, Body: `{"error":"quota","limit_type":"","resets_at":""}`},
			"policy service refused the request: a rate limit was reached (HTTP 429): quota"},
		{"429 non-string limit_type", clientError{StatusCode: 429, Body: `{"error":"quota","limit_type":7}`},
			"policy service refused the request: a rate limit was reached (HTTP 429): quota"},
		{"403 measured org mismatch (verdict deny ignored)", clientError{StatusCode: 403, Body: wireDecide403OrgMismatch},
			"policy service rejected the request (HTTP 403): caller_identity.org_id does not match authenticated identity"},
		{"403 feature_pro_only envelope is a tier limit", clientError{StatusCode: 403, Body: wireFeatureProOnly403},
			`policy service refused the request: a tier limit was reached (HTTP 403, limit_type "feature_pro_only"): LLM cost pre-flight is a Pro feature — see what a multi-step plan will cost before it runs.`},
		{"400 measured malformed body", clientError{StatusCode: 400, Body: wireDecide400},
			"policy service rejected the request (HTTP 400): Invalid request body"},
		{"404 message field, with the endpoint hint", clientError{StatusCode: 404, Body: `{"message":"no such route."}`},
			"policy service rejected the request (HTTP 404): no such route. Check AXONFLOW_ENDPOINT: it may not point at an AxonFlow agent that serves this route"},
		{"405 names the endpoint too", clientError{StatusCode: 405, Body: "Method Not Allowed"},
			"policy service rejected the request (HTTP 405): Method Not Allowed. Check AXONFLOW_ENDPOINT: it may not point at an AxonFlow agent that serves this route"},
		{"error null falls through to message", clientError{StatusCode: 409, Body: `{"error":null,"message":"no such route"}`},
			"policy service rejected the request (HTTP 409): no such route"},
		{"401 text ending in a period is not doubled", clientError{StatusCode: 401, Body: `{"error":"token expired."}`},
			"policy service rejected the proxy's credentials (HTTP 401): token expired. Check AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN"},
		{"a string error.code is kept", clientError{StatusCode: 403, Body: `{"error":{"code":"LEGACY_POLICY_WRITE_FROZEN","message":"frozen"}}`},
			"policy service rejected the request (HTTP 403): LEGACY_POLICY_WRITE_FROZEN: frozen"},
		{"error object without a message falls through to message", clientError{StatusCode: 400, Body: `{"error":{"code":400},"message":"bad"}`},
			"policy service rejected the request (HTTP 400): bad"},
		{"a JSON array body is quoted raw", clientError{StatusCode: 400, Body: `["x"]`},
			`policy service rejected the request (HTTP 400): ["x"]`},
		{"limit_type null is absent", clientError{StatusCode: 429, Body: `{"error":"quota","limit_type":null,"resets_at":null}`},
			"policy service refused the request: a rate limit was reached (HTTP 429): quota"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ce := tc.ce
			if got := refusalMessage("policy service", &ce); got != tc.want {
				t.Fatalf("refusalMessage:\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

func TestRefusalMessage_CleansAndCapsPlatformText(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"error": "bad\x00\nthing\x1b " + strings.Repeat("x", 400)})
	got := refusalMessage("policy service", &clientError{StatusCode: 400, Body: string(body)})
	for _, r := range got {
		if r < 0x20 || r == 0x7f {
			t.Fatalf("control character %U left in %q", r, got)
		}
	}
	if !strings.HasPrefix(got, "policy service rejected the request (HTTP 400): bad thing xxx") {
		t.Fatalf("unexpected text: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("text not capped: %q", got)
	}
}

func TestRefusalMessage_RemovesUnicodeControlAndFormatCharacters(t *testing.T) {
	body, _ := json.Marshal(map[string]string{"error": "a\u0085b\u202ec\u2028d\u200be\u2066f"})
	got := refusalMessage("policy service", &clientError{StatusCode: 400, Body: string(body)})
	if want := "policy service rejected the request (HTTP 400): a b c d e f"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDenyReason_EveryReasonInOrder(t *testing.T) {
	cases := []struct {
		name    string
		reasons []string
		want    string
	}{
		{"absent", nil, "request blocked by policy"},
		{"present but empty", []string{}, "request blocked by policy"},
		{"only blank entries", []string{"", "  "}, "request blocked by policy"},
		{"one", []string{"explicit_constraint"}, "explicit_constraint"},
		{"many, code first", []string{"unknown_constraint", unknownConstraintSentence}, "unknown_constraint; " + unknownConstraintSentence},
		{"control and bidi characters removed", []string{"a\nb\u202ec"}, "a b c"},
		{"a reason made only of format characters is skipped", []string{"a", "\u202e\u200b", "b"}, "a; b"},
		{"blank entry skipped", []string{"a", "", "b"}, "a; b"},
	}
	long := denyReason([]string{strings.Repeat("r", 250), strings.Repeat("s", 250)}, "x")
	if !strings.HasSuffix(long, "…") || len([]rune(long)) != maxRefusalTextRunes+1 {
		t.Fatalf("joined reasons not capped: %d runes", len([]rune(long)))
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := denyReason(tc.reasons, "request blocked by policy"); got != tc.want {
				t.Fatalf("denyReason = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestIsOutputDecision_PresenceStates(t *testing.T) {
	cases := map[string]bool{
		`{"allowed":false,"block_reason":"x"}`: true,
		`{"allowed":true}`:                     false,
		`{"block_reason":"x"}`:                 false, // absent allowed is not false
		wireFeatureProOnly403:                  false,
		`not json`:                             false,
		``:                                     false,
		`{"allowed":null}`:                     false,
	}
	for body, want := range cases {
		if got := isOutputDecision([]byte(body)); got != want {
			t.Fatalf("isOutputDecision(%q) = %v, want %v", body, got, want)
		}
	}
}

// ─── end to end through enforce, with the raw bodies on the wire ─────────────

// rawPDP answers decide and check-output with raw status, body and headers, so
// a test puts exactly the measured or spec bytes on the wire.
type rawPDP struct {
	server        *httptest.Server
	decideStatus  int
	decideBody    string
	decideHeaders map[string]string
	coStatus      int
	coBody        string
	coHeaders     map[string]string
	decideCalls   atomic.Int64
}

func newRawPDP() *rawPDP {
	r := &rawPDP{coStatus: http.StatusOK, coBody: `{"allowed":true}`}
	mux := http.NewServeMux()
	write := func(w http.ResponseWriter, status int, body string, headers map[string]string) {
		for k, v := range headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
	mux.HandleFunc("/api/v1/decide", func(w http.ResponseWriter, _ *http.Request) {
		r.decideCalls.Add(1)
		write(w, r.decideStatus, r.decideBody, r.decideHeaders)
	})
	mux.HandleFunc("/api/v1/mcp/check-output", func(w http.ResponseWriter, _ *http.Request) {
		write(w, r.coStatus, r.coBody, r.coHeaders)
	})
	r.server = httptest.NewServer(mux)
	return r
}

func callThrough(t *testing.T, pdp *rawPDP, failOpen bool) (JSONRPCError, *fakeBackend) {
	t.Helper()
	be := &fakeBackend{id: "crm", tools: []json.RawMessage{toolDescriptor("lookup")},
		callResult: json.RawMessage(`{"content":[{"type":"text","text":"ok"}]}`)}
	p := newTestProxy(t, pdp.server.URL, be)
	p.cfg.FailOpen = failOpen
	resp := p.HandleToolsCall(context.Background(), json.RawMessage(`77`), ToolCallParams{Name: "lookup"})
	e := mustParseError(t, resp)
	return *e, be
}

func TestEnforce_Decide4xxIsNeverAPolicyDeny(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		headers map[string]string
		want    string
	}{
		{"401 carrying verdict deny", 401, wireDecide401, nil,
			"policy service rejected the proxy's credentials (HTTP 401): invalid client credentials. Check AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN"},
		{"403 org mismatch carrying verdict deny (measured)", 403, wireDecide403OrgMismatch, nil,
			"policy service rejected the request (HTTP 403): caller_identity.org_id does not match authenticated identity"},
		{"402 ceiling (measured)", 402, wireDecide402, nil,
			"policy service refused the request: a tier limit of this deployment was reached (HTTP 402): ERR_TIER_LIMIT_SERVICE_PRINCIPAL: the community edition admits at most 5 service_principal(s) per organization and 5 are already admitted. Upgrade at https://getaxonflow.com/enterprise"},
		{"429 envelope", 429, wireDailyQuota429, map[string]string{"Retry-After": "3600"},
			`policy service refused the request: a rate limit was reached (HTTP 429, limit_type "daily_quota", resets at 2026-09-17T00:00:00Z, retry after 3600 s): Daily request limit reached. Resets at midnight UTC.`},
		{"400 malformed (measured)", 400, wireDecide400, nil,
			"policy service rejected the request (HTTP 400): Invalid request body"},
	}
	for _, tc := range cases {
		for _, failOpen := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failOpen=%v", tc.name, failOpen), func(t *testing.T) {
				pdp := newRawPDP()
				defer pdp.server.Close()
				pdp.decideStatus, pdp.decideBody, pdp.decideHeaders = tc.status, tc.body, tc.headers
				e, be := callThrough(t, pdp, failOpen)
				if e.Code != codePolicyUnavailable {
					t.Fatalf("code = %d, want %d (-32003): a decide 4xx is never a policy deny (failOpen=%v)", e.Code, codePolicyUnavailable, failOpen)
				}
				if e.Message != tc.want {
					t.Fatalf("message:\n got: %s\nwant: %s", e.Message, tc.want)
				}
				if be.callCount.Load() != 0 {
					t.Fatalf("a refused call must not reach the backend (failOpen=%v)", failOpen)
				}
			})
		}
	}
}

func TestEnforce_DenyCarriesEveryReason(t *testing.T) {
	pdp := newRawPDP()
	defer pdp.server.Close()
	pdp.decideStatus = 200
	pdp.decideBody = `{"verdict":"deny","decision_id":"dec-uc","trace_id":"` + strings.Repeat("e", 32) +
		`","reasons":["unknown_constraint","` + unknownConstraintSentence + `"],"obligations":[],"evaluated_policies":["ceiling.refund"]}`
	e, be := callThrough(t, pdp, false)
	if e.Code != codePolicyDeny {
		t.Fatalf("code = %d, want %d", e.Code, codePolicyDeny)
	}
	if want := "unknown_constraint; " + unknownConstraintSentence; e.Message != want {
		t.Fatalf("message:\n got: %s\nwant: %s", e.Message, want)
	}
	var data struct {
		Reasons []string `json:"reasons"`
	}
	if err := json.Unmarshal(e.Data, &data); err != nil || len(data.Reasons) != 2 {
		t.Fatalf("data.reasons must keep both reasons: %s (%v)", string(e.Data), err)
	}
	if be.callCount.Load() != 0 {
		t.Fatal("a deny must not reach the backend")
	}
}

func TestEnforce_MeasuredShippedControlDeny(t *testing.T) {
	pdp := newRawPDP()
	defer pdp.server.Close()
	pdp.decideStatus = 200
	// MEASURED: decide, `rm -rf / --no-preserve-root`.
	pdp.decideBody = `{"verdict":"deny","decision_id":"3c9b6f8f-ee34-4018-9950-1ce9da39dd0c","trace_id":"408c2b3ae393d3e0a72c1a03270c1766","reasons":["explicit_constraint"],"obligations":[],"evaluated_policies":["corpus:static_policies:sys__dangerous__destructive__fs"],"stage":"tool","expires_at":"2026-09-16T09:21:03.016788134Z","engine":"anchored","subject_type":"Client","policy_bundle":"sha256:be33fe8cde91167b29684c4ff87a76fb52e71db55218b8ea30d762ae626b794f","policy_identities":[{"id":"corpus:static_policies:sys__dangerous__destructive__fs","name":"Destructive Filesystem Operations","source":"shipped"}]}`
	e, _ := callThrough(t, pdp, false)
	if e.Code != codePolicyDeny || e.Message != "explicit_constraint" {
		t.Fatalf("got %d %q, want -32001 explicit_constraint", e.Code, e.Message)
	}
}

func TestEnforce_NeedsApprovalStaysFailClosedAndCarriesReasons(t *testing.T) {
	for _, tc := range []struct {
		name, reasons, want string
	}{
		{"with reasons", `["approval_required: sys_example_high_value requires a reviewer"]`, "tool call refused pending approval: approval_required: sys_example_high_value requires a reviewer"},
		{"without reasons", `null`, "tool call refused pending approval: no reason given"},
	} {
		for _, failOpen := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failOpen=%v", tc.name, failOpen), func(t *testing.T) {
				pdp := newRawPDP()
				defer pdp.server.Close()
				pdp.decideStatus = 200
				pdp.decideBody = `{"verdict":"needs_approval","decision_id":"dec-na","trace_id":"` + strings.Repeat("a", 32) + `","reasons":` + tc.reasons + `}`
				e, be := callThrough(t, pdp, failOpen)
				if e.Code != codeNeedsApproval || e.Message != tc.want {
					t.Fatalf("got %d %q, want -32002 %q", e.Code, e.Message, tc.want)
				}
				if be.callCount.Load() != 0 {
					t.Fatalf("needs_approval must not reach the backend (failOpen=%v)", failOpen)
				}
			})
		}
	}
}

func TestEnforce_CheckOutputRefusalsAreNamed(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		headers  map[string]string
		wantCode int
		want     string
	}{
		{"403 decision is a block", 403, wireCheckOutput403Block, nil, codePolicyDeny, "explicit_constraint"},
		{"403 feature_pro_only is a tier limit, not a block", 403, wireFeatureProOnly403, nil, codePolicyUnavailable,
			`response governance refused the request: a tier limit was reached (HTTP 403, limit_type "feature_pro_only"): LLM cost pre-flight is a Pro feature — see what a multi-step plan will cost before it runs.; response not forwarded (fail-closed)`},
		{"403 without allowed is not a block", 403, `{"error":"tenant mismatch"}`, nil, codePolicyUnavailable,
			"response governance rejected the request (HTTP 403): tenant mismatch; response not forwarded (fail-closed)"},
		{"401 middleware JSONError", 401, wireJSONError401, nil, codePolicyUnavailable,
			"response governance rejected the proxy's credentials (HTTP 401): invalid user token. Check AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN; response not forwarded (fail-closed)"},
		{"401 handler string error", 401, `{"success":false,"error":"user_token_rejected"}`, nil, codePolicyUnavailable,
			"response governance rejected the proxy's credentials (HTTP 401): user_token_rejected. Check AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN; response not forwarded (fail-closed)"},
		{"429 plain with Retry-After", 429, wirePerMinute429, map[string]string{"Retry-After": "30"}, codePolicyUnavailable,
			"response governance refused the request: a rate limit was reached (HTTP 429, retry after 30 s): Rate limit exceeded (60 req/min). Try again shortly.; response not forwarded (fail-closed)"},
		{"400 measured", 400, wireCheckOutput400, nil, codePolicyUnavailable,
			"response governance rejected the request (HTTP 400): Invalid request body; response not forwarded (fail-closed)"},
		{"5xx stays unavailable", 503, `{"error":"down"}`, nil, codePolicyUnavailable,
			"response governance unavailable; response not forwarded (fail-closed)"},
	}
	for _, tc := range cases {
		// The response plane is fail-closed under BOTH request-plane fail modes.
		for _, failOpen := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/failOpen=%v", tc.name, failOpen), func(t *testing.T) {
				pdp := newRawPDP()
				defer pdp.server.Close()
				pdp.decideStatus = 200
				pdp.decideBody = `{"verdict":"allow","decision_id":"dec-ok","trace_id":"` + strings.Repeat("f", 32) + `","obligations":[],"evaluated_policies":[]}`
				pdp.coStatus, pdp.coBody, pdp.coHeaders = tc.status, tc.body, tc.headers
				e, _ := callThrough(t, pdp, failOpen)
				if e.Code != tc.wantCode || e.Message != tc.want {
					t.Fatalf("got %d %q\nwant %d %q", e.Code, e.Message, tc.wantCode, tc.want)
				}
			})
		}
	}
}
