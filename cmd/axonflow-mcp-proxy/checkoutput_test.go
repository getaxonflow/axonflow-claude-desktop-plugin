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

// checkOutputServer stands up an httptest server emulating the engine's
// /api/v1/mcp/check-output, capturing the last request for auth assertions.
type checkOutputServer struct {
	server   *httptest.Server
	status   int
	resp     checkOutputResponse
	rawBody  string // optional: when set, write this raw body instead of resp
	lastAuth string
	lastReq  checkOutputRequest
}

func newCheckOutputServer() *checkOutputServer {
	s := &checkOutputServer{status: http.StatusOK, resp: checkOutputResponse{Allowed: true}}
	s.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.lastAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&s.lastReq)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(s.status)
		if s.rawBody != "" {
			_, _ = w.Write([]byte(s.rawBody))
			return
		}
		_ = json.NewEncoder(w).Encode(s.resp)
	}))
	return s
}
func (s *checkOutputServer) close() { s.server.Close() }

func coClient(endpoint string) *CheckOutputClient {
	return NewCheckOutputClient(Config{
		Endpoint:     endpoint,
		ClientID:     "org-acme",
		ClientSecret: "lic-secret",
		TenantID:     "tenant-acme",
		Timeout:      2 * time.Second,
	})
}

func TestCheckOutput_NoRedaction_ForwardsOriginal(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	s.resp = checkOutputResponse{Allowed: true} // no redacted_data
	res, err := coClient(s.server.URL).CheckOutput(context.Background(), `{"content":[]}`, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.WasRedacted {
		t.Fatalf("WasRedacted should be false when no redacted_data")
	}
}

func TestCheckOutput_Redaction_ReturnsRedactedText(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	s.resp = checkOutputResponse{Allowed: true, RedactedData: "nik [REDACTED:nik]", PoliciesEvaluated: 2, DecisionID: "d1"}
	res, err := coClient(s.server.URL).CheckOutput(context.Background(), "nik 3174012509900001", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.WasRedacted || res.RedactedText != "nik [REDACTED:nik]" {
		t.Fatalf("redaction not surfaced: %+v", res)
	}
	if res.DecisionID != "d1" || res.PoliciesEvaluated != 2 {
		t.Fatalf("metadata lost: %+v", res)
	}
}

func TestCheckOutput_SendsBasicAuthAndConnectorSentinel(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	_, err := coClient(s.server.URL).CheckOutput(context.Background(), "hello", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("org-acme:lic-secret"))
	if s.lastAuth != wantAuth {
		t.Fatalf("auth header = %q, want %q", s.lastAuth, wantAuth)
	}
	if s.lastReq.ConnectorType != checkOutputConnectorType {
		t.Fatalf("connector_type = %q, want %q", s.lastReq.ConnectorType, checkOutputConnectorType)
	}
	if s.lastReq.TenantID != "tenant-acme" || s.lastReq.Message != "hello" {
		t.Fatalf("request fields wrong: %+v", s.lastReq)
	}
}

func TestCheckOutput_403_IsBlock(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	s.status = http.StatusForbidden
	s.resp = checkOutputResponse{Allowed: false, BlockReason: "critical PII", DecisionID: "blk"}
	_, err := coClient(s.server.URL).CheckOutput(context.Background(), "nik 3174012509900001", "")
	be, ok := asOutputBlocked(err)
	if !ok {
		t.Fatalf("expected outputBlockedError, got %v", err)
	}
	if be.Reason != "critical PII" || be.DecisionID != "blk" {
		t.Fatalf("block details lost: %+v", be)
	}
	if !strings.Contains(be.Error(), "critical PII") {
		t.Fatalf("block Error() lost reason: %q", be.Error())
	}
}

func TestCheckOutput_200_AllowedFalse_IsBlock(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	s.resp = checkOutputResponse{Allowed: false, BlockReason: "blocked-on-200"}
	_, err := coClient(s.server.URL).CheckOutput(context.Background(), "x", "")
	if _, ok := asOutputBlocked(err); !ok {
		t.Fatalf("200 allowed:false must be treated as a block, got %v", err)
	}
}

func TestCheckOutput_401_IsClientError(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	s.status = http.StatusUnauthorized
	s.rawBody = `{"error":"unauthorized"}`
	_, err := coClient(s.server.URL).CheckOutput(context.Background(), "x", "")
	if !isClientError(err) {
		t.Fatalf("401 should be a clientError, got %v", err)
	}
	// And NOT an output block (a 4xx auth failure is misconfig, not a policy block).
	if _, ok := asOutputBlocked(err); ok {
		t.Fatalf("401 must not be classified as an output block")
	}
}

func TestCheckOutput_500_IsError(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	s.status = http.StatusInternalServerError
	s.rawBody = `oops`
	_, err := coClient(s.server.URL).CheckOutput(context.Background(), "x", "")
	if err == nil {
		t.Fatalf("500 must error (fail closed)")
	}
	if isClientError(err) {
		t.Fatalf("500 is not a client error")
	}
	if _, ok := asOutputBlocked(err); ok {
		t.Fatalf("500 is not an output block")
	}
}

func TestCheckOutput_TransportError(t *testing.T) {
	_, err := coClient("http://127.0.0.1:1").CheckOutput(context.Background(), "x", "")
	if err == nil {
		t.Fatalf("transport failure must error (fail closed)")
	}
}

func TestCheckOutput_NonStringRedactedData_FailsClosed(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	// A wire shape we never ask for (rows array): must fail closed, not guess.
	s.rawBody = `{"allowed":true,"redacted_data":[{"nik":"masked"}]}`
	_, err := coClient(s.server.URL).CheckOutput(context.Background(), "x", "")
	if err == nil {
		t.Fatalf("non-string redacted_data must fail closed")
	}
	if _, ok := asOutputBlocked(err); ok {
		t.Fatalf("non-string redacted_data is a shape error, not a block")
	}
}

func TestCheckOutput_EmptyRedactedData_NotRedacted(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	s.resp = checkOutputResponse{Allowed: true, RedactedData: ""} // empty string → no change
	res, err := coClient(s.server.URL).CheckOutput(context.Background(), "x", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.WasRedacted {
		t.Fatalf("empty redacted_data must not count as redaction")
	}
}

func TestCheckOutput_RequestTooLarge_FailsClosed(t *testing.T) {
	huge := strings.Repeat("a", maxCheckOutputBytes+10)
	_, err := coClient("http://127.0.0.1:1").CheckOutput(context.Background(), huge, "")
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized request must fail closed with size error, got %v", err)
	}
}

func TestMaskSpanCount(t *testing.T) {
	if got := maskSpanCount("a [REDACTED:nik] b [REDACTED:email]"); got != 2 {
		t.Fatalf("token count = %d, want 2", got)
	}
	// Redaction happened but with a partial mask carrying no token → floor of 1.
	if got := maskSpanCount("0812****7890"); got != 1 {
		t.Fatalf("partial-mask count = %d, want floor 1", got)
	}
}

func TestRedactResponse_EmptyResult_NoCall(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	p := &Proxy{cfg: Config{Endpoint: s.server.URL}, checkOutput: coClient(s.server.URL)}
	out, n, err := p.redactResponse(context.Background(), json.RawMessage("  "), "")
	if err != nil || n != 0 || string(out) != "  " {
		t.Fatalf("empty result should pass through untouched: out=%q n=%d err=%v", out, n, err)
	}
}

func TestCheckOutput_NoAuthHeaderWhenSecretEmpty(t *testing.T) {
	s := newCheckOutputServer()
	defer s.close()
	c := NewCheckOutputClient(Config{Endpoint: s.server.URL, ClientID: "community", Timeout: time.Second})
	if _, err := c.CheckOutput(context.Background(), "x", ""); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.lastAuth != "" {
		t.Fatalf("community mode (no secret) must send no auth header, got %q", s.lastAuth)
	}
}
