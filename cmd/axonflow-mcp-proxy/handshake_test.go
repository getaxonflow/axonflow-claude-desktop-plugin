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

// Golden vectors captured from the PLATFORM's own shipped encoder
// (contract.PEPHandshake.Encode, axonflow-enterprise
// runtime-e2e/3704_pep_capability_handshake/client -print-handshake), not
// regenerated from this file's output.
//
// THIS IS THE WHOLE ANTI-DRIFT MECHANISM AND IT IS WORTH BEING EXPLICIT ABOUT.
// This repository cannot import the contract package: it is public and the
// contract lives in a private one. So handshake.go is a HAND-TRANSCRIPTION of a
// wire format, which is exactly the drift class that bit five SDKs in #3603.
//
// A test that built its expectation by calling buildPEPHandshake would agree
// with whatever this file did, including being wrong. These constants are the
// other implementation's actual output, so the two are compared rather than one
// being compared with itself. If either side moves, this fails HERE rather than
// a customer's proxy being refused in the field.
const (
	goldenCapable  = "eyJwcm9maWxlX3ZlcnNpb24iOjEsInBlcF9pZCI6ImNsYXVkZS1kZXNrdG9wLXBsdWdpbiIsImF1ZGllbmNlIjoiYXhvbmZsb3ctZGVjaXNpb24tcHJvb2YiLCJjYXBhYmlsaXRpZXMiOlt7InR5cGUiOiJmaWVsZF9yZWRhY3QiLCJ2ZXJzaW9uIjoxfV19"
	goldenNone     = "eyJwcm9maWxlX3ZlcnNpb24iOjEsInBlcF9pZCI6ImNsYXVkZS1kZXNrdG9wLXBsdWdpbiIsImF1ZGllbmNlIjoiYXhvbmZsb3ctZGVjaXNpb24tcHJvb2YiLCJjYXBhYmlsaXRpZXMiOltdfQ"
	goldenAudience = "axonflow-decision-proof"
)

// TestHandshakeMatchesThePlatformEncoderByteForByte is the load-bearing test in
// this file.
func TestHandshakeMatchesThePlatformEncoderByteForByte(t *testing.T) {
	for _, tc := range []struct {
		name   string
		redact string
		want   string
	}{
		{"can discharge redaction (default)", redactAlways, goldenCapable},
		{"can discharge redaction (on-obligation)", redactOnObligation, goldenCapable},
		{"cannot discharge redaction", redactOff, goldenNone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildPEPHandshake(Config{PEPAudience: goldenAudience, RedactResponses: tc.redact})
			if err != nil {
				t.Fatalf("buildPEPHandshake: %v", err)
			}
			if got != tc.want {
				t.Fatalf("the encoding disagrees with the platform's own encoder.\n got: %s\nwant: %s\n"+
					"This repo cannot import the contract package, so this file is a hand transcription; "+
					"a mismatch here is a proxy the platform will refuse in the field.", got, tc.want)
			}
		})
	}
}

// TestAnEmptyDeclarationEncodesAsAnEmptyArrayNeverAnAbsentMember pins
// absent-is-not-empty at the client end.
//
// The platform treats an OMITTED capabilities member as MALFORMED and refuses
// the request, while `[]` is the legitimate declaration "I discharge nothing".
// A single `omitempty` on that struct field would silently convert every
// honest empty declaration into a 400 - and every other test in this file would
// still pass, because they compare whole strings that would move together.
// This asserts the decoded SHAPE.
func TestAnEmptyDeclarationEncodesAsAnEmptyArrayNeverAnAbsentMember(t *testing.T) {
	encoded, err := buildPEPHandshake(Config{PEPAudience: goldenAudience, RedactResponses: redactOff})
	if err != nil {
		t.Fatalf("buildPEPHandshake: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("the header value is not raw url-safe base64: %v", err)
	}

	var members map[string]json.RawMessage
	if err := json.Unmarshal(raw, &members); err != nil {
		t.Fatalf("the document is not a JSON object: %v", err)
	}
	caps, present := members["capabilities"]
	if !present {
		t.Fatal("the `capabilities` member is ABSENT; the platform reads that as MALFORMED and refuses " +
			"the request. An empty declaration must encode as [], which is a declaration.")
	}
	if string(caps) != "[]" {
		t.Fatalf("`capabilities` = %s, want []", caps)
	}
	// A PEP may declare what it can DO, never who it is or what it is entitled
	// to. These members must never appear on the wire.
	for _, forbidden := range []string{"edition", "tier", "license", "realm", "org_id"} {
		if _, found := members[forbidden]; found {
			t.Fatalf("the document carries a %q member; a PEP may not declare its own edition or "+
				"entitlement, and the platform refuses an unknown member outright", forbidden)
		}
	}
}

// TestTheDeclarationIsHonestAboutWhatThisProxyCanDischarge is the correctness
// claim the whole handshake rests on.
//
// Under AXONFLOW_REDACT_RESPONSES=off the proxy never calls the fulfillment
// endpoint (see shouldRedact), so it genuinely cannot discharge a field_redact
// obligation. Declaring it anyway would be the worst outcome available: the
// platform would ALLOW the request believing a redaction was coming, and none
// would happen. Declaring nothing makes the platform deny instead.
func TestTheDeclarationIsHonestAboutWhatThisProxyCanDischarge(t *testing.T) {
	off := declaredCapabilities(Config{RedactResponses: redactOff})
	if len(off) != 0 {
		t.Fatalf("a proxy configured never to redact declared %v; the platform would allow a request "+
			"carrying a mandatory redaction believing this proxy would discharge it, and it would not", off)
	}
	for _, mode := range []string{redactAlways, redactOnObligation} {
		got := declaredCapabilities(Config{RedactResponses: mode})
		if len(got) != 1 || got[0].Type != capFieldRedact || got[0].Version != capSchemaV1 {
			t.Fatalf("RedactResponses=%q declared %v, want exactly %s@%d", mode, got, capFieldRedact, capSchemaV1)
		}
	}
}

// TestNoAudienceMeansNoHeaderAtAll is the nothing-changes-by-default arm.
func TestNoAudienceMeansNoHeaderAtAll(t *testing.T) {
	got, err := buildPEPHandshake(Config{RedactResponses: redactAlways})
	if err != nil {
		t.Fatalf("an unconfigured proxy must not error: %v", err)
	}
	if got != "" {
		t.Fatalf("an unconfigured proxy produced a handshake %q; absence must be byte-identical to "+
			"the pre-handshake behaviour", got)
	}
}

// TestAnInvalidAudienceRefusesToStart.
//
// A misconfigured value that silently disabled the handshake would leave an
// operator believing a control was in force when it was not, so the failure is
// loud and at startup rather than a 400 on every governed call in production.
func TestAnInvalidAudienceRefusesToStart(t *testing.T) {
	for _, bad := range []string{
		"has spaces",
		"-leading-hyphen",
		"trailing\nnewline",
		strings.Repeat("a", 129),
	} {
		if _, err := buildPEPHandshake(Config{PEPAudience: bad, RedactResponses: redactAlways}); err == nil {
			t.Fatalf("audience %q was accepted; the platform refuses it, so this proxy would 400 on "+
				"every governed call", bad)
		}
	}
}

// TestBothGovernedCallPathsPresentTheSameDeclaration.
//
// The two paths are ONE enforcement point. A declaration that differed between
// them would be a per-call-site dialect the platform would attribute to a
// single PEP, and the capability answer could then depend on which path a
// request happened to take. Asserted by driving the REAL clients against test
// servers and reading the header off the wire, rather than by inspecting the
// config value both happen to read.
func TestBothGovernedCallPathsPresentTheSameDeclaration(t *testing.T) {
	seen := map[string]string{}

	decideSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen["decide"] = r.Header.Get(pepHandshakeHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":"allow","decision_id":"d","trace_id":"t","obligations":[],"evaluated_policies":[]}`))
	}))
	defer decideSrv.Close()

	outSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen["check-output"] = r.Header.Get(pepHandshakeHeader)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":true}`))
	}))
	defer outSrv.Close()

	base := Config{PEPAudience: goldenAudience, RedactResponses: redactAlways}
	handshake, err := buildPEPHandshake(base)
	if err != nil {
		t.Fatalf("buildPEPHandshake: %v", err)
	}
	if handshake == "" {
		t.Fatal("fixture produced no handshake, so the assertions below would be vacuous")
	}

	decideCfg := base
	decideCfg.Endpoint = decideSrv.URL
	decideCfg.PEPHandshake = handshake
	decideCfg.Timeout = 5 * time.Second
	if _, _, err := NewDecideClient(decideCfg).Decide(context.Background(), DecideRequest{}, ""); err != nil {
		t.Fatalf("decide call: %v", err)
	}

	outCfg := base
	outCfg.Endpoint = outSrv.URL
	outCfg.PEPHandshake = handshake
	outCfg.Timeout = 5 * time.Second
	if _, err := NewCheckOutputClient(outCfg).CheckOutput(context.Background(), "hello", ""); err != nil {
		t.Fatalf("check-output call: %v", err)
	}

	if seen["decide"] != handshake {
		t.Fatalf("/api/v1/decide received %q, want %q", seen["decide"], handshake)
	}
	if seen["check-output"] != handshake {
		t.Fatalf("/api/v1/mcp/check-output received %q, want %q", seen["check-output"], handshake)
	}
	if seen["decide"] != seen["check-output"] {
		t.Fatalf("the two governed call paths presented DIFFERENT declarations (%q vs %q); "+
			"they are one enforcement point", seen["decide"], seen["check-output"])
	}
}

// TestNoHeaderIsSentWhenUnconfigured proves the omission on the wire, not just
// in the builder. A header set to the empty string is NOT the same as an absent
// header: the platform reads a present-but-empty value as MALFORMED and refuses
// the request, so an `if != ""` guard that was dropped would turn every
// unconfigured proxy into a 400.
func TestNoHeaderIsSentWhenUnconfigured(t *testing.T) {
	var present bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header[http.CanonicalHeaderKey(pepHandshakeHeader)]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":"allow","decision_id":"d","trace_id":"t","obligations":[],"evaluated_policies":[]}`))
	}))
	defer srv.Close()

	cfg := Config{Endpoint: srv.URL, RedactResponses: redactAlways, Timeout: 5 * time.Second}
	if _, _, err := NewDecideClient(cfg).Decide(context.Background(), DecideRequest{}, ""); err != nil {
		t.Fatalf("decide call: %v", err)
	}
	if present {
		t.Fatal("an unconfigured proxy sent the handshake header; a PRESENT-but-empty value is " +
			"MALFORMED to the platform and refuses the request, which an absent header does not")
	}
}

// TestTheAudiencePatternIsAnchoredToTheWholeString.
//
// The same grammar is hand-ported into five clients and the end anchor means
// something different in each: Python's `$` also matches just BEFORE a trailing
// newline (it accepted "aud\n" until it was anchored with \A/\Z), and shell's
// grep is line-based (it accepted "aud\nhas spaces", putting a raw newline
// inside a JSON string). Go's `$` is end-of-text without the `m` flag, so this
// port is correct as written - but "correct as written" is exactly the claim
// that goes stale when someone adds `(?m)` or switches to FindString, so it is
// pinned rather than reasoned about.
func TestTheAudiencePatternIsAnchoredToTheWholeString(t *testing.T) {
	for _, bad := range []string{
		"aud\n",           // trailing newline: the Python defect
		"aud\nhas spaces", // embedded newline: the shell defect
		"aud\r\n",         // CRLF
		"\naud",           // leading newline
	} {
		if _, err := buildPEPHandshake(Config{PEPAudience: bad, RedactResponses: redactAlways}); err == nil {
			t.Fatalf("audience %q was accepted; a multi-line value puts a raw newline inside a JSON "+
				"string, which the platform refuses as a malformed handshake on every governed call", bad)
		}
	}
}
