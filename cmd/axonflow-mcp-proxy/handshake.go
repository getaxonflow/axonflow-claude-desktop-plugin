package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
)

// The ADR-065 PEP capability handshake, client side (axonflow-enterprise#3763).
//
// The proxy tells the platform WHAT IT CAN DISCHARGE, on every governed call,
// as a base64url-encoded JSON document in one request header. The platform
// answers a mandatory obligation this proxy has declared it cannot discharge
// with a DENY rather than by handing the content over and hoping (ADR-065
// invariant 8).
//
// # ONE BUILDER, TWO CALL SITES
//
// The document is built and encoded ONCE, at construction, and the two governed
// call paths (decide.go and checkoutput.go) each set the resulting string. It
// is deliberately not built per request and deliberately not built twice: a
// declaration that differs between this proxy's own call paths would be a
// per-call-site dialect of a contract that is supposed to have exactly one
// shape, and the platform would attribute both to the same enforcement point.
//
// # WHAT THIS PROXY MAY DECLARE, AND WHAT IT MAY NOT
//
// It may declare what it can DO. It may not declare who it is, what edition it
// is, or what its organisation is entitled to. There is no `edition` member and
// no `tier` member, by design: a build claiming Enterprise would defeat exactly
// the over-advertising rule that exists to catch it. The platform composes the
// enforcement point's identifier as `client:<authenticated credential>:<pep_id>`,
// so `pep_id` is only a NAME INSIDE the namespace the server owns - the same
// shape as a path inside a chroot. That is why it carries no colon.
//
// # WHY THIS FILE RE-IMPLEMENTS AN ENCODER THAT EXISTS
//
// The canonical encoder is `contract.PEPHandshake.Encode` in
// axonflow-enterprise, a PRIVATE repository this public one cannot import. So
// the encoding is re-derived here from the published wire contract, which makes
// it a hand-transcription and therefore a drift risk of exactly the class that
// bit the five SDKs in #3603.
//
// The mitigation is not care, it is a GOLDEN VECTOR: handshake_test.go asserts
// the exact bytes this file produces against bytes captured from the platform's
// own shipped encoder. If either side moves, that test fails here rather than a
// customer's proxy being refused in the field.

const (
	// pepHandshakeHeader is the request header the declaration rides on.
	pepHandshakeHeader = "X-Axonflow-PEP-Handshake"
	// pepHandshakeProfileV1 is the only profile this build emits.
	//
	// Matched by the platform with EXACT EQUALITY, never as a floor or a range:
	// a build that cannot emit the named profile must not answer as though
	// negotiation succeeded.
	pepHandshakeProfileV1 = 1
	// pepID names THIS enforcement point inside the caller's credential
	// namespace.
	//
	// It matches the client-telemetry identity deliberately (see
	// axonflowClientValue in main.go) so an operator reading
	// axonflow_pep_handshake_total and axonflow_client_version_requests_total
	// sees the same name in both. The two headers remain different facts and
	// neither is derived from the other.
	pepID = "claude-desktop-plugin"
	// pepMaxHandshakeBytes bounds the encoded header value. The platform
	// refuses anything longer, so exceeding it is a build-time error here
	// rather than a 400 in the field.
	pepMaxHandshakeBytes = 4096
	// capFieldRedact is the obligation type for engine-fulfilled redaction.
	capFieldRedact = "field_redact"
	// capSchemaV1 is the schema version the platform stamps on the redaction
	// obligation it emits. Declaring a different one is declaring a capability
	// the platform will not match: the comparison is exact on BOTH type and
	// version.
	capSchemaV1 = 1
)

// pepAudiencePattern bounds the operator-supplied audience before it can reach
// the wire, so a malformed value fails at startup rather than 400-ing every
// governed call in production.
var pepAudiencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]*$`)

// pepCapability is one {type, version} pair.
type pepCapability struct {
	Type    string `json:"type"`
	Version int    `json:"version"`
}

// pepHandshakeDoc is the wire document. EVERY member is required and there is
// no optional or defaulted member; `omitempty` appears nowhere in this struct
// and its absence is load bearing.
//
// In particular Capabilities MUST NOT be omitempty. An omitted `capabilities`
// member is MALFORMED to the platform and is refused, while `[]` is the
// legitimate declaration "I discharge nothing". Those are different facts with
// different outcomes, and `omitempty` would silently turn the second into the
// first - which is precisely the absent-is-not-empty collapse the handshake
// exists to close.
type pepHandshakeDoc struct {
	ProfileVersion int             `json:"profile_version"`
	PEPID          string          `json:"pep_id"`
	Audience       string          `json:"audience"`
	Capabilities   []pepCapability `json:"capabilities"`
}

// declaredCapabilities reports what THIS proxy, as configured, can actually
// discharge.
//
// # WHY THIS READS CONFIG AND IS STILL NOT A USER-DECLARED CAPABILITY SET
//
// The rule the design states for the SDKs is that an application must not be
// able to declare arbitrary capabilities, because that would let it claim an
// obligation its own client cannot discharge. That rule is about ARBITRARY
// input, and it is kept here: there is no setting that names a capability, and
// nothing a caller sends can add one.
//
// What this function does instead is tell the truth about a configuration that
// genuinely changes what the proxy can do. A `field_redact` obligation is
// discharged by calling the fulfillment endpoint (/api/v1/mcp/check-output) and
// forwarding the engine-redacted content in place of the original - ADR-056
// forbids the proxy from redacting for itself. Under
// AXONFLOW_REDACT_RESPONSES=off the proxy NEVER calls it (see shouldRedact), so
// it genuinely cannot discharge the obligation.
//
// Declaring field_redact anyway would be the worst outcome available: the
// platform would allow the request believing a redaction was going to happen,
// and none would. Declaring the empty set makes the platform deny instead,
// which is the honest answer and the one invariant 8 requires.
func declaredCapabilities(cfg Config) []pepCapability {
	// Non-nil and empty rather than nil: the empty set must encode as `[]`,
	// which is a declaration, and never as an absent member, which is
	// malformed.
	caps := []pepCapability{}
	if cfg.RedactResponses != redactOff {
		caps = append(caps, pepCapability{Type: capFieldRedact, Version: capSchemaV1})
	}
	return caps
}

// buildPEPHandshake renders the declaration as the header value.
//
// It returns "" with no error when no audience is configured, which is the
// OPT-IN arm: no audience means no header, and the platform then behaves
// byte-for-byte as it did before this file existed.
//
// # WHY AN AUDIENCE IS REQUIRED RATHER THAN DEFAULTED
//
// The audience is what a decision proof gets bound to, and only the DEPLOYMENT
// knows it. A proxy that invented one would be asserting a binding nobody
// asked for. It is also the reason presenting a handshake is opt-in at all:
// on an Enterprise deployment the transition this gates is ALLOW -> DENY for a
// proxy configured never to redact, so it is stated on a knob an operator sets
// rather than discovered in production. The same knob name and the same
// semantics as the gateway adapters' AXONFLOW_PEP_AUDIENCE, deliberately: one
// contract, no per-client dialects.
//
// An INVALID audience is an error, not a silent skip. A misconfigured value
// that quietly disabled the handshake would leave an operator believing a
// control was in force when it was not.
func buildPEPHandshake(cfg Config) (string, error) {
	if cfg.PEPAudience == "" {
		return "", nil
	}
	if len(cfg.PEPAudience) > 128 || !pepAudiencePattern.MatchString(cfg.PEPAudience) {
		return "", fmt.Errorf(
			"invalid AXONFLOW_PEP_AUDIENCE %q: 1-128 bytes matching %s",
			cfg.PEPAudience, pepAudiencePattern)
	}

	caps := declaredCapabilities(cfg)
	// Canonical (type, version) order so two proxies declaring the same set in
	// a different order send the same bytes. The platform sorts too; agreeing
	// on the order here is what makes the encoding reproducible and the golden
	// vector meaningful.
	sort.Slice(caps, func(i, j int) bool {
		if caps[i].Type != caps[j].Type {
			return caps[i].Type < caps[j].Type
		}
		return caps[i].Version < caps[j].Version
	})

	raw, err := json.Marshal(pepHandshakeDoc{
		ProfileVersion: pepHandshakeProfileV1,
		PEPID:          pepID,
		Audience:       cfg.PEPAudience,
		Capabilities:   caps,
	})
	if err != nil {
		return "", fmt.Errorf("encoding the PEP capability handshake: %w", err)
	}

	// RAW url-safe base64: no padding. The platform accepts several alphabets
	// but this is the one its own encoder emits, and matching it byte for byte
	// is what lets the golden vector compare against captured output.
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	if len(encoded) > pepMaxHandshakeBytes {
		// Refused at CONSTRUCTION rather than on the first request: a
		// declaration the platform is certain to reject must not be a runtime
		// surprise on the governed path.
		return "", fmt.Errorf(
			"the PEP capability handshake encodes to %d bytes; the header carries at most %d",
			len(encoded), pepMaxHandshakeBytes)
	}
	return encoded, nil
}
