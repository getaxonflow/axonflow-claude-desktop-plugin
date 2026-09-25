// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// maxRefusalTextRunes caps the platform text quoted into a refusal message.
const maxRefusalTextRunes = 300

// refusalMessage is the ONE place a 4xx from the policy service becomes the
// text the user reads. Every such refusal stays JSON-RPC -32003 and fails
// closed; only the words differ, so a quota is never described as a credential
// problem and a credential problem never as a policy deny.
//
// subject names the plane: "policy service" for decide, "response governance"
// for check-output.
//
// The body's `verdict` is deliberately IGNORED. On decide every error body is a
// DecideErrorResponse carrying `verdict: deny` (a 400 for a malformed body, a
// 401, a 403 for a mismatched organization alike): that is a fail-closed
// envelope, not a policy decision, and reading it as one would turn a
// credential rejection into a -32001 policy deny.
func refusalMessage(subject string, ce *clientError) string {
	said, limitType, resetsAt := platformErrorText(ce.Body)
	limit := limitSuffix(limitType, resetsAt, ce.RetryAfter)
	switch {
	case ce.StatusCode == 401:
		return fmt.Sprintf("%s rejected the proxy's credentials (HTTP 401): %s. Check AXONFLOW_CLIENT_ID, AXONFLOW_CLIENT_SECRET and AXONFLOW_USER_TOKEN", subject, strings.TrimRight(said, "."))
	case ce.StatusCode == 402:
		return fmt.Sprintf("%s refused the request: a tier limit of this deployment was reached (HTTP 402%s): %s", subject, limit, said)
	case ce.StatusCode == 429:
		return fmt.Sprintf("%s refused the request: a rate limit was reached (HTTP 429%s): %s", subject, limit, said)
	case limitType != "":
		return fmt.Sprintf("%s refused the request: a tier limit was reached (HTTP %d%s): %s", subject, ce.StatusCode, limit, said)
	case ce.StatusCode == 404 || ce.StatusCode == 405:
		return fmt.Sprintf("%s rejected the request (HTTP %d): %s. Check AXONFLOW_ENDPOINT: it may not point at an AxonFlow agent that serves this route", subject, ce.StatusCode, strings.TrimRight(said, "."))
	default:
		return fmt.Sprintf("%s rejected the request (HTTP %d): %s", subject, ce.StatusCode, said)
	}
}

// platformErrorText reads the platform's words from an error body, which comes
// in three shapes on the routes this proxy calls: `{"error": "..."}` (a
// DecideErrorResponse, a handler-written error, a RateLimitEnvelope),
// `{"error": {"code": N, "message": "..."}}` (the middleware's JSONError, which
// is also how decide answers a 402), and anything else, quoted raw. It also
// returns the RateLimitEnvelope's limit_type and resets_at when they are
// strings.
func platformErrorText(body string) (text, limitType, resetsAt string) {
	// Every field is decoded raw and read as a string only when it IS one, so
	// one mistyped field (a numeric limit_type) cannot hide the others.
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(body), &parsed); err == nil {
		limitType = cleanRefusalText(jsonString(parsed["limit_type"]))
		resetsAt = cleanRefusalText(jsonString(parsed["resets_at"]))
		var asObject map[string]json.RawMessage
		switch {
		case jsonIsString(parsed["error"]):
			text = jsonString(parsed["error"])
		case json.Unmarshal(parsed["error"], &asObject) == nil && jsonIsString(asObject["message"]):
			text = jsonString(asObject["message"])
			// A string code (ERR_...) is kept; a numeric one repeats the HTTP
			// status the message already names.
			if code := jsonString(asObject["code"]); code != "" {
				text = code + ": " + text
			}
		case jsonIsString(parsed["message"]):
			text = jsonString(parsed["message"])
		default:
			text = body
		}
	} else {
		text = body
	}
	if text = cleanRefusalText(text); text == "" {
		text = "(the response carried no error text)"
	}
	return text, limitType, resetsAt
}

// jsonIsString reports whether a raw JSON value is a string. A JSON null is
// not: encoding/json decodes null into a string without an error.
func jsonIsString(raw json.RawMessage) bool {
	var s string
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '"' && json.Unmarshal(trimmed, &s) == nil
}

// jsonString returns a raw JSON value's string, or "" when it is not a string.
func jsonString(raw json.RawMessage) string {
	var s string
	if !jsonIsString(raw) || json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// limitSuffix renders `, limit_type "daily_quota", resets at <time>, retry
// after 30 s` from whichever parts are present. A resets_at that is not an
// RFC 3339 time is quoted as given and marked; a Retry-After that is not a
// whole number of seconds is omitted.
func limitSuffix(limitType, resetsAt, retryAfter string) string {
	var parts []string
	if limitType != "" {
		parts = append(parts, fmt.Sprintf("limit_type %q", limitType))
	}
	if resetsAt != "" {
		if _, err := time.Parse(time.RFC3339, resetsAt); err == nil {
			parts = append(parts, "resets at "+resetsAt)
		} else {
			parts = append(parts, fmt.Sprintf("resets_at %q (not a date)", resetsAt))
		}
	}
	if ra := strings.TrimSpace(retryAfter); ra != "" && isAllDigits(ra) {
		parts = append(parts, "retry after "+ra+" s")
	}
	if len(parts) == 0 {
		return ""
	}
	return ", " + strings.Join(parts, ", ")
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// cleanRefusalText makes platform text safe for a one-line message: control
// characters (C0, DEL, C1), format characters (bidi overrides, zero-width
// characters) and line and paragraph separators become spaces, runs of spaces
// collapse, and the result is capped at maxRefusalTextRunes runes.
func cleanRefusalText(s string) string {
	var b strings.Builder
	lastSpace := false
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\u2028' || r == '\u2029' || r == ' ' {
			if !lastSpace {
				b.WriteByte(' ')
			}
			lastSpace = true
			continue
		}
		b.WriteRune(r)
		lastSpace = false
	}
	out := strings.TrimSpace(b.String())
	if utf8.RuneCountInString(out) > maxRefusalTextRunes {
		runes := []rune(out)
		out = string(runes[:maxRefusalTextRunes]) + "…"
	}
	return out
}

// denyReason renders a deny's reasons for the JSON-RPC message: every reason,
// in the platform's order, joined with "; ", cleaned and capped like refusal
// text. The machine code the platform sends first (e.g. unknown_constraint)
// stays first, so a script matching on it still matches; the sentence after it
// is what a person needs to read. data.reasons keeps them verbatim.
func denyReason(reasons []string, fallback string) string {
	var kept []string
	for _, r := range reasons {
		if r = cleanRefusalText(r); r != "" {
			kept = append(kept, r)
		}
	}
	if len(kept) == 0 {
		return fallback
	}
	return cleanRefusalText(strings.Join(kept, "; "))
}
