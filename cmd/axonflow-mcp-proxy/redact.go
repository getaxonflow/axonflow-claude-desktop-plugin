// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"regexp"
)

// Response-side PII redaction.
//
// When Decision Mode returns an allow verdict carrying a `redact_pii`
// obligation, the proxy MUST strip PII from the tool RESPONSE before it
// reaches Claude Desktop's context window. This is the load-bearing control
// in BukuWarung's R&C §4.3: "the most reliable compliance control … is
// preventing sensitive personal data from entering Claude's context window …
// at the MCP server layer." If no PII crosses into the context, the UU PDP
// Pasal-56 cross-border trigger is removed.
//
// The patterns below are a deliberately self-contained, defense-in-depth
// MIRROR of the platform's Indonesia + generic PII categories
// (platform/agent/indonesia/pii_detector.go) — the proxy is a separate Go
// module and does not import the BUSL-licensed platform package. The platform
// remains the authoritative detector at the gate; this redactor is the
// last-line response filter the obligation asks the PEP to apply.
//
// Coverage & limitations (stated plainly — this is a regex filter, NOT a
// complete DLP engine):
//   - Covers: PII in string AND numeric leaf VALUES, and in object KEYS, at any
//     nesting depth (redactResult walks keys + values recursively).
//   - Does NOT catch PII split across separate JSON array elements
//     (e.g. ["3174","0125","0990","0001"] reassembling to a NIK) — each element
//     is scanned independently and no element matches on its own.
//   - Does NOT decode transformed PII: base64 / hex / URL-encoded values pass
//     through unmatched.
//   - Patterns are tuned for Indonesian + generic identifiers; other-locale PII
//     (e.g. US SSN) is not covered here — add patterns as needed.
// The fix for the gaps above is policy at the gate (block the call) or a
// purpose-built backend that never emits the data — not this last-line filter.

// piiPattern is one named redaction rule.
type piiPattern struct {
	name string
	re   *regexp.Regexp
	// group is the submatch index to mask. 0 = mask the whole match; >0 masks
	// only that capture group (so a labelled pattern like "NPWP: 0123..." keeps
	// the label and masks only the number).
	group int
}

// piiPatterns is the ordered redaction rule set. Order matters: the most
// specific / highest-value identifiers run first so a NIK is masked as a NIK
// rather than being partially eaten by a looser numeric rule.
//
// Patterns mirror platform/agent/indonesia/pii_detector.go (NIK, NPWP legacy/
// new, +62 phone, bank accounts) plus two universally-sensitive generics
// (email, payment-card) that any tool response can leak.
var piiPatterns = []piiPattern{
	// NPWP legacy — NN.NNN.NNN.N-NNN.NNN. Runs first (separators make it
	// unambiguous) so it can't be eaten by the bare-digit rules below.
	{name: "npwp", re: regexp.MustCompile(`\b\d{2}\.\d{3}\.\d{3}\.\d{1}-\d{3}\.\d{3}\b`), group: 0},
	// NPWP new — 16-digit, label-anchored. Runs before the bare NIK rule so a
	// labelled "NPWP: <16 digits>" is tagged npwp, not nik; masks the number
	// group only, keeping the label for audit readability.
	{name: "npwp", re: regexp.MustCompile(`(?i)(?:NPWP|tax[\s_-]*(?:id|number|no)|nomor[\s_-]*pokok)[:\s]+(\d{16})\b`), group: 1},
	// Bank accounts — label-anchored Indonesian bank account numbers (10–15
	// digits); mask the number group, keep the bank label.
	{name: "bank_account", re: regexp.MustCompile(`(?i)(?:BCA|bank[\s_-]*central[\s_-]*asia|mandiri|bank[\s_-]*mandiri|BRI|bank[\s_-]*rakyat|BNI|bank[\s_-]*negara|rek(?:ening)?)[:\s]+(\d{10,15})\b`), group: 1},
	// NIK — 16-digit Indonesian national ID (province/regency prefix + DDMMYY
	// + serial). Bare 16-digit run; runs after the labelled 16-digit NPWP rule.
	{name: "nik", re: regexp.MustCompile(`\b\d{16}\b`), group: 0},
	// Indonesian mobile — +62 / 62 / 0 followed by 8X and 6–10 more digits.
	{name: "phone_id", re: regexp.MustCompile(`\b(?:\+?62|0)8[1-9]\d{6,10}\b`), group: 0},
	// Email — generic, universally sensitive.
	{name: "email", re: regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`), group: 0},
	// Payment card — 13–19 digit PAN, optionally space/dash grouped. Loose by
	// design: over-redaction of a long digit run is the safe failure mode.
	{name: "card", re: regexp.MustCompile(`\b(?:\d[ -]*?){13,19}\b`), group: 0},
}

// RedactionResult reports what a redaction pass did, for the audit trail.
type RedactionResult struct {
	// Count is the total number of PII spans masked.
	Count int
	// ByType counts masked spans per pattern name (nik, email, …).
	ByType map[string]int
}

// RedactText masks every PII span in s and returns the cleaned string plus a
// summary. It is a pure function (no I/O, no globals beyond the compiled
// pattern table) so the full pattern matrix is unit-testable.
//
// Masking uses a stable token `[REDACTED:<type>]` so a downstream reader (and
// the demo) can see WHAT was stripped without seeing the value. Group-scoped
// patterns mask only the captured submatch, preserving the surrounding label.
func RedactText(s string) (string, RedactionResult) {
	res := RedactionResult{ByType: map[string]int{}}
	for _, p := range piiPatterns {
		token := "[REDACTED:" + p.name + "]"
		s = p.re.ReplaceAllStringFunc(s, func(match string) string {
			if p.group == 0 {
				res.Count++
				res.ByType[p.name]++
				return token
			}
			// Group-scoped: replace only the captured submatch within match.
			sub := p.re.FindStringSubmatchIndex(match)
			if sub == nil || len(sub) <= 2*p.group+1 || sub[2*p.group] < 0 {
				return match // no capture — leave untouched
			}
			start, end := sub[2*p.group], sub[2*p.group+1]
			res.Count++
			res.ByType[p.name]++
			return match[:start] + token + match[end:]
		})
	}
	return s, res
}
