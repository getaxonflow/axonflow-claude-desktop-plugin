// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRedactText_Patterns(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantToken string
		wantGone  string // substring that must be gone after redaction
	}{
		{"nik", "id is 3174012509900001 ok", "[REDACTED:nik]", "3174012509900001"},
		{"npwp_legacy", "npwp 09.254.294.3-407.000 here", "[REDACTED:npwp]", "09.254.294.3-407.000"},
		{"npwp_new_labelled", "NPWP: 0925429430700012", "[REDACTED:npwp]", "0925429430700012"},
		{"phone_plus62", "call +6281234567890 now", "[REDACTED:phone_id]", "+6281234567890"},
		{"phone_0", "call 081234567890 now", "[REDACTED:phone_id]", "081234567890"},
		{"email", "mail a.b+c@example.co.id done", "[REDACTED:email]", "a.b+c@example.co.id"},
		{"bank_bca", "BCA: 1234567890 transfer", "[REDACTED:bank_account]", "1234567890"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, res := RedactText(c.in)
			if strings.Contains(got, c.wantGone) {
				t.Fatalf("value not redacted: %q still contains %q", got, c.wantGone)
			}
			if !strings.Contains(got, c.wantToken) {
				t.Fatalf("expected token %q in %q", c.wantToken, got)
			}
			if res.Count < 1 {
				t.Fatalf("expected count>=1, got %d", res.Count)
			}
		})
	}
}

func TestRedactText_LabelPreserved(t *testing.T) {
	// Group-scoped patterns keep the label and mask only the value.
	got, _ := RedactText("BCA: 1234567890")
	if !strings.HasPrefix(got, "BCA:") {
		t.Fatalf("bank label not preserved: %q", got)
	}
}

func TestRedactText_NoPII_Unchanged(t *testing.T) {
	in := "the quarterly report shows revenue up 12 percent"
	got, res := RedactText(in)
	if got != in {
		t.Fatalf("clean text altered: %q -> %q", in, got)
	}
	if res.Count != 0 {
		t.Fatalf("clean text reported %d redactions", res.Count)
	}
}

func TestRedactText_MultiplePatterns_Counted(t *testing.T) {
	in := "nik 3174012509900001 phone +6281234567890 mail x@y.com"
	got, res := RedactText(in)
	if res.Count != 3 {
		t.Fatalf("expected 3 redactions, got %d (%v)", res.Count, res.ByType)
	}
	for _, gone := range []string{"3174012509900001", "+6281234567890", "x@y.com"} {
		if strings.Contains(got, gone) {
			t.Fatalf("%q survived: %s", gone, got)
		}
	}
}

func TestRedactResult_WalksNestedJSON(t *testing.T) {
	// Email nested in structuredContent + NIK in content text → both masked,
	// JSON structure preserved.
	in := `{"content":[{"type":"text","text":"nik 3174012509900001"}],"structuredContent":{"customer":{"email":"deep@example.com"}}}`
	out, res := redactResult([]byte(in))
	s := string(out)
	if strings.Contains(s, "3174012509900001") || strings.Contains(s, "deep@example.com") {
		t.Fatalf("nested PII not redacted: %s", s)
	}
	if res.Count != 2 {
		t.Fatalf("expected 2 nested redactions, got %d", res.Count)
	}
	// Keys must be intact (we redact values, not keys).
	if !strings.Contains(s, "\"email\"") || !strings.Contains(s, "\"customer\"") {
		t.Fatalf("redaction corrupted JSON keys: %s", s)
	}
}

func TestRedactResult_InvalidJSON_FallsBackToTextRedaction(t *testing.T) {
	out, res := redactResult([]byte("raw email leak@example.com not json"))
	if strings.Contains(string(out), "leak@example.com") {
		t.Fatalf("fallback redaction failed: %s", string(out))
	}
	if res.Count != 1 {
		t.Fatalf("expected 1 redaction in fallback, got %d", res.Count)
	}
}

func TestRedactResult_RedactsPIIKeys(t *testing.T) {
	// A record keyed by a NIK must not leak the NIK via the object key.
	in := `{"structuredContent":{"3174012509900001":{"name":"Budi","balance":5000}}}`
	out, res := redactResult([]byte(in))
	s := string(out)
	if strings.Contains(s, "3174012509900001") {
		t.Fatalf("NIK key not redacted: %s", s)
	}
	if !strings.Contains(s, "[REDACTED:nik]") {
		t.Fatalf("expected redacted key token: %s", s)
	}
	if res.Count < 1 {
		t.Fatalf("key redaction not counted: %d", res.Count)
	}
	// the nested non-PII value must survive
	if !strings.Contains(s, "Budi") || !strings.Contains(s, "5000") {
		t.Fatalf("non-PII nested data lost: %s", s)
	}
}

func TestRedactResult_TwoPIIKeys_NoCollisionLoss(t *testing.T) {
	// Two distinct NIK keys both mask to [REDACTED:nik]; the collision-suffix
	// must keep both records (no silent drop).
	in := `{"3174012509900001":{"v":1},"3201019008880002":{"v":2}}`
	out, _ := redactResult([]byte(in))
	var m map[string]interface{}
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatalf("redacted output not JSON: %v", err)
	}
	if len(m) != 2 {
		t.Fatalf("expected 2 records preserved after key collision, got %d: %s", len(m), string(out))
	}
}
