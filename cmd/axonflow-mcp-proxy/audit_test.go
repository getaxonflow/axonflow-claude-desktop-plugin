// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHashParameters_Deterministic(t *testing.T) {
	a := hashParameters(map[string]interface{}{"b": 2, "a": 1})
	b := hashParameters(map[string]interface{}{"a": 1, "b": 2})
	if a != b {
		t.Fatalf("hash not order-independent: %s != %s", a, b)
	}
	if len(a) != 64 {
		t.Fatalf("sha256 hex must be 64 chars, got %d", len(a))
	}
	if hashParameters(map[string]interface{}{"a": 1}) == a {
		t.Fatalf("different args must hash differently")
	}
}

func TestAuditLogger_RecordSchema(t *testing.T) {
	var captured string
	a := &AuditLogger{out: func(line string) { captured = line }}
	row := a.Record(AuditRow{
		SessionID: "s1", LeaderEmail: "l@x", ToolName: "lookup",
		ParametersHash: "abc", ResponseRecordCount: 5, DecisionID: "d1",
		Verdict: "allow", TraceID: "t1", AIAgent: "claude-desktop", GatewayID: "claude_desktop.h",
	})
	if row.Timestamp == "" {
		t.Fatalf("timestamp must be defaulted")
	}
	// All required Layer-1 fields present in the marshalled JSON.
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(captured), &m); err != nil {
		t.Fatalf("audit line not JSON: %v", err)
	}
	for _, f := range []string{"timestamp", "session_id", "leader_email", "tool_name",
		"parameters_hash", "response_record_count", "duration_ms", "decision_id",
		"verdict", "evaluated_policies", "trace_id", "ai_agent", "gateway_id"} {
		if _, ok := m[f]; !ok {
			t.Fatalf("audit row missing required field %q: %s", f, captured)
		}
	}
}

func TestAuditLogger_AppendsToFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "audit.jsonl")
	a := NewAuditLogger(path)
	a.out = func(string) {}
	a.Record(AuditRow{ToolName: "a", Verdict: "allow"})
	a.Record(AuditRow{ToolName: "b", Verdict: "deny"})
	if err := a.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("audit file not created: %v", err)
	}
	defer f.Close()
	var lines int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			lines++
		}
	}
	if lines != 2 {
		t.Fatalf("expected 2 audit lines, got %d", lines)
	}
}
