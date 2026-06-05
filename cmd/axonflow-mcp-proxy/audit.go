// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Layer-1 audit (BukuWarung 4-layer audit framework, Layer 1: MCP-server
// logging). Each governed tools/call writes exactly one JSON line. The schema
// is field-for-field identical to the Python reference
// (examples/mcp-decision-mode/audit_log.py) so a single SIEM parser ingests
// both the reference PEP and this proxy.
//
// Required Risk-Committee field set: timestamp, session_id, leader_email,
// tool_name, parameters_hash, response_record_count, duration_ms. The AxonFlow
// correlation fields (decision_id, verdict, evaluated_policies, trace_id,
// ai_agent) are appended so the row joins to the platform decision record.

// AuditRow is one Layer-1 record. Field order in the struct matches the
// reference schema so the marshalled JSON reads top-to-bottom as the Risk
// Committee defined it.
type AuditRow struct {
	Timestamp           string `json:"timestamp"`
	SessionID           string `json:"session_id"`
	LeaderEmail         string `json:"leader_email"`
	ToolName            string `json:"tool_name"`
	ParametersHash      string `json:"parameters_hash"`
	ResponseRecordCount int    `json:"response_record_count"`
	DurationMs          int64  `json:"duration_ms"`
	// AxonFlow decision correlation.
	DecisionID        string   `json:"decision_id"`
	Verdict           string   `json:"verdict"`
	EvaluatedPolicies []string `json:"evaluated_policies"`
	TraceID           string   `json:"trace_id"`
	// Layer-2 evidence: the AI-agent + gateway identity forwarded to the PDP.
	AIAgent   string `json:"ai_agent"`
	GatewayID string `json:"gateway_id"`
	// RedactionCount is the number of PII spans stripped from the response
	// before it reached Claude's context (0 when no redact obligation fired).
	RedactionCount int `json:"redaction_count"`
}

// hashParameters returns the sha256 hex digest of a tool's arguments,
// canonicalized with sorted keys + compact separators so identical arguments
// always hash identically. The audit row logs the HASH, never the raw
// arguments, so the trail proves which call was made without persisting
// argument values that may carry PII. Mirrors audit_log.hash_parameters.
func hashParameters(args map[string]interface{}) string {
	canonical := canonicalJSON(args)
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// canonicalJSON renders v with deterministic key ordering. Go's encoding/json
// already sorts map[string]... keys, so a plain Marshal is canonical for our
// argument maps; we route through it in one place so the contract is explicit
// and matches the Python json.dumps(sort_keys=True, separators=(",",":")).
func canonicalJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// AuditLogger appends Layer-1 rows. It always echoes each row to stderr as
// structured JSON (so the demo + Greg's e2e can read the trail off the process
// log) and, when a path is configured, also appends to an on-disk JSONL file.
// Writes are mutex-guarded so concurrent tools/call handlers can't interleave
// partial lines.
type AuditLogger struct {
	path string
	mu   sync.Mutex
	// out is the stderr sink (overridable in tests). file is the optional
	// on-disk JSONL appender, opened lazily on first write.
	out  func(line string)
	file *os.File
}

// NewAuditLogger builds an AuditLogger writing to the given path (empty →
// stderr only) and echoing to stderr via the package logger.
func NewAuditLogger(path string) *AuditLogger {
	return &AuditLogger{
		path: path,
		out:  func(line string) { logStderr("AUDIT %s", line) },
	}
}

// Record builds, writes, and returns one audit row. Returning the row lets the
// e2e harness assert the exact emitted shape inline. timestamp defaults to now
// (UTC, RFC3339) when row.Timestamp is empty.
func (a *AuditLogger) Record(row AuditRow) AuditRow {
	if row.Timestamp == "" {
		row.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if row.EvaluatedPolicies == nil {
		row.EvaluatedPolicies = []string{}
	}
	line, err := json.Marshal(row)
	if err != nil {
		logStderr("audit marshal failed (non-fatal): %v", err)
		return row
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	if a.out != nil {
		a.out(string(line))
	}
	if a.path != "" {
		if err := a.appendLocked(string(line)); err != nil {
			logStderr("audit file write failed (non-fatal): %v", err)
		}
	}
	return row
}

// appendLocked appends one line to the on-disk JSONL file, opening it on first
// use. Caller holds a.mu. A file error is non-fatal: the stderr echo already
// captured the row, so a full disk degrades audit durability without dropping
// the record from the process log or changing the enforcement decision.
func (a *AuditLogger) appendLocked(line string) error {
	if a.file == nil {
		if dir := filepath.Dir(a.path); dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("mkdir audit dir: %w", err)
			}
		}
		f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return fmt.Errorf("open audit file: %w", err)
		}
		a.file = f
	}
	if _, err := a.file.WriteString(line + "\n"); err != nil {
		return fmt.Errorf("write audit line: %w", err)
	}
	return nil
}

// Close releases the on-disk file handle, if open.
func (a *AuditLogger) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.file != nil {
		err := a.file.Close()
		a.file = nil
		return err
	}
	return nil
}

// redactionByTypeSorted renders a ByType map as a stable "type:count" list for
// human-readable logging (deterministic order for test assertions).
func redactionByTypeSorted(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s:%d", k, m[k]))
	}
	return out
}
