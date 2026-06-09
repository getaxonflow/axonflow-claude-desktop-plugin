// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

// Command stub-mcp-server is a minimal stdio MCP server used by the runtime-e2e
// harness as a backend behind the AxonFlow governance proxy. It stands in for a
// real BukuWarung backend (Panacea/CRM/BigQuery) and deliberately returns
// PII-bearing records so the proxy's redact_pii obligation is observable
// end-to-end.
//
// It speaks newline-delimited JSON-RPC 2.0 over stdin/stdout (MCP stdio
// transport) and implements initialize, tools/list, and tools/call for:
//
//   - lookup_customer  → returns a record containing NIK / email / phone / SSN (PII)
//   - export_ledger    → returns a JSON array of N rows (record-count check)
//
// All diagnostics go to stderr so stdout stays a clean JSON-RPC channel.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("stub-mcp-server ")
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)
	w := bufio.NewWriter(os.Stdout)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			log.Printf("undecodable line: %v", err)
			continue
		}
		resp, respond := handle(&req)
		if !respond {
			continue
		}
		out, _ := json.Marshal(resp)
		w.Write(out)
		w.WriteByte('\n')
		w.Flush()
	}
}

func handle(req *rpcRequest) (rpcResponse, bool) {
	switch req.Method {
	case "initialize":
		return ok(req.ID, map[string]interface{}{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]interface{}{"tools": map[string]interface{}{}},
			"serverInfo":      map[string]string{"name": "stub-mcp-server", "version": "0.1.0"},
		}), true
	case "notifications/initialized":
		return rpcResponse{}, false
	case "tools/list":
		return ok(req.ID, map[string]interface{}{"tools": tools()}), true
	case "tools/call":
		return handleCall(req)
	default:
		return errResp(req.ID, -32601, "method not found: "+req.Method), true
	}
}

func tools() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "lookup_customer",
			"description": "Look up a customer record by id (returns PII).",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{"customer_id": map[string]string{"type": "string"}},
				"required":   []string{"customer_id"},
			},
		},
		{
			"name":        "export_ledger",
			"description": "Export the last N ledger rows.",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{"rows": map[string]string{"type": "number"}},
			},
		},
	}
}

func handleCall(req *rpcRequest) (rpcResponse, bool) {
	var params struct {
		Name      string                 `json:"name"`
		Arguments map[string]interface{} `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return errResp(req.ID, -32602, "invalid params"), true
	}
	switch params.Name {
	case "lookup_customer":
		// PII-bearing record: NIK (16 digits), email, +62 phone, US SSN.
		record := map[string]interface{}{
			"customer_id": params.Arguments["customer_id"],
			"name":        "Budi Santoso",
			"nik":         "3174012509900001",           // Indonesian KTP/NIK
			"email":       "budi.santoso@example.co.id", // generic email
			"phone":       "+6281234567890",             // +62 Indonesian mobile
			"ssn":         "123-45-6789",                // US SSN (#2565 coverage)
			"status":      "active",
		}
		text := mustJSON(record)
		return ok(req.ID, map[string]interface{}{
			"content": []map[string]interface{}{{"type": "text", "text": text}},
		}), true
	case "export_ledger":
		n := 3
		if v, okv := params.Arguments["rows"].(float64); okv && v > 0 {
			n = int(v)
		}
		rows := make([]map[string]interface{}, 0, n)
		for i := 0; i < n; i++ {
			rows = append(rows, map[string]interface{}{"row": i, "amount": 1000 + i})
		}
		return ok(req.ID, map[string]interface{}{
			"content": []map[string]interface{}{{"type": "text", "text": mustJSON(rows)}},
		}), true
	default:
		return errResp(req.ID, -32602, "unknown tool: "+params.Name), true
	}
}

func ok(id json.RawMessage, result interface{}) rpcResponse {
	b, _ := json.Marshal(result)
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: b}
}

func errResp(id json.RawMessage, code int, msg string) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{Code: code, Message: msg}}
}

func mustJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}
