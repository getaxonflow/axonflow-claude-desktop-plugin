// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

// Command bukuwarung-backend is a REAL MCP server built on the official
// Model Context Protocol Go SDK (github.com/modelcontextprotocol/go-sdk/mcp).
//
// It is the backend the AxonFlow governance proxy fronts in the CLI-harness
// runtime-e2e (runtime-e2e/cli-harness/). It is deliberately NOT the hand-rolled
// JSON-RPC stub in ../../stub-mcp-server (that backs the original #2520
// proxy-vs-stub coverage); this harness exercises the proxy in front of a
// genuine SDK-based server, driven by a genuine MCP client (Claude Code), so the
// whole chain — client → proxy → backend — is real.
//
// It stands in for a BukuWarung back-office MCP server (Panacea / CRM / ledger)
// and returns Indonesian-PII-bearing records so the proxy's redact_pii
// obligation is observable end-to-end, including a record keyed by a NIK (the
// §4.3 key-redaction fix in the proxy).
//
//	tools:
//	  export_ledger    → N ledger rows, no PII                 (ALLOW path)
//	  lookup_customer  → a customer record with NIK/email/+62  (REDACT path),
//	                     plus related_accounts keyed BY NIK     (§4.3 key redaction)
//	  run_sql_report   → echoes the SQL it would run            (DENY path: the
//	                     SQL arg carries the injection the PDP blocks)
//
// All diagnostics go to stderr; stdout is the MCP stdio JSON-RPC channel.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- tool input types (the SDK derives the JSON input schema from these) ------

type exportLedgerIn struct {
	Rows int `json:"rows" jsonschema:"number of ledger rows to export"`
}

type lookupCustomerIn struct {
	// Aadhaar is the request-side trigger: an RBI-India identifier the AxonFlow
	// PDP attaches a redact_pii obligation to (policy sys_pii_aadhaar). The proxy
	// then strips the Indonesian PII this tool returns.
	Aadhaar    string `json:"aadhaar" jsonschema:"the customer's Aadhaar number to look up by"`
	CustomerID string `json:"customer_id,omitempty" jsonschema:"optional customer id"`
}

type runSQLReportIn struct {
	SQL string `json:"sql" jsonschema:"the SQL the report would run"`
}

// --- tool output types (the SDK emits these as structuredContent) -------------
//
// Every Out is an OBJECT: the official SDK rejects a tool whose output schema is
// a bare array/scalar ("output schema must have type object"), so a list result
// is wrapped in a struct.

type ledgerRow struct {
	Row    int `json:"row"`
	Amount int `json:"amount"`
}

type ledgerOut struct {
	Rows []ledgerRow `json:"rows"`
}

type sqlReportOut struct {
	WouldRun string `json:"would_run"`
	Engine   string `json:"engine"`
}

type account struct {
	Bank    string `json:"bank"`
	Balance int    `json:"balance_idr"`
}

type customerOut struct {
	CustomerID string `json:"customer_id"`
	Name       string `json:"name"`
	NIK        string `json:"nik"`
	Email      string `json:"email"`
	Phone      string `json:"phone"`
	Status     string `json:"status"`
	// RelatedAccounts is keyed BY NIK on purpose: a record keyed by PII leaks the
	// key unless the redactor masks object keys too (proxy redactValue, §4.3).
	RelatedAccounts map[string]account `json:"related_accounts"`
}

func textResult(v any) *mcp.CallToolResult {
	b, err := json.Marshal(v)
	if err != nil {
		b = []byte(fmt.Sprintf("%v", v))
	}
	// Return the payload as text content AND let the SDK also set
	// structuredContent from the typed Out — the proxy redacts both paths.
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(b)}}}
}

func handleExportLedger(_ context.Context, _ *mcp.CallToolRequest, in exportLedgerIn) (*mcp.CallToolResult, ledgerOut, error) {
	n := in.Rows
	if n <= 0 {
		n = 3
	}
	rows := make([]ledgerRow, 0, n)
	for i := 0; i < n; i++ {
		rows = append(rows, ledgerRow{Row: i, Amount: 1000 + i})
	}
	// Content text is the bare rows array so the proxy's response_record_count
	// heuristic sees N records; structuredContent carries the wrapper object.
	return textResult(rows), ledgerOut{Rows: rows}, nil
}

func handleLookupCustomer(_ context.Context, _ *mcp.CallToolRequest, in lookupCustomerIn) (*mcp.CallToolResult, customerOut, error) {
	id := in.CustomerID
	if id == "" {
		id = "CUST-001"
	}
	out := customerOut{
		CustomerID: id,
		Name:       "Budi Santoso",
		NIK:        "3174012509900001",           // 16-digit Indonesian national ID
		Email:      "budi.santoso@example.co.id", // generic PII
		Phone:      "+6281234567890",             // +62 mobile
		Status:     "active",
		RelatedAccounts: map[string]account{
			// keyed BY NIK — exercises object-KEY redaction (§4.3).
			"3174012509900001": {Bank: "BCA", Balance: 5_000_000},
		},
	}
	return textResult(out), out, nil
}

func handleRunSQLReport(_ context.Context, _ *mcp.CallToolRequest, in runSQLReportIn) (*mcp.CallToolResult, sqlReportOut, error) {
	// The proxy NEVER reaches this handler on the deny path — the PDP blocks the
	// call because in.SQL carries the injection. If execution gets here at all
	// during the deny test, the assertion fails (backend was reached). On a
	// benign SQL it just echoes, proving the tool is otherwise callable.
	out := sqlReportOut{WouldRun: in.SQL, Engine: "bukuwarung-reporting"}
	return textResult(out), out, nil
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("bukuwarung-backend ")

	server := mcp.NewServer(&mcp.Implementation{Name: "bukuwarung-backend", Version: "1.0.0"}, nil)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "export_ledger",
		Description: "Export the last N BukuWarung ledger rows (no PII).",
	}, handleExportLedger)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "lookup_customer",
		Description: "Look up a BukuWarung customer by Aadhaar (returns the customer's Indonesian PII and related accounts).",
	}, handleLookupCustomer)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "run_sql_report",
		Description: "Run a read-only reporting SQL query and return the rows.",
	}, handleRunSQLReport)

	log.Printf("starting stdio MCP server (export_ledger, lookup_customer, run_sql_report)")
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server.Run: %v", err)
	}
}
