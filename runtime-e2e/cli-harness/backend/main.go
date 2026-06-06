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
//	  export_ledger     → N ledger rows, no PII                (ALLOW path)
//	  get_sales_summary → aggregate figures, no PII            (ALLOW path)
//	  lookup_customer   → a customer record with NIK/email/+62 (REDACT path),
//	                      plus related_accounts keyed BY NIK    (§4.3 key redaction).
//	                      Takes a clean customer_id — NO PII in the request — so
//	                      the response-only redaction path is exercised (#2530).
//	  get_bank_details  → bank account + NPWP in free text     (REDACT, response-only)
//	  list_contacts     → array of {email,+62 phone} rows      (REDACT, array/nested)
//	  run_sql_report    → echoes the SQL it would run          (DENY path: the
//	                      SQL arg carries the injection the PDP blocks)
//	  run_command       → echoes the shell command             (DENY path:
//	                      dangerous-command policies)
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
	// Aadhaar is OPTIONAL and test-only: it lets the matrix put PII in the REQUEST
	// (firing a redact_pii obligation) while the RESPONSE stays PII-free — the
	// "request-only" precondition cell. The handler ignores it. Declared so the
	// official SDK's strict input schema accepts the arg instead of rejecting it.
	Aadhaar string `json:"aadhaar,omitempty" jsonschema:"optional Aadhaar (test-only: puts PII in the request, ignored by the handler)"`
}

type lookupCustomerIn struct {
	// CustomerID is the ONLY natural argument: a clean, non-PII lookup key. A bare
	// {"customer_id":"CUST-001"} call carries NO PII in the request, yet the
	// response is PII-laden — this is exactly the precondition-absent case that
	// obligation-gated redaction used to leak (the §4.3 hole, #2530). It is
	// OPTIONAL so an even-emptier {} call still returns a record.
	CustomerID string `json:"customer_id,omitempty" jsonschema:"the customer id to look up (e.g. CUST-001)"`
	// Aadhaar is OPTIONAL and exists only so a test can ALSO put PII in the
	// request (the "both" / "request-only" matrix cells). It is no longer required
	// — and redaction no longer depends on it firing a redact_pii obligation.
	// Previously this field was required, which structurally forced PII into every
	// redact request and hid the response-only leak.
	Aadhaar string `json:"aadhaar,omitempty" jsonschema:"optional Aadhaar to look up by (test-only: puts PII in the request)"`
}

type getBankDetailsIn struct {
	AccountID string `json:"account_id,omitempty" jsonschema:"the internal account id to fetch details for"`
}

type getSalesSummaryIn struct {
	Period string `json:"period,omitempty" jsonschema:"reporting period, e.g. 2026-Q2"`
}

type listContactsIn struct {
	Limit int `json:"limit,omitempty" jsonschema:"max contacts to return"`
}

type runSQLReportIn struct {
	SQL string `json:"sql" jsonschema:"the SQL the report would run"`
}

type runCommandIn struct {
	Command string `json:"command" jsonschema:"the shell command to run"`
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

type commandOut struct {
	Executed string `json:"executed"`
	Shell    string `json:"shell"`
}

type account struct {
	Bank    string `json:"bank"`
	Balance int    `json:"balance_idr"`
}

// bankDetailsOut carries label-anchored Indonesian PII (bank account + NPWP)
// with NO PII in the request — a second response-only redaction case covering
// the bank_account + npwp patterns, distinct from lookup_customer's NIK/email.
type bankDetailsOut struct {
	AccountID string `json:"account_id"`
	Holder    string `json:"holder"`
	Detail    string `json:"detail"` // free text carrying "BCA: <digits>" + "NPWP: <16 digits>"
}

// contact is one row in a list; list_contacts returns several, exercising
// array/nested redaction (email + +62 phone in every element).
type contact struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type contactsOut struct {
	Contacts []contact `json:"contacts"`
}

// salesSummaryOut is pure aggregates — NO PII. The "allow (aggregates)" case:
// a benign analytical call that forwards untouched and triggers zero redactions.
type salesSummaryOut struct {
	Period      string `json:"period"`
	TotalIDR    int    `json:"total_idr"`
	OrderCount  int    `json:"order_count"`
	AvgOrderIDR int    `json:"avg_order_idr"`
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

func handleRunCommand(_ context.Context, _ *mcp.CallToolRequest, in runCommandIn) (*mcp.CallToolResult, commandOut, error) {
	// Deny path for dangerous-command policies. The unique echo "bukuwarung-shell"
	// proves backend reach on the deny test — it must be ABSENT from any blocked
	// call's response.
	out := commandOut{Executed: in.Command, Shell: "bukuwarung-shell"}
	return textResult(out), out, nil
}

func handleGetBankDetails(_ context.Context, _ *mcp.CallToolRequest, in getBankDetailsIn) (*mcp.CallToolResult, bankDetailsOut, error) {
	id := in.AccountID
	if id == "" {
		id = "ACC-7781"
	}
	// Response-only PII: bank account (label-anchored) + NPWP. The request
	// (account_id) carries NO PII, so a redact_pii obligation does NOT fire on the
	// live PDP — the proxy must redact this on its own (default-always).
	out := bankDetailsOut{
		AccountID: id,
		Holder:    "Siti Rahayu",
		Detail:    "BCA: 1234567890 — NPWP: 0925429430700012 — settlement account",
	}
	return textResult(out), out, nil
}

func handleListContacts(_ context.Context, _ *mcp.CallToolRequest, in listContactsIn) (*mcp.CallToolResult, contactsOut, error) {
	n := in.Limit
	if n <= 0 || n > 3 {
		n = 2
	}
	all := []contact{
		{Name: "Budi Santoso", Email: "budi.santoso@example.co.id", Phone: "+6281234567890"},
		{Name: "Siti Rahayu", Email: "siti.rahayu@example.co.id", Phone: "081298765432"},
		{Name: "Andi Wijaya", Email: "andi.wijaya@example.co.id", Phone: "+6285711112222"},
	}
	out := contactsOut{Contacts: all[:n]}
	// Content text is the bare contacts array so PII sits inside JSON array
	// elements — exercising array/nested redaction across multiple records.
	return textResult(out.Contacts), out, nil
}

func handleGetSalesSummary(_ context.Context, _ *mcp.CallToolRequest, in getSalesSummaryIn) (*mcp.CallToolResult, salesSummaryOut, error) {
	p := in.Period
	if p == "" {
		p = "2026-Q2"
	}
	// Pure aggregates, NO PII — a benign allow that must forward untouched with
	// zero redactions (the leak detector also confirms nothing was over-masked).
	out := salesSummaryOut{Period: p, TotalIDR: 487_500_000, OrderCount: 1320, AvgOrderIDR: 369_318}
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
		Description: "Look up a BukuWarung customer by customer_id (returns the customer's Indonesian PII and related accounts).",
	}, handleLookupCustomer)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_bank_details",
		Description: "Fetch a settlement account's bank/NPWP details by account_id (returns label-anchored Indonesian PII).",
	}, handleGetBankDetails)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_contacts",
		Description: "List back-office contacts (each row carries an email and Indonesian phone).",
	}, handleListContacts)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "get_sales_summary",
		Description: "Return aggregate sales figures for a period (no PII).",
	}, handleGetSalesSummary)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "run_sql_report",
		Description: "Run a read-only reporting SQL query and return the rows.",
	}, handleRunSQLReport)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "run_command",
		Description: "Run a maintenance shell command on the reporting host.",
	}, handleRunCommand)

	log.Printf("starting stdio MCP server (export_ledger, lookup_customer, get_bank_details, list_contacts, get_sales_summary, run_sql_report, run_command)")
	if err := server.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		log.Fatalf("server.Run: %v", err)
	}
}
