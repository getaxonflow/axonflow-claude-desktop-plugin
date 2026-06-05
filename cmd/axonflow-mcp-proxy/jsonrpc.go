// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

package main

import "encoding/json"

// JSON-RPC 2.0 + MCP message types.
//
// Claude Desktop launches a .mcpb extension as a stdio MCP server: it speaks
// newline-delimited JSON-RPC 2.0 over the extension's stdin/stdout (one
// compact JSON object per line, no embedded newlines — MCP stdio transport).
// The proxy is BOTH an MCP server (to Claude Desktop) and an MCP client (to
// each backend server it fronts), so the same wire types are used in both
// directions.

// JSON-RPC error codes. The -32xxx block below 32000 is the JSON-RPC
// reserved range; -32001/-32002/-32003 are the AxonFlow Decision Mode
// verdict codes, kept byte-for-byte identical to the reference adapter
// (examples/integrations/decision-mode-mcp-adapter/main.go) so a backend or
// client that already understands the adapter understands the proxy.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603

	// codePolicyDeny is returned to Claude Desktop when Decision Mode denies
	// a tools/call. The user sees the deny reason in the tool error.
	codePolicyDeny = -32001
	// codeNeedsApproval is returned when the verdict is needs_approval — the
	// call is held pending a human approval (HITL) and not forwarded.
	codeNeedsApproval = -32002
	// codePolicyUnavailable is returned when the PDP is unreachable/degraded
	// and the configured posture is fail-closed (the fintech default).
	codePolicyUnavailable = -32003
)

// JSONRPCRequest is an inbound or outbound JSON-RPC 2.0 request/notification.
// A notification has a nil ID (MCP sends notifications/initialized,
// notifications/cancelled, etc. with no id and expects no response).
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// isNotification reports whether the message is a notification (no id) and
// therefore must NOT receive a response per JSON-RPC 2.0.
func (r *JSONRPCRequest) isNotification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// JSONRPCResponse is an outbound or inbound JSON-RPC 2.0 response. Exactly one
// of Result / Error is set.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
}

// JSONRPCError is the error object of a JSON-RPC 2.0 response.
type JSONRPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// ToolCallParams is the params of an MCP tools/call request.
type ToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// Tool is one entry of an MCP tools/list result.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"inputSchema,omitempty"`
	// Annotations and other fields are preserved verbatim via the raw map in
	// ToolsListResult so a backend's richer tool descriptors survive the hop.
}

// ToolsListResult is the result of an MCP tools/list request.
type ToolsListResult struct {
	Tools      []json.RawMessage `json:"tools"`
	NextCursor string            `json:"nextCursor,omitempty"`
}

// InitializeResult is the result the proxy returns to Claude Desktop for the
// initialize request. protocolVersion echoes the client's requested version
// when supported; capabilities advertises only the tools capability (the
// proxy aggregates tools — it does not surface backend prompts/resources in
// this PoC, see README "Scope & boundaries").
type InitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      ServerInfo             `json:"serverInfo"`
	Instructions    string                 `json:"instructions,omitempty"`
}

// ServerInfo identifies an MCP server to its peer.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// InitializeParams is the subset of the initialize params the proxy reads.
type InitializeParams struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities,omitempty"`
	ClientInfo      ServerInfo      `json:"clientInfo,omitempty"`
}
