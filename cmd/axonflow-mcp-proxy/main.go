// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

// Command axonflow-mcp-proxy is the AxonFlow governance MCP proxy for Claude
// Desktop. Claude Desktop launches it as a stdio MCP server (via a .mcpb
// Desktop Extension); it fronts one or more backend MCP servers, checks every
// tools/call against AxonFlow Decision Mode (POST /api/v1/decide) before
// forwarding, redacts PII from responses on a redact_pii obligation, and writes
// a Layer-1 audit row per call.
//
// Architecture note: Claude Desktop has NO PreToolUse/PostToolUse hooks (those
// are Claude Code only). The MCP layer is the only pre-execution interception
// point on Desktop, so enforcement lives in THIS proxy, not in a hook. See the
// README "Why a proxy, not a hook".
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"
)

// proxyVersion is the proxy build version, surfaced in serverInfo + the .mcpb
// manifest. Keep in lockstep with manifest.json + CHANGELOG.md.
const proxyVersion = "0.1.0"

// proxyProtocolVersion is the MCP protocol version the proxy advertises to
// Claude Desktop. It echoes the client's requested version when the client
// asks for one (forward/backward compatible negotiation).
const proxyProtocolVersion = "2025-06-18"

// logStderr writes a single structured log line to stderr. stdout is the
// JSON-RPC channel and MUST NOT carry anything else, so ALL diagnostics go to
// stderr (Claude Desktop surfaces extension stderr in its logs).
func logStderr(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.LUTC)
	log.SetPrefix("axonflow-mcp-proxy ")

	cfg, err := LoadConfig()
	if err != nil {
		logStderr("FATAL config error: %v", err)
		os.Exit(2)
	}

	logStderr("starting v%s", proxyVersion)
	logStderr("  endpoint:  %s", cfg.Endpoint)
	logStderr("  gateway:   %s", cfg.GatewayID)
	logStderr("  tenant:    %s", cfg.TenantID)
	logStderr("  fail-mode: %s", failModeLabel(cfg.FailOpen))
	logStderr("  backends:  %d", len(cfg.Backends))
	for _, b := range cfg.Backends {
		logStderr("    - %s (%s)", b.ID, b.transport())
	}

	proxy, err := NewProxy(cfg)
	if err != nil {
		logStderr("FATAL proxy init: %v", err)
		os.Exit(2)
	}
	defer proxy.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Aggregate backends up front so a backend that's down is reported at boot,
	// not on the first tool call. A hard failure (no backend reachable) is
	// logged but does NOT exit — Claude Desktop keeps the extension loaded and
	// the operator can fix the backend without re-installing.
	if err := proxy.Aggregate(ctx); err != nil {
		logStderr("WARNING %v — will retry on first tools/list", err)
	}

	if err := proxy.Serve(ctx, os.Stdin, os.Stdout); err != nil && !errors.Is(err, io.EOF) {
		logStderr("serve ended: %v", err)
	}
	logStderr("shutdown")
}

// Serve runs the stdio MCP message loop: read newline-delimited JSON-RPC from
// in, dispatch, write newline-delimited JSON-RPC responses to out. It returns
// when in reaches EOF or ctx is cancelled. Factored out (in/out injectable) so
// the loop is unit-testable with in-memory pipes.
func (p *Proxy) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 64*1024), maxDecideRequestBytes)
	enc := newLineWriter(out)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var req JSONRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.write(errorResponse(nil, codeParseError, "invalid JSON-RPC"))
			continue
		}
		resp, respond := p.dispatch(ctx, &req)
		if respond {
			if err := enc.write(resp); err != nil {
				return fmt.Errorf("write response: %w", err)
			}
		}
	}
	return scanner.Err()
}

// dispatch routes one inbound message. The bool return is false for
// notifications (no response is written).
func (p *Proxy) dispatch(ctx context.Context, req *JSONRPCRequest) (JSONRPCResponse, bool) {
	switch req.Method {
	case "initialize":
		return p.handleInitialize(req), true
	case "notifications/initialized", "notifications/cancelled":
		return JSONRPCResponse{}, false // notifications: acknowledged, no reply
	case "ping":
		return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: json.RawMessage(`{}`)}, true
	case "tools/list":
		return p.handleToolsList(ctx, req), true
	case "tools/call":
		return p.handleToolsCallMessage(ctx, req), true
	default:
		if req.isNotification() {
			return JSONRPCResponse{}, false
		}
		return errorResponse(req.ID, codeMethodNotFound, fmt.Sprintf("method not found: %s", req.Method)), true
	}
}

// handleInitialize answers Claude Desktop's initialize. protocolVersion echoes
// the client's requested version when present so negotiation succeeds across
// Desktop releases.
func (p *Proxy) handleInitialize(req *JSONRPCRequest) JSONRPCResponse {
	version := proxyProtocolVersion
	var params InitializeParams
	if len(req.Params) > 0 && json.Unmarshal(req.Params, &params) == nil && params.ProtocolVersion != "" {
		version = params.ProtocolVersion
	}
	result := InitializeResult{
		ProtocolVersion: version,
		Capabilities:    map[string]interface{}{"tools": map[string]interface{}{}},
		ServerInfo:      ServerInfo{Name: "axonflow-mcp-proxy", Version: proxyVersion},
		Instructions:    "Tool calls are governed by AxonFlow Decision Mode: policy-violating calls are blocked and responses are PII-redacted before reaching this conversation.",
	}
	return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: mustRaw(result)}
}

// handleToolsList returns the aggregated, namespaced tool list.
func (p *Proxy) handleToolsList(ctx context.Context, req *JSONRPCRequest) JSONRPCResponse {
	tools, err := p.ToolsList(ctx)
	if err != nil {
		return errorResponse(req.ID, codeInternalError, "tools unavailable: "+err.Error())
	}
	if tools == nil {
		tools = []json.RawMessage{}
	}
	result, _ := json.Marshal(ToolsListResult{Tools: tools})
	return JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: result}
}

// handleToolsCallMessage parses params and runs enforcement. A malformed
// tools/call (bad params / missing name) still writes a minimal Layer-1 audit
// row (verdict "error") so every tools/call invocation leaves an audit trace,
// not just the ones that reach the policy engine.
func (p *Proxy) handleToolsCallMessage(ctx context.Context, req *JSONRPCRequest) JSONRPCResponse {
	var params ToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		p.audit.Record(AuditRow{SessionID: p.cfg.SessionID, LeaderEmail: p.cfg.LeaderEmail,
			Verdict: "error", AIAgent: p.cfg.AIAgent, GatewayID: p.cfg.GatewayID})
		return errorResponse(req.ID, codeInvalidParams, "invalid tools/call params")
	}
	if params.Name == "" {
		p.audit.Record(AuditRow{SessionID: p.cfg.SessionID, LeaderEmail: p.cfg.LeaderEmail,
			Verdict: "error", AIAgent: p.cfg.AIAgent, GatewayID: p.cfg.GatewayID})
		return errorResponse(req.ID, codeInvalidParams, "tools/call missing tool name")
	}
	return p.HandleToolsCall(ctx, req.ID, params)
}

func failModeLabel(open bool) string {
	if open {
		return "open"
	}
	return "closed (fail-closed)"
}

// asRPCError is errors.As specialized to *rpcError, kept as a one-liner so
// callers read cleanly.
func asRPCError(err error, target **rpcError) bool {
	return errors.As(err, target)
}

// mustJSONString returns v JSON-encoded as a string literal.
func mustJSONString(v string) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `""`
	}
	return string(b)
}

// lineWriter writes compact, newline-delimited JSON-RPC messages. A mutex-free
// single-writer is fine because Serve is the only writer to stdout.
type lineWriter struct{ w io.Writer }

func newLineWriter(w io.Writer) *lineWriter { return &lineWriter{w: w} }

func (l *lineWriter) write(msg interface{}) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = l.w.Write(data)
	return err
}
