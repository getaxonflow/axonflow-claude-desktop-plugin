// Copyright 2026 AxonFlow
// SPDX-License-Identifier: MIT

// Command recorder is a header-recording reverse proxy for the cli-harness
// (#2860). It sits between the REAL proxy under test and the live AxonFlow
// agent, forwards every request unchanged, and appends one JSONL line per
// request recording the method, path, and X-Axonflow-Client header value.
//
// Why it exists: the runtime-e2e harnesses assert governance EFFECTS (audit
// rows, verdicts) against a live agent, but a telemetry-only header has no
// verdict-visible effect by design — the only honest runtime assertion is on
// the wire itself. The recorder is transparent to governance (it copies the
// request through byte-for-byte), so every verdict observed through it is the
// live agent's own.
//
// Usage: recorder <listen-addr> <target-url> <log-file>
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"sync"
)

type wireRecord struct {
	Method         string `json:"method"`
	Path           string `json:"path"`
	AxonflowClient string `json:"x_axonflow_client"`
}

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintln(os.Stderr, "usage: recorder <listen-addr> <target-url> <log-file>")
		os.Exit(2)
	}
	listenAddr, targetURL, logPath := os.Args[1], os.Args[2], os.Args[3]

	target, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("bad target url %q: %v", targetURL, err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Fatalf("open log file: %v", err)
	}

	var mu sync.Mutex
	rp := httputil.NewSingleHostReverseProxy(target)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := wireRecord{
			Method:         r.Method,
			Path:           r.URL.Path,
			AxonflowClient: r.Header.Get("X-Axonflow-Client"),
		}
		line, _ := json.Marshal(rec)
		mu.Lock()
		_, _ = logFile.Write(append(line, '\n'))
		_ = logFile.Sync()
		mu.Unlock()
		rp.ServeHTTP(w, r)
	})

	log.Printf("recorder: %s → %s (wire log %s)", listenAddr, targetURL, logPath)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
