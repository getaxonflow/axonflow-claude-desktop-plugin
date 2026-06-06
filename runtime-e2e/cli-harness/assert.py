#!/usr/bin/env python3
# Copyright 2026 AxonFlow
# SPDX-License-Identifier: MIT
#
# Assertions for the CLI-harness runtime-e2e. Reads, for each governed case:
#   - Claude Code's stdout (what the real MCP CLIENT actually received)
#   - the proxy's Layer-1 audit JSONL (the proxy's own per-call record)
#   - the platform's audit_logs DB rows (queried live via docker compose exec)
# and cross-checks them. Every PASS is backed by a real PDP decision; there is no
# fixture/mocking anywhere (the live agent issues the verdicts, the real proxy
# enforces them, the official-SDK backend serves the data, Claude Code calls it).
import json
import subprocess
import sys

WORK = sys.argv[1]
PROJECT = sys.argv[2]
COMPOSE_FILE = sys.argv[3]
LEADER = sys.argv[4]

fails = 0
passes = 0


def check(cond, msg):
    global fails, passes
    print(("  PASS " if cond else "  FAIL ") + msg)
    if cond:
        passes += 1
    else:
        fails += 1


def read_text(name):
    try:
        with open(f"{WORK}/{name}") as f:
            return f.read()
    except FileNotFoundError:
        return ""


def read_audit(name):
    rows = []
    try:
        with open(f"{WORK}/{name}") as f:
            for line in f:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    except FileNotFoundError:
        pass
    return rows


def psql(query):
    """Run a query against the live postgres in the harness stack."""
    out = subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "-p", PROJECT, "exec", "-T",
         "postgres", "psql", "-U", "axonflow", "-d", "axonflow", "-At", "-c", query],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print("  (psql error: " + out.stderr.strip() + ")")
    return out.stdout.strip()


def db_row(decision_id):
    """Fetch the platform audit_logs row the agent wrote for this decision."""
    q = (
        "SELECT policy_decision || '|' || "
        "COALESCE(policy_details->>'gateway_id','') || '|' || "
        "COALESCE(policy_details->'context'->>'x_leader_identity','') || '|' || "
        "COALESCE(array_to_string(ARRAY(SELECT jsonb_array_elements_text(policy_details->'policy_ids')),','),'') "
        f"FROM audit_logs WHERE id = 'decide_{decision_id}'"
    )
    raw = psql(q)
    if not raw:
        return None
    verdict, gw, leader, pols = (raw.split("|", 3) + ["", "", "", ""])[:4]
    return {"verdict": verdict, "gateway_id": gw, "leader": leader, "policies": pols}


# --- universal PII-leak detector (runs on EVERY case's response-to-Claude) --
# A single check applied to all four cases, not just the redact one. A leak in a
# case that wasn't looking (a deny that secretly forwarded, an allow whose
# response carried PII) is exactly how the §4.3 hole hid; this catches it. Tuned
# to not match the backend's benign numerics (ledger amounts < 13 digits, no
# '@'/'+62'), so a hit is a real leak.
import re as _re
_LEAK_PATTERNS = [
    ("nik_or_long_id", _re.compile(r"\b\d{16}\b")),
    ("email", _re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("phone_id", _re.compile(r"\b(?:\+?62|0)8[1-9]\d{6,10}\b")),
]
_KNOWN_PII = ["3174012509900001", "budi.santoso@example.co.id", "+6281234567890"]


def assert_no_leak(label, text):
    hits = [k for k, rx in _LEAK_PATTERNS if rx.search(text)]
    hits += [f"lit:{l}" for l in _KNOWN_PII if l in text]
    check(not hits, f"[{label}] universal leak detector: NO raw PII in Claude's context"
          + ("" if not hits else f" — LEAKED {hits}"))


print("================ CLI-harness assertions ================")

# ---- ALLOW ----------------------------------------------------------------
print("\n[ALLOW] benign export_ledger call is forwarded")
a = read_audit("allow.audit.jsonl")
assert_no_leak("allow", read_text("allow.out"))
arow = next((r for r in a if r["tool_name"] == "export_ledger"), None)
check(arow is not None, "proxy Layer-1 row written for export_ledger")
if arow:
    check(arow["verdict"] == "allow", f"verdict=allow (got {arow['verdict']})")
    check(arow["response_record_count"] == 3, f"response_record_count=3 (got {arow['response_record_count']})")
    check(arow["leader_email"] == LEADER, f"leader_email={LEADER}")
    check(arow["gateway_id"].startswith("claude_desktop."), f"gateway_id={arow['gateway_id']}")
    db = db_row(arow["decision_id"])
    check(db is not None, "platform audit_logs row exists for this decision_id")
    if db:
        check(db["verdict"] == "allow", f"DB policy_decision=allow (got {db['verdict']})")
        check(db["gateway_id"] == arow["gateway_id"], f"DB gateway_id matches proxy ({db['gateway_id']})")
        check(db["leader"] == LEADER, f"DB x_leader_identity={LEADER} (got {db['leader']})")

# ---- DENY -----------------------------------------------------------------
print("\n[DENY] SQL-injection call is blocked, backend never reached")
d = read_audit("deny.audit.jsonl")
drow = next((r for r in d if r["tool_name"] == "run_sql_report"), None)
dout = read_text("deny.out")
assert_no_leak("deny", dout)
check(drow is not None, "proxy Layer-1 row written for run_sql_report")
if drow:
    check(drow["verdict"] == "deny", f"verdict=deny (got {drow['verdict']})")
    # The SQLi string is a STACKED drop (";" + DROP TABLE), so the live PDP
    # matches sys_sqli_stacked_drop. Accept either the stacked or the bare
    # drop-table policy so the assertion tracks the real verdict, not a stale id.
    check(any(p in drow["evaluated_policies"] for p in ("sys_sqli_stacked_drop", "sys_sqli_drop_table")),
          f"SQLi drop policy fired (got {drow['evaluated_policies']})")
    check(drow["response_record_count"] == 0, "no records forwarded on deny (response_record_count=0)")
check("-32001" in dout, "Claude received JSON-RPC -32001 (deny) for the call")
# Real proof the backend was NOT reached: run_sql_report echoes "would_run" +
# the engine tag "bukuwarung-reporting" iff it executes. Neither may appear in
# what Claude got back, since the PDP blocked the call before forwarding.
check("bukuwarung-reporting" not in dout and "would_run" not in dout,
      "backend never executed (its run_sql_report echo is absent from Claude's response)")
if drow:
    db = db_row(drow["decision_id"])
    check(db is not None and db["verdict"] == "deny", "platform audit_logs records verdict=deny")
    if db:
        check(any(p in db["policies"] for p in ("sys_sqli_stacked_drop", "sys_sqli_drop_table")),
              f"DB policy_ids include the SQLi drop policy ({db['policies']})")

# ---- REDACT — the §4.3 CLEAN-REQUEST regression (#2530) --------------------
# The request is a bare customer_id lookup with NO PII, so the PDP returns allow
# with NO redact_pii obligation (evaluated_policies empty). The old proxy gated
# redaction on that obligation and therefore LEAKED this response. The fixed
# proxy redacts unconditionally, so the NIK / email / NIK-keyed map are masked
# even though no policy fired on the request.
print("\n[REDACT] clean-request response PII stripped incl. a NIK-keyed map (the #2530 fix)")
r = read_audit("redact.audit.jsonl")
rrow = next((r_ for r_ in r if r_["tool_name"] == "lookup_customer"), None)
rout = read_text("redact.out")
check(rrow is not None, "proxy Layer-1 row written for lookup_customer")
if rrow:
    check(rrow["verdict"] == "allow", f"verdict=allow (got {rrow['verdict']})")
    # The clean request fires NO redact_pii obligation — that is the whole point.
    check("sys_pii_aadhaar" not in rrow["evaluated_policies"],
          f"clean request fires NO obligation (evaluated_policies={rrow['evaluated_policies']})")
    check(rrow["redaction_count"] > 0,
          f"response redacted anyway — unconditionally (redaction_count={rrow['redaction_count']})")
# What the CLIENT (Claude) actually received — the universal detector + specifics:
assert_no_leak("redact", rout)
check("[REDACTED:nik]" in rout, "NIK redaction token present in what Claude received")
# §4.3: the NIK-keyed object KEY must be masked, not just the value. The backend
# returns related_accounts keyed by the NIK; a value-only redactor would leak it.
check('"[REDACTED:nik]":' in rout or "'[REDACTED:nik]':" in rout,
      "NIK-keyed map KEY is redacted (§4.3 key redaction), not just values")
if rrow:
    db = db_row(rrow["decision_id"])
    check(db is not None and db["verdict"] == "allow",
          "platform audit_logs records the allow (no-obligation) decision")

# ---- FAIL-CLOSED ----------------------------------------------------------
print("\n[FAIL-CLOSED] PDP unreachable → call blocked")
f = read_audit("failclosed.audit.jsonl")
frow = next((r_ for r_ in f if r_["tool_name"] == "export_ledger"), None)
fout = read_text("failclosed.out")
assert_no_leak("fail-closed", fout)
check(frow is not None, "proxy Layer-1 row written for the fail-closed call")
if frow:
    check(frow["verdict"] == "deny", f"verdict=deny on PDP-unreachable (got {frow['verdict']})")
check("-32003" in fout, "Claude received JSON-RPC -32003 (fail-closed)")

# ---- attribution sanity across every row ----------------------------------
print("\n[AUDIT] every proxy row carries session_id + leader + gateway_id")
allrows = a + d + r + f
for row in allrows:
    if not (row.get("session_id") and row.get("leader_email") == LEADER and row.get("gateway_id", "").startswith("claude_desktop.")):
        check(False, f"row missing attribution: {row}")
        break
else:
    check(len(allrows) >= 4, f"all {len(allrows)} rows carry session_id/leader/gateway_id")

print("\n================ RESULT: %d passed, %d failed ================" % (passes, fails))
sys.exit(1 if fails else 0)
