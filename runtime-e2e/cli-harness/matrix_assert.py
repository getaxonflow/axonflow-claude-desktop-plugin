#!/usr/bin/env python3
# Copyright 2026 AxonFlow
# SPDX-License-Identifier: MIT
#
# Assertions for the DETERMINISTIC governance matrix (matrix.sh). Where run.sh /
# assert.py drive a single happy path through Claude Code (a real LLM MCP
# client), this matrix drives the SAME real proxy + real official-SDK backend +
# live in-vpc-enterprise PDP through a DETERMINISTIC MCP client (exact JSON-RPC),
# so every governance behaviour is exercised with its trigger ABSENT as well as
# present — the discipline that was missing when the §4.3 response-only leak
# survived 30/0 (#2530).
#
# Two cross-checks back every case:
#   1. the proxy's response to its MCP client (== the bytes Claude would receive)
#   2. the proxy's Layer-1 audit JSONL  (verdict / redaction_count / decision_id)
# and, for representative cases, the platform audit_logs DB row by decision_id.
#
# THE load-bearing assertion is the UNIVERSAL PII-LEAK DETECTOR (leak_scan):
# it runs on EVERY case's final response — not just the redact cases — and fails
# if any raw PII pattern appears unless the case explicitly opted in (none do).
# A leak in an unexpected case (a deny that secretly forwarded, an allow whose
# response carried PII) can no longer slip through a case that wasn't looking.
import json
import re
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


# --- the universal PII-leak detector ---------------------------------------
# Patterns for raw PII that must NEVER appear in a response-to-Claude. These are
# tuned to NOT match the backend's benign numerics (ledger amounts, order counts,
# aggregate totals are <13 digits and carry no '@'/'+62'), so a hit is a real
# leak, not a false positive.
LEAK_PATTERNS = [
    ("nik_or_long_id", re.compile(r"\b\d{16}\b")),                       # 16-digit NIK / NPWP-new
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("phone_id", re.compile(r"\b(?:\+?62|0)8[1-9]\d{6,10}\b")),         # +62 / 08 Indonesian mobile
    ("npwp_legacy", re.compile(r"\b\d{2}\.\d{3}\.\d{3}\.\d{1}-\d{3}\.\d{3}\b")),
    ("card", re.compile(r"\b(?:\d[ -]*?){13,19}\b")),
]
# The exact literals the backend emits — a belt-and-braces check independent of
# the regexes above (catches e.g. a bank account that the regex set might miss).
KNOWN_PII_LITERALS = [
    "3174012509900001", "3201019008880002",
    "budi.santoso@example.co.id", "siti.rahayu@example.co.id", "andi.wijaya@example.co.id",
    "+6281234567890", "081298765432", "+6285711112222",
    "0925429430700012",            # NPWP
    "1234567890",                  # BCA account number
]


def leak_scan(label, text):
    """Run the universal detector on one response. Returns list of (kind, sample)."""
    hits = []
    for kind, rx in LEAK_PATTERNS:
        m = rx.search(text)
        if m:
            hits.append((kind, m.group(0)))
    for lit in KNOWN_PII_LITERALS:
        if lit in text:
            hits.append(("literal", lit))
    return hits


def assert_no_leak(label, text):
    hits = leak_scan(label, text)
    check(not hits, f"[{label}] universal leak detector: response carries NO raw PII"
          + ("" if not hits else f" — LEAKED {hits}"))


# --- IO helpers ------------------------------------------------------------
def load_responses(name):
    """proxy stdout (JSON-RPC responses) → {id: obj}."""
    resp = {}
    try:
        with open(f"{WORK}/{name}") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    o = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(o, dict) and o.get("id") is not None:
                    resp[o["id"]] = o
    except FileNotFoundError:
        pass
    return resp


def load_audit(name):
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
    out = subprocess.run(
        ["docker", "compose", "-f", COMPOSE_FILE, "-p", PROJECT, "exec", "-T",
         "postgres", "psql", "-U", "axonflow", "-d", "axonflow", "-At", "-c", query],
        capture_output=True, text=True,
    )
    if out.returncode != 0:
        print("  (psql error: " + out.stderr.strip() + ")")
    return out.stdout.strip()


def db_verdict(decision_id):
    raw = psql("SELECT policy_decision FROM audit_logs WHERE id = 'decide_%s'" % decision_id)
    return raw or None


# --- load everything -------------------------------------------------------
main_resp = load_responses("matrix.out.jsonl")
main_audit = load_audit("matrix.audit.jsonl")
fc_resp = load_responses("matrix_failclosed.out.jsonl")
fc_audit = load_audit("matrix_failclosed.audit.jsonl")
tenant_resp = load_responses("matrix_tenant.out.jsonl")
tenant_audit = load_audit("matrix_tenant.audit.jsonl")
negctl_resp = load_responses("matrix_negcontrol.out.jsonl")

# id → case label (must match matrix.sh)
CASES = {
    # ---- ALLOW (neither: no request PII, no response PII) ----
    101: ("allow_ledger", "allow", "neither"),
    102: ("allow_aggregates", "allow", "neither"),
    # ---- REDACT (response-only PII — the #2530 fix) ----
    103: ("redact_clean_lookup", "allow", "response-only"),     # customer_id only
    104: ("redact_bank_details", "allow", "response-only"),     # account_id only
    105: ("redact_list_contacts", "allow", "response-only"),    # array/nested
    # ---- REDACT (both: request PII + response PII) ----
    106: ("redact_both_aadhaar", "allow", "both"),
    # ---- request-only PII (clean response) ----
    107: ("requestonly_pii", "allow", "request-only"),
    # ---- DENY (vanilla system policies) ----
    108: ("deny_drop", "deny", None),
    109: ("deny_union", "deny", None),
    110: ("deny_or_true", "deny", None),
    111: ("deny_injection_override", "deny", None),
    112: ("deny_injection_reveal", "deny", None),
    113: ("deny_dangerous_command", "deny", None),
    # ---- DENY (BukuWarung bundle: read-only write/DDL) ----
    114: ("deny_readonly_delete", "deny", None),
    115: ("deny_readonly_update", "deny", None),
    116: ("deny_readonly_insert", "deny", None),
}

# Tools whose execution-proof string must be ABSENT when a call is denied
# (proves the backend was never reached).
BACKEND_EXEC_MARKERS = ["bukuwarung-reporting", "bukuwarung-shell", "would_run", "executed"]

print("================ DETERMINISTIC governance matrix ================")
print(f"  {len(CASES)} core cases + fail-closed + tenant-isolation\n")

# Every case must have produced a proxy response.
for cid, (label, _, _) in CASES.items():
    check(cid in main_resp, f"[{label}] proxy returned a response (id={cid})")

# ---- per-case assertions --------------------------------------------------
for cid, (label, want_verdict, cell) in CASES.items():
    o = main_resp.get(cid, {})
    body = json.dumps(o)  # whole response object — covers result AND error data
    # UNIVERSAL leak detector on EVERY case, redact or not.
    assert_no_leak(label, body)

    if want_verdict == "allow":
        check("error" not in o, f"[{label}] verdict=allow (no JSON-RPC error)")
        if cell in ("response-only", "both"):
            # redaction tokens must be present (PII was masked, not dropped).
            check("[REDACTED:" in body, f"[{label}] redaction token present (PII masked)")
        if cell in ("neither", "request-only"):
            # no over-redaction of benign data.
            check("[REDACTED:" not in body, f"[{label}] benign response not over-redacted")
    elif want_verdict == "deny":
        code = o.get("error", {}).get("code")
        check(code == -32001, f"[{label}] blocked with -32001 (got {code})")
        # backend must NOT have executed.
        reached = [m for m in BACKEND_EXEC_MARKERS if m in body]
        check(not reached, f"[{label}] backend never executed (no exec marker)"
              + ("" if not reached else f" — LEAKED markers {reached}"))

# ---- audit cross-check ----------------------------------------------------
print("\n[AUDIT] proxy Layer-1 rows + DB correlation")
audit_by_id = {}
for r in main_audit:
    # match a row to its case by tool+verdict heuristic later; here index by decision_id
    audit_by_id[r.get("decision_id", "")] = r
check(len(main_audit) == len(CASES),
      f"one Layer-1 row per case (got {len(main_audit)}, want {len(CASES)})")

# every row carries attribution.
attrib_ok = all(
    r.get("session_id") and r.get("leader_email") == LEADER
    and r.get("gateway_id", "").startswith("claude_desktop.")
    for r in main_audit
)
check(attrib_ok, "every proxy row carries session_id + leader + gateway_id")

# redact cases recorded redaction_count>0; allow/deny non-PII recorded 0.
redact_rows = [r for r in main_audit if r.get("redaction_count", 0) > 0]
check(len(redact_rows) >= 4,
      f"redaction recorded on the PII-response cases (>=4 rows, got {len(redact_rows)})")

# DB correlation: enough decide rows exist, AND three representative proxy rows
# (allow / deny / redact) each resolve to a matching platform audit_logs verdict
# by decision_id — a real per-case end-to-end check, not just an aggregate count.
print("\n[DB] platform audit_logs correlation (live psql)")
db_count = psql("SELECT count(*) FROM audit_logs WHERE id LIKE 'decide_%%'")
check(db_count.isdigit() and int(db_count) >= len(CASES),
      f"platform audit_logs holds >= {len(CASES)} decide rows (got {db_count})")


def first_audit(pred):
    return next((r for r in main_audit if r.get("decision_id") and pred(r)), None)


representatives = [
    ("allow", first_audit(lambda r: r["tool_name"] == "export_ledger" and r["verdict"] == "allow"), "allow"),
    ("deny", first_audit(lambda r: r["tool_name"] == "run_sql_report" and r["verdict"] == "deny"), "deny"),
    ("redact", first_audit(lambda r: r["tool_name"] == "lookup_customer" and r.get("redaction_count", 0) > 0), "allow"),
]
for name, row, want in representatives:
    check(row is not None, f"[{name}] a proxy audit row with a decision_id exists")
    if row:
        v = db_verdict(row["decision_id"])
        check(v == want,
              f"[{name}] DB audit_logs row for decision_id={row['decision_id'][:8]}… reads policy_decision={want} (got {v})")

# ---- FAIL-CLOSED ----------------------------------------------------------
print("\n[FAIL-CLOSED] PDP unreachable → blocked, leak detector still runs")
fc = fc_resp.get(201, {})
assert_no_leak("fail_closed", json.dumps(fc))
check(fc.get("error", {}).get("code") == -32003,
      f"fail-closed blocked with -32003 (got {fc.get('error', {}).get('code')})")
check(any(r.get("verdict") == "deny" for r in fc_audit), "fail-closed audit row verdict=deny")

# ---- TENANT ISOLATION -----------------------------------------------------
print("\n[TENANT-ISOLATION] foreign tenant → PDP 403 → call blocked, backend untouched")
ti = tenant_resp.get(301, {})
assert_no_leak("tenant_isolation", json.dumps(ti))
check("error" in ti, "foreign-tenant call blocked (JSON-RPC error)")
reached = [m for m in BACKEND_EXEC_MARKERS if m in json.dumps(ti)]
check(not reached, "foreign-tenant call never reached the backend")
check(any(r.get("verdict") in ("deny", "error") for r in tenant_audit),
      "tenant-isolation audit row verdict=deny/error")

# ---- NEGATIVE CONTROL -----------------------------------------------------
# Proves the universal detector is NOT vacuous AND reproduces the #2530 bug:
# the SAME clean-request lookup as case 103, but driven with the legacy
# on-obligation mode. With no obligation on a clean request the response is
# forwarded RAW, so the detector MUST find PII. If this does NOT leak, either the
# detector is blind or the negative control is misconfigured — both are failures.
print("\n[NEGATIVE-CONTROL] legacy on-obligation mode leaks the clean-request case")
nc = negctl_resp.get(401, {})
nc_body = json.dumps(nc)
nc_hits = leak_scan("negcontrol", nc_body)
check(bool(nc_hits),
      "detector FIRES on the un-fixed (on-obligation) clean-request response — "
      "proves it is not vacuous AND that the old behaviour leaked"
      + (f" (found {nc_hits})" if nc_hits else " — DID NOT LEAK (detector blind or control broken!)"))
# And it must be the real NIK that leaked (the exact §4.3 value).
check("3174012509900001" in nc_body, "the leaked value is the real NIK (the §4.3 datum)")

print("\n================ RESULT: %d passed, %d failed ================" % (passes, fails))
sys.exit(1 if fails else 0)
