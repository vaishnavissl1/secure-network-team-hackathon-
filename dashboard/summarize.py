#!/usr/bin/env python3
"""
Alert summarizer (Person B). Standard library only. No jq.

Builds ONE defensible summary (dashboard/alerts.json) from three inputs,
JOINED FROM THE SCHEDULE so nothing is silently dropped:

  1. replay results  (tests/results/run-*.jsonl)  -> the denominator
  2. nginx access log (logs/nginx/access.log, JSON) -> status / limiter decision
  3. ModSec audit log (logs/modsec/audit.log, JSON) -> which CRS rules matched

Key correctness rule: start with one row per scheduled replay request. LEFT-join
the logs by request_id. A success may have no audit record; a timeout may have no
edge record at all -- those rows STAY in the denominator and count as failures.

Modes:
  python dashboard/summarize.py --selftest
  python dashboard/summarize.py --list-rules logs/modsec/audit.log
  python dashboard/summarize.py --results R --access A --audit U --out dashboard/alerts.json
"""
import argparse
import json
import os
import sys
import time

TARGET = 0.95
SECRET_KEYS = ("password", "token", "cookie", "authorization", "set-cookie")


# ---------------------------------------------------------------- loading
def load_jsonl(path):
    rows = []
    if not path or not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def index_access(access_rows):
    by_id = {}
    for a in access_rows:
        rid = a.get("request_id")
        if rid:
            by_id[rid] = a
    return by_id


def index_audit(audit_rows):
    """Map request_id -> list of {ruleId, msg, var}. Handles the CRS v3 JSON shape."""
    by_id = {}
    for a in audit_rows:
        tx = a.get("transaction", a)
        rid = (tx.get("unique_id") or tx.get("request_id")
               or a.get("request_id") or a.get("transaction_id"))
        msgs = (tx.get("messages") or a.get("messages") or [])
        hits = []
        for m in msgs:
            d = m.get("details", m)
            hits.append({
                "ruleId": str(d.get("ruleId") or d.get("id") or ""),
                "msg": d.get("msg") or m.get("message") or "",
                "var": (d.get("match") or d.get("data") or ""),
                "category": _category(str(d.get("ruleId") or "")),
            })
        if rid:
            by_id.setdefault(rid, []).extend(hits)
    return by_id


def _category(rule_id):
    """Map a CRS rule-id range to an attack type."""
    try:
        n = int(rule_id)
    except (TypeError, ValueError):
        return "other"
    table = [
        (913000, 913999, "scanner"),
        (920000, 920999, "protocol"),
        (930000, 930999, "traversal"),
        (931000, 931999, "rfi"),
        (932000, 932999, "cmdi"),
        (933000, 933999, "php"),
        (941000, 941999, "xss"),
        (942000, 942999, "sqli"),
        (949000, 949999, "anomaly"),
    ]
    for lo, hi, name in table:
        if lo <= n <= hi:
            return name
    return "other"


def sanitize(obj):
    if isinstance(obj, dict):
        return {k: ("***" if k.lower() in SECRET_KEYS else sanitize(v))
                for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(x) for x in obj]
    return obj


# ---------------------------------------------------------------- summary
def build_summary(result_rows, access_by_id, audit_by_id, run_id=None):
    rows = []
    benign_pass = benign_total = 0
    exploit = {}
    brute = {"admitted": 0, "rejected": 0, "other": 0, "recovered": False}
    by_type = {}
    rule_counts = {}

    for r in result_rows:
        rid = r.get("request_id")
        access = access_by_id.get(rid) if rid else None
        hits = audit_by_id.get(rid, []) if rid else []
        for h in hits:
            if h["ruleId"]:
                rc = rule_counts.setdefault(h["ruleId"], {"count": 0, "msg": h["msg"],
                                                          "category": h["category"]})
                rc["count"] += 1
                by_type[h["category"]] = by_type.get(h["category"], 0) + 1
        blocked = (r.get("status") == 403)
        klass = r.get("klass", "")
        row = {
            "case_id": r.get("case_id"), "suite": klass, "method": r.get("method"),
            "uri": r.get("uri"), "status": r.get("status"),
            "request_id": rid, "passed": r.get("passed"),
            "limiter": (access or {}).get("limit_req_status"),
            "upstream_status": (access or {}).get("upstream_status"),
            "rule_ids": sorted({h["ruleId"] for h in hits if h["ruleId"]}),
            "note": r.get("note", ""),
        }
        rows.append(row)

        cid = r.get("case_id", "")
        if klass == "benign":
            benign_total += 1
            if r.get("passed"):
                benign_pass += 1
        elif klass == "bruteforce":
            if cid in ("atk-brute-pre", "atk-brute-post"):
                if cid == "atk-brute-post" and r.get("passed"):
                    brute["recovered"] = True
                continue
            st = r.get("status")
            if st == 429:
                brute["rejected"] += 1
            elif st in (200, 401):
                brute["admitted"] += 1
            else:
                brute["other"] += 1
        else:  # single-request exploit classes
            exploit[klass] = {"blocked": blocked, "status": r.get("status"),
                              "rule_ids": row["rule_ids"]}

    total = len(rows)
    blocked_total = sum(1 for x in rows if x["status"] == 403)
    allowed_total = sum(1 for x in rows if x["status"] and 200 <= x["status"] < 400)
    pass_rate = (benign_pass / benign_total) if benign_total else 0.0
    top_rules = sorted(
        ({"id": k, **v} for k, v in rule_counts.items()),
        key=lambda x: x["count"], reverse=True)[:10]

    exploit_ok = all(v["blocked"] for v in exploit.values()) and len(exploit) >= 5
    brute_ok = brute["rejected"] > 0 and brute["recovered"]

    return {
        "run_id": run_id, "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "totals": {"requests": total, "allowed": allowed_total, "blocked": blocked_total},
        "benign": {"passed": benign_pass, "total": benign_total,
                   "pass_rate": round(pass_rate, 4), "target": TARGET,
                   "ok": pass_rate >= TARGET},
        "attacks": {"exploit": exploit, "exploit_ok": exploit_ok, "bruteforce": brute,
                    "bruteforce_ok": brute_ok},
        "by_type": by_type,
        "top_rules": top_rules,
        "rows": sanitize(rows),
    }


# ---------------------------------------------------------------- modes
def do_build(args):
    results = load_jsonl(args.results)
    run_id = results[0].get("run_id") if results else None
    summary = build_summary(results, index_access(load_jsonl(args.access)),
                            index_audit(load_jsonl(args.audit)), run_id)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    b = summary["benign"]
    print(f"wrote {args.out}")
    print(f"  benign {b['passed']}/{b['total']} = {b['pass_rate']*100:.0f}%  "
          f"({'PASS' if b['ok'] else 'FAIL'}; target {TARGET*100:.0f}%)")
    print(f"  exploit_ok={summary['attacks']['exploit_ok']}  "
          f"bruteforce_ok={summary['attacks']['bruteforce_ok']}")
    return 0


def do_list_rules(path):
    audit = index_audit(load_jsonl(path))
    counts = {}
    for hits in audit.values():
        for h in hits:
            if not h["ruleId"]:
                continue
            c = counts.setdefault(h["ruleId"], {"count": 0, "var": h["var"],
                                                "cat": h["category"], "msg": h["msg"]})
            c["count"] += 1
    print(f"{'ruleId':<10}{'count':<7}{'category':<12}{'matched-var':<24}msg")
    for rid, c in sorted(counts.items(), key=lambda x: x[1]["count"], reverse=True):
        print(f"{rid:<10}{c['count']:<7}{c['cat']:<12}{str(c['var'])[:22]:<24}{c['msg'][:50]}")
    if not counts:
        print("(no rule hits found — is the audit log path correct and non-empty?)")
    return 0


def do_selftest(out=None):
    """Prove the denominator rule: 18 benign OK + 2 timeouts MUST be 18/20 = 90% FAIL."""
    rows = []
    for i in range(1, 19):
        rows.append({"run_id": "selftest", "case_id": f"ben-{i:02d}", "klass": "benign",
                     "method": "GET", "uri": f"/ok/{i}", "status": 200,
                     "request_id": f"rid-{i}", "passed": True})
    for i in (19, 20):  # two timeouts: no edge record, must still count
        rows.append({"run_id": "selftest", "case_id": f"ben-{i:02d}", "klass": "benign",
                     "method": "GET", "uri": f"/timeout/{i}", "status": None,
                     "request_id": None, "passed": False, "note": "timeout"})
    # a couple of attack rows for a non-empty attack section
    for k in ("sqli", "xss", "traversal", "cmdi", "scanner"):
        rows.append({"run_id": "selftest", "case_id": f"atk-{k}", "klass": k,
                     "method": "GET", "uri": f"/{k}", "status": 403,
                     "request_id": f"a-{k}", "passed": True})

    summary = build_summary(rows, {}, {}, "selftest")
    b = summary["benign"]
    ok = (b["passed"] == 18 and b["total"] == 20
          and abs(b["pass_rate"] - 0.90) < 1e-9 and b["ok"] is False)
    print(f"selftest: benign {b['passed']}/{b['total']} = {b['pass_rate']*100:.0f}% "
          f"-> {'FAIL (correct)' if not b['ok'] else 'PASS (WRONG!)'}")
    if out:
        with open(out, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        print(f"  wrote sample summary -> {out}")
    if ok:
        print("SELFTEST PASSED: denominator keeps timeouts (18/20=90%, FAIL).")
        return 0
    print("SELFTEST FAILED: summarizer math is wrong.")
    return 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--list-rules", metavar="AUDIT_LOG")
    ap.add_argument("--results")
    ap.add_argument("--access")
    ap.add_argument("--audit")
    ap.add_argument("--out", default="dashboard/alerts.json")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(do_selftest(args.out if args.out != "dashboard/alerts.json" else
                             "dashboard/alerts.sample.json"))
    if args.list_rules:
        sys.exit(do_list_rules(args.list_rules))
    if args.results:
        sys.exit(do_build(args))
    ap.print_help()
    sys.exit(2)


if __name__ == "__main__":
    main()
