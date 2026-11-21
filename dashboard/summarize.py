"""Join one replay schedule to the corresponding proxy and WAF transactions."""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile

BENIGN = {f"ben-{n:02}" for n in range(1, 21)}
BURST = {f"atk-brute-{n:02}" for n in range(25)}
WAF = {"atk-sqli-01": ("sqli", "942"), "atk-xss-01": ("xss", "941"),
       "atk-trav-01": ("traversal", "930"), "atk-cmdi-01": ("cmdi", "932"),
       "atk-scan-01": ("scanner", "913")}
PRE, POST = "atk-brute-pre", "atk-brute-post"
EDGE = "atk-trav-02"


def records(path):
    with Path(path).open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if line.strip():
                try:
                    yield json.loads(line)
                except ValueError as exc:
                    raise ValueError(f"{path} line {number} contains invalid JSON") from exc


def matched_variable(details):
    text = details.get("match", "") + " " + details.get("data", "")
    match = re.search(r"(?:variable|found within)\s+[`']?([\w.:-]+)", text, re.I)
    return match.group(1) if match else ""


def summarize(results, access, audits):
    if not results or len({r.get("run_id") for r in results}) != 1 or not results[0].get("run_id"):
        raise ValueError("Expected results from exactly one named run")
    wanted = {r.get("request_id") for r in results} - {None, ""}
    proxy = {}
    for event in access:
        rid = event.get("request_id")
        if rid in wanted:
            if rid in proxy:
                raise ValueError("Duplicate access-log ID")
            proxy[rid] = event
    transactions = {}
    for event in audits:
        tx = event["transaction"]
        rid = tx["unique_id"]
        if rid in wanted:
            if rid in transactions:
                raise ValueError("Duplicate WAF transaction ID")
            transactions[rid] = tx

    ids = set()
    joined = set()
    rows = []
    rules = Counter()
    by_type = Counter()
    accepted = set()
    denied = set()
    admitted = set()
    limited = set()
    categories = {}
    for r in results:
        cid, rid, status = r["case_id"], r.get("request_id"), r.get("status")
        if cid in ids or (rid and rid in joined):
            raise ValueError("Duplicate replay case or response ID")
        ids.add(cid)
        if rid:
            joined.add(rid)
        a = proxy.get(rid, {})
        tx = transactions.get(rid, {})
        rule_ids = sorted({str(m["details"]["ruleId"]) for m in tx.get("messages", [])})
        rules.update(rule_ids)
        up = a.get("upstream_status")
        limiter = a.get("limit_req_status")
        correlated = bool(a) and status == a.get("status") and r["method"] == a.get("method")
        reached = correlated and up == str(status)
        stopped = correlated and up == ""
        ok = False
        outcome = "unverified"
        if cid in BENIGN or cid in (PRE, POST):
            ok = reached and status == 200 and r.get("passed") is True
            if ok:
                accepted.add(cid)
                outcome = "allowed"
        elif cid in WAF:
            category, prefix = WAF[cid]
            ok = (stopped and status == 403 and tx.get("is_interrupted") is True
                  and "949110" in rule_ids and any(i.startswith(prefix) for i in rule_ids))
            categories[category] = {"blocked": ok, "status": status, "rule_ids": rule_ids}
            if ok:
                denied.add(cid)
                by_type[category] += 1
                outcome = "WAF block"
        elif cid == EDGE:
            ok = stopped and status in (400, 403)
            if ok:
                accepted.add(cid)
                outcome = "edge rejection"
        elif cid in BURST:
            if stopped and status == 429 and limiter == "REJECTED":
                limited.add(cid)
                ok, outcome = True, "rate limited"
            elif reached and status == 401 and limiter == "PASSED":
                admitted.add(cid)
                ok, outcome = True, "admitted"
        rows.append({"case_id": cid, "request_id": rid, "suite": r["klass"],
                     "method": r["method"], "uri": (a.get("uri") or r.get("uri","")).split("?")[0],
                     "status": status, "upstream_status": up, "limiter": limiter,
                     "passed": ok, "outcome": outcome, "rule_ids": rule_ids})

    passed = len(BENIGN & accepted)
    benign_ok = BENIGN <= ids and passed >= 19 and "ben-20" in accepted
    waf_ok = denied == WAF.keys()
    brute_ok = admitted | limited == BURST and bool(limited) and {PRE, POST} <= accepted
    complete = ids == BENIGN | BURST | WAF.keys() | {PRE, POST, EDGE}
    return {"run_id": results[0]["run_id"], "generated_at": datetime.now(timezone.utc).isoformat(),
            "totals": {"requests":len(rows), "blocked":len(denied), "rate_limited":len(limited),
                       "allowed":sum(r["outcome"] == "allowed" for r in rows)},
            "benign":{"passed":passed, "total":20, "pass_rate":passed/20, "ok":benign_ok, "target":0.95},
            "attacks":{"exploit":categories, "exploit_ok":waf_ok, "bruteforce_ok":brute_ok,
                       "bruteforce":{"admitted":len(admitted),"rejected":len(limited),"recovered":POST in accepted}},
            "full_suite_ok":complete and benign_ok and waf_ok and brute_ok and EDGE in accepted,
            "by_type":dict(by_type), "top_rules":[{"id":k,"count":v} for k,v in rules.most_common(10)],
            "rows":rows}


def selftest():
    rows = [{"run_id":"selftest","case_id":cid,"request_id":cid,"status":200,
             "klass":"benign","method":"GET","passed":True} for cid in sorted(BENIGN)]
    access = [{"request_id":r["request_id"],"method":"GET","status":200,"upstream_status":"200"} for r in rows]
    assert summarize(rows, access, [])["benign"]["ok"]
    assert not summarize(rows, [], [])["benign"]["ok"]
    rows[-1]["passed"] = False
    assert not summarize(rows, access, [])["benign"]["ok"]
    for r in rows[-2:]:
        r.update(status=None, request_id=None, passed=False)
    b = summarize(rows, access, [])["benign"]
    assert b["passed"] == 18 and b["pass_rate"] == 0.9 and not b["ok"]
    assert not summarize(rows[:1], access, [])["full_suite_ok"]
    print("PASS incomplete schedules, missing logs, failed login and two timeouts fail scoring")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--list-rules")
    for name in ("results","access","audit"):
        ap.add_argument("--"+name)
    ap.add_argument("--out", default="dashboard/alerts.json")
    ap.add_argument("--require", choices=("full","benign"))
    args = ap.parse_args()
    if args.selftest:
        return selftest()
    if args.list_rules:
        counts = Counter((str(m["details"]["ruleId"]),matched_variable(m["details"]))
                         for e in records(args.list_rules) for m in e["transaction"].get("messages",[]))
        for (rule,var), count in counts.most_common():
            print(rule, count, var or "(unspecified)", sep="\t")
        return
    if not (args.results and args.access and args.audit):
        ap.error("Provide results, access and audit paths")
    doc = summarize(list(records(args.results)), records(args.access), records(args.audit))
    target = Path(args.out)
    target.parent.mkdir(parents=True,exist_ok=True)
    with tempfile.NamedTemporaryFile(mode="w",encoding="utf8",dir=target.parent,delete=False) as f:
        json.dump(doc,f,indent=2)
    os.replace(f.name,target)
    print(f"{doc['run_id']} | benign {doc['benign']['passed']}/20 | full suite verified {doc['full_suite_ok']}")
    if args.require and not (doc["full_suite_ok"] if args.require == "full" else doc["benign"]["ok"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
