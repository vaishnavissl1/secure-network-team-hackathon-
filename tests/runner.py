#!/usr/bin/env python3
"""
Replay runner (Person B). Standard library only.

Sends each scheduled case through the WAF, captures the status AND the
X-Request-ID response header, scores benign requests by EXPECTED OUTCOME, and
writes ONE result row per scheduled request (including timeouts) to
tests/results/run-<id>.jsonl. That file is the denominator the summarizer uses.

Usage:
    python tests/runner.py --suite attack
    python tests/runner.py --suite benign
    python tests/runner.py --suite all --base https://localhost:8443

Notes:
 - Self-signed TLS on localhost is expected; the runner does NOT verify the cert
   (TLS validity is checked separately in acceptance.sh with curl --cacert).
 - Every row keeps its case_id even on timeout (request_id=null, passed=false),
   so missing requests stay in the denominator.
"""
import argparse
import json
import os
import ssl
import sys
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cases as C  # noqa: E402

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")
_CTX = ssl._create_unverified_context()


def _send(base, case, timeout):
    """Send one request. Return (status, request_id, elapsed_ms, note)."""
    url = base + case["path"]
    headers = dict(case.get("headers") or {})
    data = None
    if case.get("json") is not None:
        data = json.dumps(case["json"]).encode()
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=case.get("method", "GET"))
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=_CTX) as r:
            body = r.read(4096).decode("utf-8", "replace")
            rid = r.headers.get("X-Request-ID")
            return r.status, rid, int((time.time() - t0) * 1000), "", body
    except urllib.error.HTTPError as e:
        # 403 / 429 / 4xx / 5xx arrive here — that is normal, not an error for us.
        body = ""
        try:
            body = e.read(4096).decode("utf-8", "replace")
        except Exception:
            pass
        rid = e.headers.get("X-Request-ID") if e.headers else None
        return e.code, rid, int((time.time() - t0) * 1000), "", body
    except Exception as e:  # timeout, connection refused, TLS, etc.
        return None, None, int((time.time() - t0) * 1000), type(e).__name__, ""


def _score(case, status, body):
    exp = case["expected"]
    if exp["type"] == "blocked":
        return status == 403
    if exp["type"] == "allowed":
        if status is None or not (200 <= status < 400):
            return False
        bc = exp.get("body_contains")
        return (bc.lower() in (body or "").lower()) if bc else True
    return False


def _row(run_id, case, status, rid, elapsed, note, passed):
    return {
        "run_id": run_id, "case_id": case["id"], "suite": case["klass"],
        "klass": case["klass"], "method": case.get("method", "GET"),
        "uri": case["path"], "expected": case["expected"],
        "status": status, "request_id": rid, "elapsed_ms": elapsed,
        "passed": passed, "note": note,
    }


def run_single(base, case, timeout, out):
    status, rid, elapsed, note, body = _send(base, case, timeout)
    passed = _score(case, status, body)
    row = _row(case["run_id_ctx"], case, status, rid, elapsed, note, passed)
    out.write(json.dumps(row) + "\n")
    mark = "PASS" if passed else "FAIL"
    print(f"  [{mark}] {case['id']:<12} status={status} rid={rid} ({elapsed}ms)")
    return passed


def run_brute(base, run_id, timeout, out):
    """Brute-force scenario: good login -> burst of bad -> good login."""
    print("  -- brute-force scenario --")
    login = {"method": "POST", "path": C.BRUTE["path"],
             "json": C.GOOD_LOGIN, "expected": {"type": "allowed"}, "klass": "bruteforce"}
    # recovery/pre login
    pre = dict(login, id="atk-brute-pre", run_id_ctx=run_id)
    pre_ok = run_single(base, pre, timeout, out)
    admitted = rejected = other = 0
    for i in range(C.BRUTE["attempts"]):
        bad = {"method": "POST", "path": C.BRUTE["path"], "json": C.BRUTE["bad"],
               "klass": "bruteforce", "id": f"atk-brute-{i:02d}",
               "expected": {"type": "allowed"}, "run_id_ctx": run_id}
        status, rid, elapsed, note, _ = _send(base, bad, timeout)
        if status == 429:
            rejected += 1
        elif status in (401, 200):
            admitted += 1
        else:
            other += 1
        out.write(json.dumps(_row(run_id, bad, status, rid, elapsed, note,
                                   passed=(status == 429))) + "\n")
    time.sleep(2)  # let the limiter window recover
    post = dict(login, id="atk-brute-post", run_id_ctx=run_id)
    post_ok = run_single(base, post, timeout, out)
    print(f"  brute: admitted={admitted} rejected(429)={rejected} other={other} "
          f"recovered={'yes' if post_ok else 'no'}")
    # Scenario passes if the limiter rejected excess AND a valid login recovered.
    return rejected > 0 and post_ok and pre_ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--suite", choices=["attack", "benign", "all"], default="all")
    ap.add_argument("--base", default=C.BASE)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    os.makedirs(RESULTS_DIR, exist_ok=True)
    run_id = time.strftime("%Y%m%d-%H%M%S")
    out_path = args.out or os.path.join(RESULTS_DIR, f"run-{run_id}.jsonl")
    print(f"run_id={run_id}  base={args.base}  -> {out_path}")

    with open(out_path, "w", encoding="utf-8") as out:
        if args.suite in ("attack", "all"):
            print("[attack suite]")
            for c in C.ATTACK_CASES:
                run_single(args.base, dict(c, run_id_ctx=run_id), args.timeout, out)
            run_brute(args.base, run_id, args.timeout, out)
        if args.suite in ("benign", "all"):
            print("[benign suite]")
            for c in C.BENIGN_CASES:
                run_single(args.base, dict(c, run_id_ctx=run_id), args.timeout, out)

    print(f"done -> {out_path}")
    print("next: python dashboard/summarize.py --results", out_path,
          "--access logs/nginx/access.log --audit logs/modsec/audit.log --out dashboard/alerts.json")


if __name__ == "__main__":
    main()
