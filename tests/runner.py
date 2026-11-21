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
    python tests/runner.py --suite all --base https://127.0.0.1:8443

Notes:
 - The runner trusts the lab certificate and restricts requests to local HTTPS.
 - Every row keeps its case_id even on timeout (request_id=null, passed=false),
   so missing requests stay in the denominator.
"""
import getpass
from pathlib import Path
import uuid
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
class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = None
# Connect to 127.0.0.1 but present the real vhost so CRS rule 920350 (numeric-IP Host) stays quiet.
HOST_HEADER = "shield.local:8443"
_CFG = {"host": HOST_HEADER}


def _send(base, case, timeout):
    """Send one request. Return (status, request_id, elapsed_ms, note)."""
    url = base + case["path"]
    headers = dict(case.get("headers") or {})
    data = None
    if case.get("json") is not None:
        data = json.dumps(case["json"]).encode()
        headers.setdefault("Content-Type", "application/json")
    headers.setdefault("Host", _CFG["host"])
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method=case.get("method", "GET"))
    t0 = time.time()
    try:
        with _OPENER.open(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
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
    if exp["type"] == "rejected_edge":
        return status in (400, 403)
    if exp["type"] == "allowed":
        if status != 200:
            return False
        path = case["path"].split("?")[0]
        if path == "/":
            return "<html" in body.lower()
        try:
            obj = json.loads(body)
            if path == C.LOGIN_PATH:
                auth = obj["authentication"]
                return bool(auth["token"]) and auth.get("umail") == C.GOOD_LOGIN["email"]
            if path == "/rest/products/search":
                return obj.get("status") == "success" and isinstance(obj.get("data"), list)
            if path.startswith("/api/Products/"):
                return str(obj["data"]["id"]) == path.rsplit("/", 1)[-1]
            return bool(obj) and isinstance(obj, (list, dict))
        except (ValueError, TypeError, KeyError, AttributeError):
            return False
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
    ap.add_argument("--host-header", default=HOST_HEADER)
    ap.add_argument("--timeout", type=float, default=8.0)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    if args.base not in ("https://127.0.0.1:8443", "https://localhost:8443") or args.host_header != HOST_HEADER:
        ap.error("Use the local Shield Wall HTTPS endpoint")
    global _OPENER
    ca = Path(__file__).resolve().parents[1] / "certs" / "server.crt"
    _OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))), NoRedirects())
    email = os.environ.get("SHIELD_SHOPPER_EMAIL") or input("Lab shopper email: ").strip()
    password = os.environ.get("SHIELD_SHOPPER_PASSWORD") or getpass.getpass("Lab shopper password: ")
    if not email or not password:
        ap.error("A registered lab shopper is required")
    C.GOOD_LOGIN.update(email=email, password=password)
    _CFG["host"] = args.host_header
    os.makedirs(RESULTS_DIR, exist_ok=True)
    run_id = "lab-" + uuid.uuid4().hex[:16]
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
