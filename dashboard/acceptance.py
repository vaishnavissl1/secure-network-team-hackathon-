"""Run defensive checks or score a supplied replay without publishing dashboard data."""

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from summarize import BENIGN, BURST, EDGE, POST, PRE, WAF, records, summarize

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "tests/results"
PASS, FAIL, NOT_RUN = "PASS", "FAIL", "NOT RUN"


def check(name, status, detail):
    return {"check": name, "status": status, "detail": detail}


def run_check(script):
    print(f"Running {script}", flush=True)
    return subprocess.run(["bash", script], cwd=ROOT, check=False).returncode == 0


def load_summary(results, access, audit):
    """Treat absent paths as untested and malformed evidence as a failed check."""
    missing = []
    for label, path, needs_data in (
        ("results", results, True), ("nginx access log", access, True),
        ("ModSecurity audit log", audit, False),
    ):
        try:
            if not path.is_file() or (needs_data and path.stat().st_size == 0):
                missing.append(f"{label}: {path}")
        except OSError:
            missing.append(f"{label}: {path}")
    if missing:
        detail = "Missing or empty evidence — " + "; ".join(missing)
        print(detail, file=sys.stderr, flush=True)
        return NOT_RUN, detail, None

    try:
        doc = summarize(list(records(results)), records(access), records(audit))
    except (OSError, ValueError, KeyError, AttributeError, TypeError) as exc:
        # JSON parsing errors include a file and line number, not raw log content.
        detail = f"Evidence could not be scored ({exc})" if isinstance(exc, ValueError) else "Evidence could not be read or has an invalid schema."
        print(detail, file=sys.stderr, flush=True)
        return FAIL, detail, None

    responded = [row for row in doc["rows"] if row["status"] is not None]
    matched = sum(row["correlated"] for row in responded)
    timed_out = len(doc["rows"]) - len(responded)
    detail = f"{matched}/{len(responded)} responses matched proxy method and status; {timed_out} requests had no response"
    return PASS if responded and matched == len(responded) else FAIL, detail, doc


def shopper_verdict(doc):
    if not doc or not BENIGN <= {row["case_id"] for row in doc["rows"]}:
        return check("Benign shopper traffic", NOT_RUN, "The complete 20-case shopper schedule was not supplied")
    count = doc["benign"]["passed"]
    login = next(row for row in doc["rows"] if row["case_id"] == "ben-20")
    login_status = "passed" if login["passed"] else "failed"
    return check("Benign shopper traffic", PASS if doc["benign"]["ok"] else FAIL,
                 f"{count}/20 passed (target 95%); shopper login {login_status}")


def replay_verdicts(args, results):
    summary_status, summary_detail, doc = load_summary(results, args.access, args.audit)
    ids = {row["case_id"] for row in doc["rows"]} if doc else set()
    categories = NOT_RUN
    categories_detail = "The five category cases require matching replay records and logs"
    if WAF.keys() <= ids:
        categories = PASS if doc["attacks"]["exploit_ok"] else FAIL
        categories_detail = f"{doc['totals']['blocked']}/{len(WAF)} verified inbound WAF blocks"
    burst = NOT_RUN
    burst_detail = "The complete login burst and pre/post recovery records are required"
    if BURST | {PRE, POST} <= ids:
        actual = doc["attacks"]["bruteforce"]
        burst = PASS if doc["attacks"]["bruteforce_ok"] else FAIL
        recovered = "passed" if actual["recovered"] else "failed"
        burst_detail = f"{actual['rejected']}/{len(BURST)} limited; {actual['admitted']} admitted; recovery {recovered}"

    full_schedule = BENIGN | BURST | WAF.keys() | {PRE, POST, EDGE}
    full = NOT_RUN
    if full_schedule <= ids:
        full = PASS if doc["full_suite_ok"] and summary_status == PASS else FAIL
    full_detail = f"{len(ids & full_schedule)}/{len(full_schedule)} required cases supplied"
    verdicts = [
        check("Attack-category replay", categories, categories_detail),
        check("Login burst replay", burst, burst_detail),
        shopper_verdict(doc),
        check("TLS and edge checks", NOT_RUN, "Replay mode only reads supplied evidence"),
        check("Evidence correlation", summary_status, summary_detail),
        check("Full replay", full, full_detail),
    ]
    overall = FAIL if any(item["status"] == FAIL for item in verdicts) else full
    return verdicts, overall, doc


def defensive_verdicts(args, output_dir):
    if not sys.platform.startswith("linux"):
        print("Run defensive verification on the Ubuntu VM. Use --replay to score saved evidence here.", file=sys.stderr, flush=True)
        edge = NOT_RUN
    else:
        missing = [path for path in (ROOT / "certs/server.crt", args.access, args.audit) if not path.is_file()]
        if missing:
            print("Start the lab with bash scripts/up.sh. Missing: " + ", ".join(map(str, missing)), file=sys.stderr, flush=True)
            edge = NOT_RUN
        else:
            edge = PASS if run_check("scripts/verify-edge.sh") else FAIL

    doc = None
    shopper = check("Benign shopper traffic", NOT_RUN, "TLS and edge checks must pass first")
    summary_status, summary_detail = NOT_RUN, "No shopper evidence was scored"
    policy = limiter = NOT_RUN
    if edge == PASS:
        policy = PASS if run_check("scripts/verify-waf.sh") else FAIL
        limiter = PASS if run_check("scripts/verify-rate-limit.sh") else FAIL
        shopper_results = args.shopper_results
        shopper_ran = shopper_results is None
        if shopper_ran:
            shopper_results = output_dir / "shopper.jsonl"
            print("Running 20 requests with an ordinary lab shopper", flush=True)
            shopper_exit = subprocess.run(
                [sys.executable, "tests/shopper.py", "--out", str(shopper_results)],
                cwd=ROOT, check=False,
            ).returncode
        else:
            shopper_exit = 0
            print(f"Scoring supplied shopper evidence: {shopper_results}", flush=True)

        if shopper_ran and shopper_exit:
            shopper = check("Benign shopper traffic", FAIL, "The shopper runner did not complete")
        else:
            summary_status, summary_detail, doc = load_summary(shopper_results, args.access, args.audit)
            shopper = shopper_verdict(doc)
            if doc and any(row["case_id"] not in BENIGN for row in doc["rows"]):
                summary_status, summary_detail = FAIL, "Defensive mode requires a shopper-only results file"

    verdicts = [
        check("TLS and edge checks", edge, "Trusted HTTPS, backend isolation, and proxy checks"),
        check("WAF policy probe", policy, "Correlated 403 before Juice Shop"),
        check("Login rate limit and recovery", limiter, "Credential-free 429 probe and recovery"),
        shopper,
        check("Evidence correlation", summary_status, summary_detail),
        check("Full replay", NOT_RUN, "Defensive verification covers no attack replay; use --replay with captured evidence"),
    ]
    statuses = {result["status"] for result in verdicts[:-1]}
    overall = FAIL if FAIL in statuses else NOT_RUN if NOT_RUN in statuses else PASS
    return verdicts, overall, doc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", nargs="?", type=Path, help="recorded replay results (same as --replay)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--replay", type=Path, metavar="RESULTS", help="score a recorded replay without sending requests")
    mode.add_argument("--shopper-results", type=Path, metavar="RESULTS",
                      help="reuse recorded shopper results while running the live defensive controls")
    parser.add_argument("--access", type=Path, default=ROOT / "logs/nginx/access.log", help="matching nginx access log")
    parser.add_argument("--audit", type=Path, default=ROOT / "logs/modsec/audit.log", help="matching ModSecurity audit log")
    args = parser.parse_args()
    if args.results and (args.replay or args.shopper_results):
        parser.error("Use either the positional results path or one mode option")
    results = args.replay or args.results
    if not results and (args.access != ROOT / "logs/nginx/access.log" or args.audit != ROOT / "logs/modsec/audit.log"):
        parser.error("Use the VM logs in defensive verification. Alternate log paths are for --replay.")

    mode_name = "Replay evidence" if results else "Defensive verification"
    print(f"Shield Wall | {mode_name}", flush=True)
    try:
        RESULTS.mkdir(parents=True, exist_ok=True)
        directory = Path(tempfile.mkdtemp(prefix="acceptance-", dir=RESULTS))
    except OSError:
        print(f"Cannot create an acceptance report under {RESULTS}", file=sys.stderr)
        return 2
    if results:
        verdicts, overall, doc = replay_verdicts(args, results)
    else:
        verdicts, overall, doc = defensive_verdicts(args, directory)

    report = {
        "mode": mode_name,
        "overall": overall,
        "run_id": doc["run_id"] if doc else None,
        "checks": verdicts,
    }
    target = directory / "verdict.json"
    with target.open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=2)
        file.write("\n")
    print()
    for item in verdicts:
        print(f"[{item['status']}] {item['check']} — {item['detail']}")
    print(f"[{overall}] {mode_name}")
    print(f"Acceptance report: {target.relative_to(ROOT)}", flush=True)
    return {PASS: 0, FAIL: 1, NOT_RUN: 2}[overall]


if __name__ == "__main__":
    sys.exit(main())
