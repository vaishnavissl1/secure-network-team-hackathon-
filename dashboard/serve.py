"""Serve the evaluator site, published verification, and sanitized activity on loopback."""

import argparse
from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
REQUEST_ID = re.compile(r"[a-f0-9]{32}")
RULE_ID = re.compile(r"[0-9]{5,7}")
LOG_WINDOW = 1024 * 1024
ROW_LIMIT = 120
VISIBLE_ROUTES = {
    "/", "/rest/user/login", "/rest/user/whoami", "/rest/products/search",
    "/rest/languages", "/rest/admin/application-version",
    "/rest/admin/application-configuration", "/api/Products",
    "/__shield_wall_crs_probe", "/socket.io/",
}
RULE_LABELS = {
    "913": "Scanner indicator",
    "930": "Path traversal signature",
    "932": "Command injection signature",
    "941": "Cross-site scripting signature",
    "942": "SQL injection signature",
}


def recent_json(path):
    """Read complete lines from a bounded tail of a log being appended to."""
    with path.open("rb") as log:
        end = log.seek(0, 2)
        start = max(0, end - LOG_WINDOW)
        log.seek(start)
        if start:
            log.seek(start - 1)
            if log.read(1) != b"\n":
                log.readline(end - start)
        for line in log.read(end - log.tell()).splitlines(keepends=True):
            if not line.endswith(b"\n"):
                continue
            try:
                record = json.loads(line)
            except (ValueError, UnicodeError):
                continue
            if isinstance(record, dict):
                yield record


def activity():
    project_logs = ROOT.parent / "logs"
    access = []
    for row in recent_json(project_logs / "nginx/access.log"):
        request_id = row.get("request_id", "")
        uri = row.get("uri", "")
        status = row.get("status")
        if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
            continue
        if type(status) is not int or not isinstance(uri, str) or uri == "/healthz":
            continue
        if status < 400 and uri == "/socket.io/":
            continue
        if status < 400 and uri not in VISIBLE_ROUTES and not re.fullmatch(r"/api/Products/[0-9]+", uri):
            continue
        access.append(row)

    rows = list(reversed(access[-ROW_LIMIT:]))
    blocked = {row["request_id"] for row in rows if row["status"] == 403 and not row.get("upstream_status")}
    audit_rules = {}
    for event in recent_json(project_logs / "modsec/audit.log"):
        tx = event.get("transaction", {})
        rid = tx.get("unique_id")
        if rid in blocked and tx.get("is_interrupted") is True:
            rules = (str(m.get("details", {}).get("ruleId", "")) for m in tx.get("messages", ()))
            audit_rules[rid] = sorted({rule for rule in rules if RULE_ID.fullmatch(rule)})

    response = []
    for row in rows:
        rid = row["request_id"]
        status = row["status"]
        uri = row["uri"]
        method = row.get("method")
        raw_upstream = row.get("upstream_status", "")
        upstream = raw_upstream if isinstance(raw_upstream, str) and re.fullmatch(r"[1-5][0-9]{2}", raw_upstream) else ""
        raw_time = row.get("time", "")
        time = raw_time if isinstance(raw_time, str) and re.fullmatch(r"[0-9T:+Z-]{20,25}", raw_time) else ""
        rules = audit_rules.get(rid, [])
        labels = sorted({RULE_LABELS[r[:3]] for r in rules if r[:3] in RULE_LABELS})
        if "920420" in rules:
            labels.append("Content type policy")
        if status == 429 and row.get("limit_req_status") == "REJECTED" and not upstream:
            decision = "Rate limited"
        elif rid in audit_rules:
            decision = "WAF blocked"
        elif upstream:
            decision = "Forwarded"
        else:
            decision = "Edge response"
        response.append({
            "time": time,
            "request_id": rid,
            "method": method if method in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS") else "OTHER",
            "route": uri if uri in VISIBLE_ROUTES else "/api/Products/:id" if re.fullmatch(r"/api/Products/[0-9]+", uri) else "Other route",
            "status": status,
            "upstream": upstream,
            "decision": decision,
            "rules": rules,
            "signals": labels,
        })
    return response


class Handler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        if urlsplit(path).path == "/alerts.json":
            return str(ROOT / "alerts.json")
        return super().translate_path(path)

    def do_GET(self):
        if urlsplit(self.path).path != "/activity.json":
            return super().do_GET()
        try:
            payload = json.dumps({"rows": activity()}).encode("utf-8")
        except OSError:
            self.send_error(HTTPStatus.SERVICE_UNAVAILABLE, "Activity logs unavailable")
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def list_directory(self, path):
        self.send_error(HTTPStatus.NOT_FOUND)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8099)
    port = parser.parse_args().port
    site = ROOT / "site"
    if not (site / "demo/index.html").is_file():
        parser.error("Build the Estate static pages with dashboard/build_estate.py and deploy dashboard/site first")
    handler = partial(Handler, directory=str(site))
    with ThreadingHTTPServer(("127.0.0.1", port), handler) as server:
        print(f"Dashboard http://127.0.0.1:{port}", flush=True)
        server.serve_forever()
