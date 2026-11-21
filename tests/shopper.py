"""Run the normal shopper cases against the VM's certificate-verified loopback edge."""
import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import secrets
import ssl
import urllib.error
import urllib.request
import uuid

from shopper_cases import BENIGN_CASES

ROOT = Path(__file__).resolve().parents[1]
BASE = "https://127.0.0.1:8443"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(opener, path, payload=None):
    headers = {"Host":"shield.local:8443", "User-Agent":"ShieldWall-Shopper"}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode()
    req = urllib.request.Request(BASE + path, data=body, headers=headers)
    try:
        response = opener.open(req, timeout=10)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return response.status, response.headers.get("X-Request-ID"), response.read()


def register(opener):
    def api(path, payload=None):
        status, _, body = request(opener,path,payload)
        if status not in (200,201):
            raise RuntimeError(f"Shopper registration failed at {path} (HTTP {status})")
        return json.loads(body)["data"]
    q = api("/api/SecurityQuestions/")[0]
    credentials = {"email":"demo-"+uuid.uuid4().hex[:12]+"@example.invalid",
                   "password":secrets.token_hex(16)}
    answer = secrets.token_hex(12)
    user = api("/api/Users/", dict(credentials,passwordRepeat=credentials["password"],
                                   securityQuestion=q,securityAnswer=answer))
    if user.get("role") != "customer":
        raise RuntimeError("Expected an ordinary shopper")
    api("/api/SecurityAnswers/",{"UserId":user["id"], "SecurityQuestionId":q["id"], "answer":answer})
    return credentials


def valid(path, body, email):
    if path == "/":
        return b"<html" in body.lower()
    doc = json.loads(body)
    if path == "/rest/user/login":
        auth = doc.get("authentication",{})
        return bool(auth.get("token")) and auth.get("umail")==email
    if path.startswith("/rest/products/search"):
        return doc.get("status")=="success" and isinstance(doc.get("data"),list)
    if path.startswith("/api/Products/"):
        return str(doc["data"]["id"])==path.rsplit("/",1)[-1]
    return isinstance(doc,(list,dict)) and bool(doc)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--register", action="store_true", help="Create one disposable ordinary shopper")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ROOT/"certs/server.crt")))
    creds = register(opener) if args.register else {
        "email":os.environ.get("SHIELD_SHOPPER_EMAIL") or input("Shopper email: ").strip(),
        "password":os.environ.get("SHIELD_SHOPPER_PASSWORD") or getpass.getpass("Shopper password: ")}
    run = datetime.now(timezone.utc).strftime("vm-%Y%m%dT%H%M%SZ-")+uuid.uuid4().hex[:6]
    args.out.parent.mkdir(parents=True,exist_ok=True)
    with args.out.open("w",encoding="utf8") as output:
        for case in BENIGN_CASES:
            status = rid = None
            passed = False
            try:
                status,rid,body = request(opener,case["path"],creds if case["method"]=="POST" else None)
                passed = status==200 and valid(case["path"],body,creds["email"])
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                pass
            row = {"run_id":run, "case_id":case["id"], "klass":"benign","method":case["method"],
                   "uri":case["path"],"request_id":rid,"status":status,"passed":passed}
            output.write(json.dumps(row)+"\n")
            print(case["id"],status,"PASS" if passed else "FAIL")


if __name__ == "__main__":
    main()
