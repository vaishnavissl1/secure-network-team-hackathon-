"""
Canonical PS6 test cases (Person B).

One place that defines every attack and benign request, each with its EXPECTED
application outcome. The runner (runner.py) replays these; the summarizer scores
benign requests by expected outcome, not just "not 403".

Routes are the REAL Juice Shop server routes (a browser '#/' fragment never
reaches the server). Verify GOOD_LOGIN on your own instance before the scored run.
"""

# 127.0.0.1 (not "localhost"): Windows resolves localhost to ::1 first and each request
# then waits ~2s for the IPv4 fallback, which also hides the rate limiter.
BASE = "https://127.0.0.1:8443"
LOGIN_PATH = "/rest/user/login"

# Populated at runtime with an ordinary lab shopper.
GOOD_LOGIN = {}

# ---------------------------------------------------------------------------
# Attack suite: 5 single-request exploit classes (expect a WAF 403 block) +
# the brute-force burst handled as a scenario (see BRUTE below).
# expected.type:
#   "blocked"     -> WAF should return 403
#   "allowed"     -> should pass (2xx/3xx), optional body_contains
#   "rejected_edge" -> refused by nginx before the WAF (400); never forwarded to the app
# ---------------------------------------------------------------------------
ATTACK_CASES = [
    {"id": "atk-sqli-01", "klass": "sqli", "method": "GET",
     "path": "/rest/products/search?q=%27%29%29%20UNION%20SELECT%20id,email,password,4,5,6,7,8,9%20FROM%20Users--",
     "expected": {"type": "blocked"}},
    {"id": "atk-xss-01", "klass": "xss", "method": "GET",
     "path": "/rest/products/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
     "expected": {"type": "blocked"}},
    {"id": "atk-trav-01", "klass": "traversal", "method": "GET",
     "path": "/ftp?file=../../../../etc/passwd",
     "expected": {"type": "blocked"}},
    # Path-form traversal: nginx normalises ..%2f above the root and answers 400 itself
    # before ModSecurity runs. It never reaches the app, but it is NOT a WAF 403, so it is
    # reported separately and not counted toward the 5 WAF-blocked exploit classes.
    {"id": "atk-trav-02", "klass": "traversal_path", "method": "GET",
     "path": "/ftp/..%2f..%2f..%2fetc%2fpasswd",
     "expected": {"type": "rejected_edge"}},
    {"id": "atk-cmdi-01", "klass": "cmdi", "method": "GET",
     "path": "/rest/products/search?q=%3Bcat%20/etc/passwd",
     "expected": {"type": "blocked"}},
    {"id": "atk-scan-01", "klass": "scanner", "method": "GET", "path": "/",
     "headers": {"User-Agent": "sqlmap/1.8"},
     "expected": {"type": "blocked"}},
]

# Brute-force scenario: a burst of wrong logins (expect the limiter to reject the
# excess with 429) bracketed by a correct login before and after (expect 200).
BRUTE = {
    "id": "atk-brute",
    "klass": "bruteforce",
    "path": LOGIN_PATH,
    "attempts": 25,
    "bad": {"email": "admin@juice-sh.op", "password": "wrong-on-purpose"},
}

# ---------------------------------------------------------------------------
# Benign suite: 20 normal requests, each with an expected outcome.
# ---------------------------------------------------------------------------
def _get(i, path, body_contains=None):
    exp = {"type": "allowed"}
    if body_contains:
        exp["body_contains"] = body_contains
    return {"id": f"ben-{i:02d}", "klass": "benign", "method": "GET",
            "path": path, "expected": exp}


BENIGN_CASES = [
    _get(1, "/"),
    _get(2, "/rest/products/search?q="),
    _get(3, "/rest/products/search?q=apple"),
    _get(4, "/rest/products/search?q=juice"),
    _get(5, "/rest/products/search?q=banana"),
    _get(6, "/rest/products/search?q=cherry"),
    _get(7, "/rest/products/search?q=lemon"),
    _get(8, "/rest/products/search?q=cola"),
    _get(9, "/rest/products/search?q=green"),
    _get(10, "/rest/products/search?q=tea"),
    _get(11, "/rest/products/search?q=coffee"),
    _get(12, "/api/Products/1"),
    _get(13, "/api/Products/2"),
    _get(14, "/api/Products/3"),
    _get(15, "/api/Products/4"),
    _get(16, "/api/Products/5"),
    _get(17, "/rest/languages"),
    _get(18, "/rest/admin/application-version"),
    _get(19, "/rest/admin/application-configuration"),
    # 20: a correct-credential login -> expect 200 + an auth token in the body.
    {"id": "ben-20", "klass": "benign", "method": "POST", "path": LOGIN_PATH,
     "json": GOOD_LOGIN, "expected": {"type": "allowed", "body_contains": "authentication"}},
]
