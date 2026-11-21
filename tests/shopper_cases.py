"""Scheduled normal browsing, search and login requests."""
LOGIN_PATH = "/rest/user/login"
GOOD_LOGIN = {}

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
