#!/usr/bin/env python3
"""Sends the same requests through the Spring gateway and gateway-rust and compares them.

Usage: parity_gateway.py [spring_base] [rust_base] [--ui-engine]
       defaults: http://localhost:8080  http://localhost:8180

--ui-engine: the Rust gateway sends /api/ui engine paths to ui-engine, whose ETag ids are content
digests where Java draws random ids (crates/ui/DIFFERENCES.md). ETags on /api/ui paths are then
compared by shape (W/ plus the login/draft prefix), not by value. HTML pages (ui-shell) are
compared with the bundle's entry script name masked, since each server reads it at startup.

Requests carry the headers nginx sends (Host, X-Forwarded-Proto, X-Real-IP, X-appCode...), so
host resolution, path stripping and header filling are exercised the way production does.
Compares status, body hash, and the response headers a service sets. Also times both.
"""
import base64
import hashlib
import json
import re
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, __import__("os").path.dirname(__import__("os").path.abspath(__file__)))
import error_parity  # coded Rust errors are compared by code (crates/security/DIFFERENCES.md)

UI_ENGINE = "--ui-engine" in sys.argv
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
SPRING = ARGS[0] if len(ARGS) > 0 else "http://localhost:8080"
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8180"
ETAG_SHAPE = re.compile(r"^W/(d-|dlg-|dnlg-|lg-|nlg-)?[0-9A-Za-z]+$")


def etag_shape(tag):
    if tag is None:
        return None
    m = re.match(r"^W/(d-|dlg-|dnlg-|lg-|nlg-)?", tag)
    return (m.group(0) if m else "?") + ("<id>" if ETAG_SHAPE.match(tag) else "<odd>")

BASIC = "Basic " + base64.b64encode(b"142:Pass@1234").decode()
COMPARED = ["content-type", "content-length", "cache-control", "etag", "content-disposition",
            "content-range", "x-cache", "last-modified", "location", "access-control-allow-origin"]


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def fetch(base, method, path, headers, body=None):
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    t = time.perf_counter()
    try:
        with OPENER.open(req, timeout=60) as r:
            data = r.read()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, data, time.perf_counter() - t
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(), time.perf_counter() - t


def nginx(host, extra=None):
    h = {"Host": host, "X-Forwarded-Proto": "https", "X-Real-IP": "10.1.2.3",
         "X-Full-URL": f"https://{host}/", "Accept": "*/*"}
    h.update(extra or {})
    return h


def normalize(body, ctype):
    """JSON bodies compared parsed, minus fields that differ per call (ids, times, tokens)."""
    if ctype and "json" in ctype:
        try:
            v = json.loads(body)
        except ValueError:
            return body
        volatile = {"exceptionId", "accessToken", "accessTokenExpiryAt", "refreshToken", "timestamp",
                    "message", "stackTrace", "debugMessage", "lastLogin", "updatedAt", "createdAt"}

        def strip(x):
            if isinstance(x, dict):
                return {k: strip(val) for k, val in x.items() if k not in volatile}
            if isinstance(x, list):
                return [strip(i) for i in x]
            return x
        return json.dumps(strip(v), sort_keys=True).encode()
    if UI_ENGINE and ctype and "html" in ctype:
        # Each server reads the bundle's entry script name when it starts (crates/ui DIFFERENCES 19).
        return re.sub(rb"/js/dist/index-[0-9a-f]+\.js", b"/js/dist/index-<entry>.js", body)
    return body


LZ = "leadzump.local.modlix.com"
CASES = [
    ("ui application by host", "GET", "/api/ui/application", nginx(LZ), None),
    ("ui page by host", "GET", "/api/ui/page/pageNotFound", nginx(LZ), None),
    ("ui page trailing slash", "GET", "/api/ui/page/pageNotFound/", nginx(LZ), None),
    ("ui theme", "GET", "/api/ui/theme", nginx(LZ), None),
    ("ui style", "GET", "/api/ui/style", nginx(LZ), None),
    ("ui page unknown", "GET", "/api/ui/page/doesNotExist", nginx(LZ), None),
    ("ui index html", "GET", "/", nginx(LZ, {"Accept": "text/html"}), None),
    ("page path with codes", "GET", "/leadzump/SYSTEM/page/pageNotFound", nginx("localhost"), None),
    ("manifest with codes", "GET", "/leadzump/SYSTEM/manifest/manifest.json", nginx("localhost"), None),
    ("api prefix ignored", "GET", "/x/y/api/ui/application", nginx(LZ), None),
    ("caller codes win", "GET", "/api/ui/application", nginx(LZ, {"appCode": "appbuilder", "clientCode": "SYSTEM"}), None),
    ("x-draft is stripped", "GET", "/api/ui/application", nginx(LZ, {"x-draft": "true"}), None),
    ("appbuilder signed in", "GET", "/api/ui/application", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("security verify basic", "GET", "/api/security/verifyToken", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("security anonymous internal", "GET", "/api/security/clients/internal/getClientNAppCodeNType?scheme=https&host=leadzump.local.modlix.com&port=-1", nginx("localhost"), None),
    ("files static", "GET", "/api/files/static/file/SYSTEM/loopzump/global/favicon/loopzump-32-v1.png", nginx(LZ), None),
    ("files static range", "GET", "/api/files/static/file/SYSTEM/loopzump/global/favicon/loopzump-32-v1.png", nginx(LZ, {"Range": "bytes=0-99"}), None),
    ("files large", "GET", "/api/files/static/file/SYSTEM/crumbco/home/bakes/baker-hands-story.png", nginx(LZ), None),
    ("files HEAD", "HEAD", "/api/files/static/file/SYSTEM/loopzump/global/favicon/loopzump-32-v1.png", nginx(LZ), None),
    ("files listing signed in", "GET", "/api/files/static/SYSTEM?size=5", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("core functions repositoryFind", "GET", "/api/core/functions/repositoryFind?namespace=System&name=Print", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM"}), None),
    ("core anonymous data refused", "GET", "/api/core/data/nothing", nginx(LZ), None),
    # Unmapped core paths and methods: Spring Security answers an anonymous caller first.
    ("core unmapped anonymous", "GET", "/api/core/nonexistent", nginx("localhost"), None),
    ("core unmapped index anonymous", "GET", "/api/core/index/nothing", nginx("localhost"), None),
    ("core unmapped internal anonymous", "GET", "/api/core/internal/nothing", nginx("localhost"), None),
    ("core unmapped storages anonymous", "GET", "/api/core/storages/a/b/c", nginx(LZ), None),
    ("core-exec unmapped anonymous", "GET", "/api/core/data/a/b/c/d", nginx("localhost"), None),
    ("core unmapped permitted anonymous", "GET", "/api/core/function/nothing", nginx("localhost"), None),
    ("core unmapped signed in", "GET", "/api/core/nonexistent", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("core unmapped internal signed in", "GET", "/api/core/internal/nothing", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("core-exec unmapped signed in", "GET", "/api/core/data/a/b/c/d", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("core wrong method anonymous", "PUT", "/api/core/index", nginx("localhost"), None),
    ("core wrong method signed in", "PUT", "/api/core/index", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("core-exec wrong method signed in", "PUT", "/api/core/eventRuns", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("ai health via route", "GET", "/api/ai/health", nginx("localhost"), None),
    ("POST body passes", "POST", "/api/security/authenticate", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Content-Type": "application/json"}),
     json.dumps({"userName": "142", "password": "Pass@1234", "rememberMe": False}).encode()),
    ("unknown api path to ui", "GET", "/api/unknownsvc/x", nginx(LZ), None),
    ("multi index signed in", "GET", "/api/multi/application/leadzumptwo/index?type=page", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("multi anonymous", "GET", "/api/multi/application/leadzumptwo/index", nginx(LZ), None),
    ("core execute GET", "GET", "/api/core/function/execute/System.Math/Add?value=1&value=2", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("core execute POST", "POST", "/api/core/function/execute/System.Math/Maximum", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC, "Content-Type": "application/json"}), b'{"value":[4,9,2]}'),
    ("ui function missing", "GET", "/api/ui/function/No/Such", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM"}), None),
    ("ui urlDetails", "GET", "/api/ui/urlDetails", nginx(LZ), None),
    ("ui pages CRUD stays on Java", "GET", "/api/ui/pages?size=1", nginx("localhost", {"appCode": "appbuilder", "clientCode": "SYSTEM", "Authorization": BASIC}), None),
    ("CORS simple GET", "GET", "/api/ui/application", nginx(LZ, {"Origin": "https://other.com"}), None),
    ("OPTIONS without CORS", "OPTIONS", "/api/ui/application", nginx(LZ), None),
    ("CORS preflight", "OPTIONS", "/api/ui/application", nginx(LZ, {"Origin": "https://other.com", "Access-Control-Request-Method": "GET"}), None),
]

# Differences that are documented and intended; reported, not counted as failures.
EXPECTED = {
    "core execute GET": "integer arithmetic answers 3 where kirun-java keeps the GET's double, 3.0 (crates/core/DIFFERENCES.md)",
}

# Properties Java security's fillDetails sets on the Client it caches, which later answers on that
# JVM then carry (crates/security/DIFFERENCES.md); Rust never does.
CLIENT_FILLS = ["managagingClient", "owners", "apps", "createdByUser", "clientManagers", "activeUsers", "inactiveUsers",
                "deletedUsers", "lockedUsers", "passwordExpiredUsers", "totalUsers"]


def only_client_leaks(a, b):
    """True when two JSON bodies differ only by the Client fill properties Java leaks."""
    exact = {"parse_float": lambda t: ("float", t), "parse_int": lambda t: ("int", t)}
    try:
        x, y = json.loads(a, **exact), json.loads(b, **exact)
    except ValueError:
        return False
    for v in (x, y):
        if isinstance(v, dict) and isinstance(v.get("client"), dict):
            for k in CLIENT_FILLS:
                v["client"].pop(k, None)
    return x == y


same = 0
expected = 0
ts, tr = [], []
for name, method, path, headers, body in CASES:
    s_status, s_h, s_b, s_t = fetch(SPRING, method, path, headers, body)
    r_status, r_h, r_b, r_t = fetch(RUST, method, path, headers, body)
    ts.append(s_t)
    tr.append(r_t)
    (r_status, r_h, r_b), coded = error_parity.decode((s_status, s_h, s_b), (r_status, r_h, r_b))
    problems = []
    if s_status != r_status:
        problems.append(f"status spring={s_status} rust={r_status}")
    for k in COMPARED:
        if s_h.get(k) != r_h.get(k):
            if k == "etag" and UI_ENGINE and "html" in (s_h.get("content-type") or "") \
                    and normalize(s_b, s_h.get("content-type")) == normalize(r_b, r_h.get("content-type")):
                continue
            if k == "etag" and UI_ENGINE and "/api/ui/" in path \
                    and etag_shape(s_h.get(k)) == etag_shape(r_h.get(k)):
                continue
            if k == "content-length" and "json" in (s_h.get("content-type") or ""):
                continue
            problems.append(f"{k}: spring={s_h.get(k)!r} rust={r_h.get(k)!r}")
    nb_s = normalize(s_b, s_h.get("content-type"))
    nb_r = normalize(r_b, r_h.get("content-type"))
    leak_only = False
    if hashlib.sha256(nb_s).digest() != hashlib.sha256(nb_r).digest():
        if not problems and "json" in (s_h.get("content-type") or "") and only_client_leaks(s_b, r_b):
            leak_only = True
        else:
            problems.append(f"body differs ({len(s_b)} vs {len(r_b)} bytes): spring={s_b[:120]!r} rust={r_b[:120]!r}")
    if error_parity.is_problem(coded):
        problems.append(coded)
    if not problems and coded:
        expected += 1
        print(f"EXPECTED  {name}  [{s_status}]  {error_parity.EXPECTED_NOTE} ({coded})")
    elif leak_only:
        expected += 1
        print(f"EXPECTED  {name}  [{s_status}]  Java security's cached Client carries fields an earlier fill set on it (crates/security/DIFFERENCES.md)")
    elif problems and name in EXPECTED:
        expected += 1
        print(f"EXPECTED  {name}  [{s_status}]  {EXPECTED[name]}")
    elif problems:
        print(f"DIFFERENT {name}  [{s_status}]")
        for p in problems:
            print(f"            {p}")
    else:
        same += 1
        print(f"SAME      {name}  [{s_status}]  spring {s_t*1000:.1f}ms  rust {r_t*1000:.1f}ms")

print(f"\n{same}/{len(CASES)} same, {expected} expected.  total time spring {sum(ts)*1000:.0f}ms  rust {sum(tr)*1000:.0f}ms")
sys.exit(0 if same + expected == len(CASES) else 1)
