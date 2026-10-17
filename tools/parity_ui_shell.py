#!/usr/bin/env python3
"""Sends the same requests to the Java ui service and to ui-shell and compares them.

Usage: parity_ui_shell.py [java_base] [rust_base] [--quick]
       defaults: http://localhost:8002  http://localhost:8106

Cases:
- the index page for every app and client in the local `security_client_url` table (read with
  the mysql CLI, password from config/local.env, never printed), on its own host, live and
  draft, at `/` and at a path with `/api/` in it (a URI path lookup that finds nothing), with
  ETag revalidation;
- `manifest/manifest.json` and `/apiDocs` per app; `/js/dist/**` (the asset manifest, entry
  scripts, a style sheet, a missing file);
- URI path routes that exist locally and do not write: GET routes whose functions only verify
  (`hub.challenge`), POST/PUT/DELETE routes whose functions are missing in core, and the body
  refusals (no body, form body, a body that is not a JSON object);
- `/hassso` (bounce and logout, refused and unknown hosts), `/sso/{token}` with one-time tokens
  minted locally for user 142 (each server gets its own), ACME;
- the analytics proxy (anonymous, a bad zone, a real query, an engine refusal, an app without
  analytics), the cache endpoints, `/api/ui/newdeployment`;
- OPTIONS, a CORS preflight, missing gateway headers, an unusable token.

Compared: status, the headers that matter, and the body. Known differences (DIFFERENCES.md)
are normalised and reported as notes: the entry script tags of the index page (each server
reads the asset manifest when it starts), the access token in an SSO page, the Feign text in
a relayed error's debugMessage.
"""
import base64
import concurrent.futures
import http.client
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

import error_parity  # coded Rust errors are compared by code (crates/ui/DIFFERENCES.md, Error bodies)

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
QUICK = "--quick" in sys.argv
JAVA = ARGS[0] if len(ARGS) > 0 else "http://localhost:8002"
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8106"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECURITY = "http://localhost:8001"

BASIC = "Basic " + base64.b64encode(b"142:Pass@1234").decode()

COMPARED = [
    "content-type", "cache-control", "pragma", "expires", "x-content-type-options", "x-xss-protection",
    "referrer-policy", "content-security-policy", "content-security-policy-report-only", "allow",
    "accept-patch", "access-control-allow-origin",
]

# Differences DIFFERENCES.md explains; matched on the case name prefix.
EXPECTED = {
    "missing clientCode": "Java asks security without a clientCode and relays its 500; the platform "
                          "security client sends an empty one, so the header check answers 400",
}


def env(name):
    with open(os.path.join(ROOT, "config", "local.env")) as f:
        for line in f:
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip()
    raise SystemExit(f"{name} missing from config/local.env")


def sql(query):
    """A read-only query on the local security schema."""
    out = subprocess.run(["mysql", "-h127.0.0.1", "-uroot", "security", "-N", "-B", "-e", query],
                         capture_output=True, text=True, check=True,
                         env=dict(os.environ, MYSQL_PWD=env("MODLIX__DATABASE__PASSWORD")))
    return [line.split("\t") for line in out.stdout.splitlines() if line]


def fetch(base, path, headers=None, method="GET", data=None, timeout=120):
    """One request, header names sent exactly as given (the gateway sends `appCode`, and a
    URI path route without a header mapping passes every header on under its own name)."""
    u = urllib.parse.urlsplit(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    try:
        conn.putrequest(method, path, skip_accept_encoding=True)
        for k, v in (headers or {}).items():
            conn.putheader(k, v)
        if data is not None:
            conn.putheader("Content-Length", str(len(data)))
        conn.endheaders(data)
        r = conn.getresponse()
        return r.status, r.msg, r.read()
    finally:
        conn.close()


def hget(h, name):
    v = h.get_all(name)
    return None if not v else ", ".join(v)


SCRIPTS = re.compile(r'(<script src="[^"]*/js/dist/[^"]+"></script>)+')


def normalize_body(kind, body):
    text = body.decode("utf-8", "replace")
    if kind == "html":
        return SCRIPTS.sub("<ENTRY/>", text)
    if kind == "sso":
        text = re.sub(r"setItem\('AuthToken', '\"[^\"']+\"'\)", "setItem('AuthToken', '<token>')", text)
        return re.sub(r"AuthTokenExpiry', '\d+'", "AuthTokenExpiry', '<expiry>'", text)
    return text


def normalize_error(d):
    """Exception ids and stack traces are per occurrence; a relayed Feign error's debugMessage
    is Java's Feign text."""
    d = dict(d)
    eid = d.pop("exceptionId", None)
    d.pop("stackTrace", None)
    for k in ("message", "debugMessage"):
        if eid and isinstance(d.get(k), str):
            d[k] = d[k].replace(eid, "<id>")
    if isinstance(d.get("message"), str):
        d["message"] = re.sub(r"\d{4}-\d{2}-\d{2}-[0-9a-f]+", "<id>", d["message"])
    dm = d.get("debugMessage")
    if isinstance(dm, str) and re.match(r"^\[\d{3} [^\]]*\] during \[", dm):
        d["debugMessage"] = d.get("message")
    return d


class Result:
    def __init__(self, name, problems, info=None, coded=None):
        self.name, self.problems, self.info = name, problems, info or []
        # error_parity's note: "coded CODE" when Rust's coded error stands for Java's text.
        self.coded = coded


class Headers:
    """Response headers after error_parity has put Rust's answer into Java's shape."""

    def __init__(self, pairs):
        self.pairs = [(k.lower(), v) for k, v in pairs]

    def get_all(self, name):
        return [v for k, v in self.pairs if k == name.lower()] or None

    def get(self, name, default=None):
        v = self.get_all(name)
        return v[0] if v else default

    def items(self):
        return list(self.pairs)


def decoded(j, r):
    """Rust's answer as Java would have sent it when it is a coded error standing for Java's
    text (error_parity.decode), and the note."""
    (js, jh, jb), (rs, rh, rb) = j, r
    jd = {k.lower(): v for k, v in jh.items()}
    rd = {k.lower(): v for k, v in rh.items()}
    (s, hd, b), note = error_parity.decode((js, jd, jb), (rs, rd, rb))
    if note is None or error_parity.is_problem(note):
        return r, note
    pairs = [(k, v) for k, v in rh.items() if k.lower() not in ("content-type", "content-length")]
    if hd.get("content-type") is not None:
        pairs.append(("content-type", hd["content-type"]))
    return (s, Headers(pairs), b), note


def first_diff(a, b, path="$"):
    if type(a) is not type(b):
        return f"{path}: {short(a)} vs {short(b)}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a or k not in b or a[k] != b[k]:
                return first_diff(a.get(k), b.get(k), f"{path}.{k}") if k in a and k in b else \
                    f"{path}.{k}: java={short(a.get(k))} rust={short(b.get(k))}"
    if isinstance(a, list) and len(a) != len(b):
        return f"{path}: list of {len(a)} vs {len(b)}"
    if isinstance(a, list):
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return first_diff(x, y, f"{path}[{i}]")
    if isinstance(a, str) and isinstance(b, str):
        i = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))
        return f"{path}: at {i}: java={a[max(0, i - 40):i + 60]!r} rust={b[max(0, i - 40):i + 60]!r}"
    return f"{path}: {short(a)} vs {short(b)}"


def short(v):
    s = json.dumps(v) if not isinstance(v, str) else repr(v)
    return s if len(s) < 140 else s[:137] + "..."


def compare_answers(name, j, r, kind=None):
    r, coded = decoded(j, r)
    (js, jh, jb), (rs, rh, rb) = j, r
    problems, info = [], []
    if js != rs:
        problems.append(f"status java={js} rust={rs}")
    for k in COMPARED:
        jv, rv = hget(jh, k), hget(rh, k)
        if jv != rv:
            problems.append(f"{k}: java={short(jv)} rust={short(rv)}")
    jx, rx = sorted(jh.get_all("x-frame-options") or []), sorted(rh.get_all("x-frame-options") or [])
    if jx != rx:
        problems.append(f"x-frame-options: java={jx} rust={rx}")
    if hget(rh, "www-authenticate"):
        problems.append("rust sent WWW-Authenticate")
    elif hget(jh, "www-authenticate"):
        info.append("no WWW-Authenticate (nocode-saas aca9929dd; the running Java build predates it)")
    normalised = False
    if jb != rb:
        jt, rt = normalize_body(kind, jb), normalize_body(kind, rb)
        if jt == rt:
            normalised = True
            info.append({"html": "entry scripts differ (asset manifest read at start)",
                         "sso": "token and expiry differ (one-time tokens)"}.get(kind, "normalised"))
        else:
            try:
                jv, rv = json.loads(jb), json.loads(rb)
            except Exception:
                problems.append(f"body differs ({len(jb)} vs {len(rb)} bytes): {first_diff(jt, rt)}")
            else:
                error = isinstance(jv, dict) and "exceptionId" in jv
                if error and isinstance(rv, dict):
                    jv, rv = normalize_error(jv), normalize_error(rv)
                if jv != rv:
                    problems.append(f"json body differs ({len(jb)} vs {len(rb)} bytes): {first_diff(jv, rv)}")
                elif not error:
                    info.append("same json value, different text")
    je, re_ = hget(jh, "etag"), hget(rh, "etag")
    if (je is None) != (re_ is None):
        problems.append(f"etag: java={je} rust={re_}")
    elif je and je != re_ and not normalised:
        problems.append(f"etag java={je} rust={re_}")
    return Result(name, problems, info, coded)


def compare(name, path, headers=None, method="GET", data=None, kind=None, revalidate=False):
    j = fetch(JAVA, path, headers, method, data)
    r = fetch(RUST, path, headers, method, data)
    res = compare_answers(name, j, r, kind)
    if revalidate and j[0] == 200 and r[0] == 200:
        for base, ans, label in ((JAVA, j, "java"), (RUST, r, "rust")):
            tag = hget(ans[1], "etag")
            if not tag:
                continue
            h2 = dict(headers or {})
            h2["If-None-Match"] = tag
            s2, h2r, b2 = fetch(base, path, h2, method, data)
            if s2 != 304:
                res.problems.append(f"{label} did not revalidate its own etag: {s2}")
            elif hget(h2r, "cache-control") != hget(ans[1], "cache-control"):
                res.problems.append(f"{label} 304 cache-control {hget(h2r, 'cache-control')!r}")
    return res


def gw(app, client, host=None, port="443", auth=False, draft=False, **extra):
    h = {"appCode": app, "clientCode": client, "X-Forwarded-Host": host or f"{app}.local.modlix.com",
         "X-Forwarded-Port": port}
    if auth:
        h["Authorization"] = BASIC
    if draft:
        h["x-draft"] = "true"
    h.update(extra)
    return h


def mint_ott(app="leadzump"):
    """A one-time token for user 142 (local only)."""
    body = json.dumps({"targetAppCode": app, "targetClientCode": "SYSTEM"}).encode()
    s, _, b = fetch(SECURITY, "/api/security/makeOneTimeToken",
                    {"Authorization": BASIC, "appCode": app, "clientCode": "SYSTEM",
                     "X-Forwarded-Host": f"{app}.local.modlix.com", "X-Forwarded-Port": "80",
                     "Content-Type": "application/json"}, "POST", body)
    if s != 200:
        raise SystemExit(f"could not mint a one-time token: {s}")
    return json.loads(b)["token"]


def sso_case(name, query, headers):
    j = fetch(JAVA, f"/sso/{mint_ott()}{query}", headers)
    r = fetch(RUST, f"/sso/{mint_ott()}{query}", headers)
    return compare_answers(name, j, r, kind="sso")


def index_cases():
    rows = sql("select u.URL_PATTERN, u.APP_CODE, c.CODE, u.URL_TYPE from security_client_url u "
               "join security_client c on c.ID = u.CLIENT_ID order by u.ID")
    seen, cases = set(), []
    for url, app, client, kind in rows:
        parsed = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
        host = parsed.hostname or url
        port = str(parsed.port or (443 if parsed.scheme == "https" else 80))
        key = (app, client, kind)
        if key in seen:
            continue
        seen.add(key)
        draft = kind == "DRAFT"
        label = f"index {app}/{client}{' draft' if draft else ''} on {host}"
        cases.append((label, "/", gw(app, client, host, port, draft=draft), dict(kind="html", revalidate=True)))
        if len(seen) <= 60:
            cases.append((label + " /x/page/api/y", "/x/page/api/y", gw(app, client, host, port, draft=draft),
                          dict(kind="html")))
    return cases, sorted({(a, c) for a, c, _ in seen})


def js_cases():
    _, _, b = fetch(RUST, "/js/dist/asset-manifest.json", {})
    m = json.loads(b)
    files = list((m.get("files") or {}).values())
    scripts = (m.get("entrypoints") or {}).get("index", [])[:3]
    css = [f.rsplit("/", 1)[-1] for f in files if isinstance(f, str) and f.endswith(".css")][:1]
    cases = [("js asset-manifest.json", "/js/dist/asset-manifest.json", {}, dict(revalidate=True))]
    for s in scripts + css:
        cases.append((f"js {s}", f"/js/dist/{s}", {}, dict(revalidate=True)))
    cases.append(("js missing file", "/js/dist/missing-parity-x.js", {}, {}))
    cases.append(("js missing file with headers", "/js/dist/nested/missing.css", gw("leadzump", "SYSTEM"), {}))
    return cases


def route_cases():
    j = {"Content-Type": "application/json"}
    lz2 = gw("leadzumptwo", "SYSTEM")
    lz = gw("leadzump", "SYSTEM")
    ab = gw("appbuilder", "SYSTEM", **j)
    tz = gw("testzerozero", "SYSTEM", **j)
    verify = "?hub.mode=subscribe&hub.challenge=4242&hub.verify_token=wrong"
    return [
        ("route GET leadzumptwo campaigns (error event with body)", f"/api/open/tickets/req/campaigns{verify}", lz2, {}),
        ("route GET leadzump campaigns (output result.result)", f"/api/open/tickets/req/campaigns{verify}", lz, {}),
        ("route GET leadzumptwo facebook (a mapped parameter missing)",
         "/api/open/collector/entry/social/facebook?hub.mode=subscribe&hub.challenge=77", lz2, {}),
        ("route GET leadzumptwo facebook", f"/api/open/collector/entry/social/facebook{verify}", lz2, {}),
        ("route GET leadzumptwo campaigns signed in", f"/api/open/tickets/req/campaigns{verify}",
         gw("leadzumptwo", "SYSTEM", auth=True), {}),
        ("route POST appbuilder hello (function missing in core)", "/hello/x/y/C/B", ab,
         dict(method="POST", data=b'{"q":1,"n":1.50}')),
        ("route POST testzerozero hello", "/hello/a%20b/y/C/B/as", tz, dict(method="POST", data=b'{"a":[1,2]}')),
        ("route PUT appbuilder hello (no PUT definition)", "/hello/x/y/C/B", ab, dict(method="PUT", data=b"{}")),
        ("route DELETE appbuilder hello", "/hello/x/y/C/B", ab, dict(method="DELETE", data=b"{}")),
        ("route PATCH no route", "/nomatch/x", ab, dict(method="PATCH", data=b"{}")),
        ("route POST /api/ no route", "/api/nomatch", ab, dict(method="POST", data=b"{}")),
        ("route POST whitespace body", "/hello/x/y/C/B", ab, dict(method="POST", data=b"   ")),
        ("route POST no body", "/hello/x/y/C/B", ab, dict(method="POST")),
        ("route POST form body", "/hello/x/y/C/B", gw("appbuilder", "SYSTEM", **{"Content-Type": "application/x-www-form-urlencoded"}),
         dict(method="POST", data=b"a=b")),
        ("route POST text body", "/hello/x/y/C/B", gw("appbuilder", "SYSTEM", **{"Content-Type": "text/plain"}),
         dict(method="POST", data=b'{"t":"x"}')),
        ("route POST not json", "/hello/x/y/C/B", ab, dict(method="POST", data=b"not json")),
        ("route POST array", "/hello/x/y/C/B", ab, dict(method="POST", data=b"[1]")),
        ("route POST null", "/hello/x/y/C/B", ab, dict(method="POST", data=b"null")),
        ("route POST lenient object", "/hello/x/y/C/B", ab, dict(method="POST", data=b"{a:1, 'b':'x'}")),
        ("route GET /api/ no route serves the page", "/api/nomatch", lz, dict(kind="html")),
        ("route GET hello is a page (no /api/)", "/hello/x/y/C/B", gw("appbuilder", "SYSTEM"), dict(kind="html")),
        ("route HEAD /api/ path", "/api/open/tickets/req/campaigns", lz2, dict(method="HEAD")),
    ]


def scratch_cases():
    """Routes of the scratch app `shellparity` (a security app, the core functions
    `shellparity.echo` and `shellparity.fail`, and four URI paths, all created through the
    APIs for this script; see DIFFERENCES.md). Skipped when it is not there."""
    sp = gw("shellparity", "SYSTEM")
    if fetch(JAVA, "/api/parity/fail?kind=msg", sp)[0] != 422:
        print("scratch app shellparity not found: its route cases are skipped")
        return []
    j = dict(sp, **{"Content-Type": "application/json"})
    return [
        ("scratch GET mapped path, query and header", "/api/parity/echo/x%20y/2?q=hello+world&z=1", sp, {}),
        ("scratch GET mapped, a parameter missing", "/api/parity/echo/x/y", sp, {}),
        ("scratch GET mapped, encoded path", "/api/parity/echo/a%2Fb/%E2%82%AC?q=%3Cq%3E", sp, {}),
        ("scratch GET mapped signed in", "/api/parity/echo/x/y?q=1", gw("shellparity", "SYSTEM", auth=True), {}),
        ("scratch GET mapped draft", "/api/parity/echo/x/y?q=1", gw("shellparity", "SYSTEM", draft=True), {}),
        ("scratch GET unmapped (every query parameter and header)", "/api/parity/raw/A1?q=Q&q=Q2&b=%3Cb%3E", sp, {}),
        ("scratch GET unmapped, a parameter without a value", "/api/parity/raw/A1?flag", sp, {}),
        ("scratch GET output parameter list[-1]", "/api/parity/pick?q=1&a=2", sp, {}),
        ("scratch POST output parameter missing", "/api/parity/pick", j, dict(method="POST", data=b"{}")),
        ("scratch PUT output parameter on a string", "/api/parity/pick", j, dict(method="PUT", data=b"{}")),
        ("scratch DELETE output parameter an object", "/api/parity/pick", j, dict(method="DELETE", data=b"{}")),
        ("scratch POST body and mappings", "/api/parity/echo/p1/p2?q=fromQuery", j,
         dict(method="POST", data=b'{"aParam":"fromBody","n":1.50,"big":12345678901234567890,"s":"\\u00e9<"}')),
        ("scratch POST unmapped body", "/api/parity/raw/A1", j, dict(method="POST", data=b'{"q":"body","aParam":"x"}')),
        ("scratch POST lenient body", "/api/parity/raw/A1", j, dict(method="POST", data=b"{q:'lenient'}")),
        ("scratch GET error event with body", "/api/parity/fail?kind=body", sp, {}),
        ("scratch GET error event with message", "/api/parity/fail?kind=msg", sp, {}),
        ("scratch POST error event without errorEventName", "/api/parity/fail", j, dict(method="POST", data=b"{}")),
        ("scratch PATCH error event", "/api/parity/fail", j, dict(method="PATCH", data=b'{"kind":"body"}')),
        ("scratch GET route method without a definition", "/api/parity/raw/x", dict(sp, **{"x-ignored": "1"}), dict(method="HEAD")),
    ]


def misc_cases(pairs):
    lz = gw("leadzump", "SYSTEM")
    cases = []
    for app, client in pairs[: (10 if QUICK else 80)]:
        h = gw(app, client)
        cases.append((f"manifest {app}/{client}", "/manifest/manifest.json", h, dict(revalidate=True)))
        cases.append((f"apiDocs {app}/{client}", "/apiDocs", h, dict(revalidate=True)))
    for missing in ["X-Forwarded-Host", "X-Forwarded-Port", "appCode", "clientCode"]:
        h = {k: v for k, v in lz.items() if k != missing}
        cases.append((f"missing {missing} GET /", "/", h, {}))
        cases.append((f"missing {missing} POST", "/hello/x/y/C/B", dict(h, **{"Content-Type": "application/json"}),
                      dict(method="POST", data=b"{}")))
    for missing in ["appCode", "clientCode"]:
        h = {k: v for k, v in lz.items() if k != missing}
        cases.append((f"missing {missing} manifest", "/manifest/manifest.json", h, {}))
        cases.append((f"missing {missing} apiDocs", "/apiDocs", h, {}))
    cases += [
        ("unusable token GET /", "/", dict(lz, Authorization="Bearer not.a.token"), dict(kind="html")),
        ("unusable basic credentials GET /", "/", dict(lz, Authorization="Basic " + base64.b64encode(b"nobody:x").decode()),
         dict(kind="html")),
        ("OPTIONS /", "/", {}, dict(method="OPTIONS")),
        ("OPTIONS /hassso", "/hassso", lz, dict(method="OPTIONS")),
        ("OPTIONS /api/ui/analytics/query", "/api/ui/analytics/query", {}, dict(method="OPTIONS")),
        ("OPTIONS /js/dist/x.js", "/js/dist/x.js", {}, dict(method="OPTIONS")),
        ("CORS preflight", "/api/ui/analytics/query",
         {"Origin": "https://elsewhere.example", "Access-Control-Request-Method": "POST"}, dict(method="OPTIONS")),
        ("POST /apiDocs (the ** body mapping)", "/apiDocs", dict(lz, **{"Content-Type": "application/json"}),
         dict(method="POST", data=b"{}")),
        ("acme unknown token", "/.well-known/acme-challenge/parity-unknown", {}, {}),
        ("firewall encoded slash", "/a%2Fb", lz, {}),
        ("firewall semicolon", "/api/open/x;jsessionid=1", lz, {}),
        ("firewall encoded percent", "/js/dist/a%2520b.js", {}, {}),
        ("firewall dot segment", "/a/./b", lz, {}),
        ("firewall double slash", "/api//x", lz, dict(method="POST", data=b"{}")),
        ("firewall line separator", "/a/%E2%80%A8", lz, {}),
        ("firewall method TRACE", "/", lz, dict(method="TRACE")),
        ("firewall control character in a parameter name", "/hassso?targetAppCode%0a=x", lz, {}),
        ("firewall control character in a parameter value is fine", "/api/nomatch?q=%0a", lz, dict(kind="html")),
        ("hassso without targetAppCode", "/hassso", lz, {}),
        ("hassso empty targetAppCode", "/hassso?targetAppCode=&returnUrl=https://leadzump.local.modlix.com/", lz, {}),
        ("hassso no returnUrl", "/hassso?targetAppCode=leadzump", lz, {}),
        ("hassso javascript returnUrl", "/hassso?targetAppCode=leadzump&returnUrl=javascript:alert(1)", lz, {}),
        ("hassso bounce", "/hassso?targetAppCode=leadzump&targetClientCode=SYSTEM&returnUrl="
         + urllib.parse.quote("https://leadzump.local.modlix.com/deals?x=1&y='<b>'", safe=""), lz, {}),
        ("hassso bounce with port", "/hassso?targetAppCode=leadzump&returnUrl=https://leadzump.local.modlix.com:8443/p", lz, {}),
        ("hassso logout", "/hassso?targetAppCode=leadzump&mode=logout&returnUrl=http://leadzump.local.modlix.com/", lz, {}),
        ("hassso wrong app for the host", "/hassso?targetAppCode=appbuilder&returnUrl=https://leadzump.local.modlix.com/", lz, {}),
        ("hassso unknown host", "/hassso?targetAppCode=leadzump&returnUrl=https://unknown-parity.example/", lz, {}),
        ("hassso userinfo spoof", "/hassso?targetAppCode=leadzump&returnUrl="
         + urllib.parse.quote("https://leadzump.local.modlix.com@evil.example/", safe=""), lz, {}),
        ("sso bad token", "/sso/not-a-token", lz, {}),
        ("newdeployment anonymous", "/api/ui/newdeployment", lz, {}),
        ("newdeployment signed in", "/api/ui/newdeployment", gw("leadzump", "SYSTEM", auth=True), {}),
        ("cache evict one (unused name)", "/api/ui/internal/cache/parityUnusedCache", {}, dict(method="DELETE")),
        ("cache evict 'stats' (the DELETE mapping)", "/api/ui/internal/cache/stats", {}, dict(method="DELETE")),
        ("cache GET a name (the ** mapping)", "/api/ui/internal/cache/parityUnusedCache", lz, dict(kind="html")),
    ]
    a = dict(lz, **{"Content-Type": "application/json"})
    au = dict(a, Authorization=BASIC)
    query = json.dumps({"widget": "topPages", "from": "2026-10-01T00:00:00Z", "to": "2026-10-15T00:00:00Z", "limit": 5}).encode()
    cases += [
        ("analytics anonymous", "/api/ui/analytics/query", a, dict(method="POST", data=b'{"widget":"topPages"}')),
        ("analytics bad zone", "/api/ui/analytics/query", au, dict(method="POST", data=b'{"widget":"topPages","timezone":"Mars/Base"}')),
        ("analytics query", "/api/ui/analytics/query", au, dict(method="POST", data=query)),
        ("analytics query in a zone", "/api/ui/analytics/query", au,
         dict(method="POST", data=json.dumps({"widget": "topPages", "from": "2026-10-01T00:00:00Z",
                                              "to": "2026-10-15T00:00:00Z", "timezone": "Europe/London"}).encode())),
        ("analytics engine refusal", "/api/ui/analytics/query", au, dict(method="POST", data=b'{"widget":"nope"}')),
        ("analytics app without analytics", "/api/ui/analytics/query", dict(au, appCode="appbuilder"),
         dict(method="POST", data=b'{"widget":"topPages"}')),
        ("analytics no body", "/api/ui/analytics/query", au, dict(method="POST")),
        ("analytics missing appCode", "/api/ui/analytics/query", {k: v for k, v in au.items() if k != "appCode"},
         dict(method="POST", data=b"{}")),
    ]
    return cases


def sso_cases():
    lz = gw("leadzump", "SYSTEM")
    return [
        ("sso default redirect", "", lz),
        ("sso same-origin path", "?redirectUrl=/deals%3Fa%3D1", lz),
        ("sso protocol-relative", "?redirectUrl=//evil.example/", lz),
        ("sso own host", "?redirectUrl=" + urllib.parse.quote("https://leadzump.local.modlix.com/x?q=<1>", safe=""), lz),
        ("sso other app host", "?redirectUrl=" + urllib.parse.quote("https://appbuilder.local.modlix.com/x", safe=""), lz),
        ("sso unknown host", "?redirectUrl=" + urllib.parse.quote("https://unknown-parity.example/", safe=""), lz),
        ("sso with X-Real-IP", "?redirectUrl=/", dict(lz, **{"X-Real-IP": "10.9.8.7"})),
    ]


def cache_shape_cases():
    out = []
    for path, want in (("/api/ui/internal/cache", list), ("/api/ui/internal/cache/stats", dict)):
        j, r = fetch(JAVA, path), fetch(RUST, path)
        problems = []
        if j[0] != r[0]:
            problems.append(f"status java={j[0]} rust={r[0]}")
        if hget(j[1], "content-type") != hget(r[1], "content-type"):
            problems.append(f"content-type java={hget(j[1], 'content-type')} rust={hget(r[1], 'content-type')}")
        jv, rv = json.loads(j[2]), json.loads(r[2])
        if not isinstance(jv, want) or not isinstance(rv, want):
            problems.append(f"shape java={type(jv).__name__} rust={type(rv).__name__}")
        elif want is dict:
            jk = {tuple(sorted(v)) for v in jv.values()}
            rk = {tuple(sorted(v)) for v in rv.values()}
            if rk - jk:
                problems.append(f"stat keys java={jk} rust={rk}")
        out.append(Result(f"cache {path} (shape; the names are each instance's own)", problems))
    return out


def main():
    idx, pairs = index_cases()
    if QUICK:
        idx = idx[:40]
    cases = idx + js_cases() + route_cases() + scratch_cases() + misc_cases(pairs)
    print(f"{len(cases)} cases ({len(idx)} index pages from {len(pairs)} app/client pairs), "
          f"{len(sso_cases())} SSO logins, 2 cache shapes, the full cache reset")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futs = [pool.submit(compare, n, p, h, **kw) for n, p, h, kw in cases]
        for f in futs:
            results.append(f.result())
    results += [sso_case(n, q, h) for n, q, h in sso_cases()]
    results += cache_shape_cases()
    # Last: it empties every cache on the local stack. Java's reset leaves Redis empty, so a page
    # read through Java refills a few caches before ui-shell's reset walks them.
    j = fetch(JAVA, "/api/ui/internal/cache", {}, "DELETE")
    fetch(JAVA, "/", gw("leadzump", "SYSTEM"))
    r = fetch(RUST, "/api/ui/internal/cache", {}, "DELETE")
    results.append(compare_answers("cache reset all (DELETE /api/ui/internal/cache)", j, r))

    failures, same, expected = 0, 0, 0
    notes = {}
    for r in results:
        exp = next((v for k, v in EXPECTED.items() if r.name.startswith(k)), None)
        if error_parity.is_problem(r.coded):
            r.problems.append(r.coded)
        if not r.problems and r.coded:
            expected += 1
            print(f"EXPECTED  {r.name}: {error_parity.detail(r.coded)}")
        elif not r.problems:
            same += 1
            for i in r.info:
                notes[i] = notes.get(i, 0) + 1
            if os.environ.get("VERBOSE"):
                print(f"SAME      {r.name}" + (f"  ({'; '.join(r.info)})" if r.info else ""))
        elif exp:
            expected += 1
            print(f"EXPECTED  {r.name}: {exp}")
            for p in r.problems:
                print(f"            {p}")
        else:
            failures += 1
            print(f"DIFFERENT {r.name}")
            for p in r.problems:
                print(f"            {p}")
    noted = ", ".join(f"{n} {k}" for k, n in sorted(notes.items()))
    print(f"\n{same} same{f' ({noted})' if noted else ''}, {expected} expected, "
          f"{failures} different, of {len(results)}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
