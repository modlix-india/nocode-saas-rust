#!/usr/bin/env python3
"""Sends the same requests to the Java security service and to security-auth and compares them.

Usage: parity_security_auth.py [java_base] [rust_base]
       defaults: http://localhost:8001  http://localhost:8101

Local stack only. Cases come from the local `security` schema (read with the mysql CLI):
client URLs from `security_client_url`, and active users whose stored password is the local
`Pass@1234` (plain, so no attempt can be wrong and burn a lockout counter). No user is created.
Requests carry the headers the gateway sets (X-Forwarded-Host/Port/Proto, clientCode, appCode).

Compared: status, the security headers, and the body as JSON values. What must differ is
ignored and named in IGNORED; differences explained in crates/security/DIFFERENCES.md are
reported as EXPECTED. Besides the side-by-side cases it checks the two runtimes against each
other: a token minted by one is used on the other, a revoke on one is refused by the other
(and Java's own Redis entry for the token is gone after a Rust revoke), one-time tokens minted
on one are redeemed on the other, and an eviction published on `evictionChannel` empties the
Rust cache. Last, it times securityContextAuthentication on both.

The Redis URL (MODLIX__REDIS__URL in config/local.env) is read but never printed.
"""
import base64
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import error_parity


def _db_password():
    """The local MySQL password: MODLIX__DATABASE__PASSWORD, else config/local.env. Never printed."""
    v = os.environ.get("MODLIX__DATABASE__PASSWORD")
    if v:
        return v
    env = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "local.env")
    with open(env) as f:
        for line in f:
            if line.startswith("MODLIX__DATABASE__PASSWORD="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("MODLIX__DATABASE__PASSWORD is not set and config/local.env has none")


MYSQL_ENV = {**os.environ, "MYSQL_PWD": _db_password()}

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
JAVA = ARGS[0] if len(ARGS) > 0 else "http://localhost:8001"
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8101"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PASSWORD = "Pass@1234"

HEADERS_COMPARED = ["content-type", "cache-control", "pragma", "expires", "x-content-type-options",
                    "x-frame-options", "x-xss-protection", "referrer-policy"]

# Fields that cannot be equal between two calls, and why.
IGNORED = {
    "accessToken": "a new token per sign-in (random jti, own iat/exp)",
    "ssoToken": "a random one-time token per call",
    "token": "a random one-time token per call",
    "url": "carries the random one-time token",
    "appOneTimeToken": "a random one-time token per call",
    "appURL": "carries the random one-time token",
    "exceptionId": "time-based id per error",
    "stackTrace": "Java sends its server stack; security-auth never does (platform-wide difference)",
    "user.createdAt@anonymous": "the anonymous user is stamped with the current time",
    "user.updatedAt@anonymous": "the anonymous user is stamped with the current time",
    "accessTokenExpiryAt@basic": "Basic callers expire now + 1 year: the current time",
    "accessTokenExpiryAt@signin": "now + validity: compared to within 2 seconds instead",
    "client.managagingClient": "Java leaks it into its cached Client when /users/findUserClients ran on that JVM",
    "client.<fills>": "Java leaks owners, apps, managers and user counts into its cached Client when a "
                      "clients route with fetch* options ran on that JVM (parity_security_internal.py does)",
}

# The Client properties Java's fillDetails sets on its cached instance.
CLIENT_FILLS = ["managagingClient", "owners", "apps", "createdByUser", "clientManagers", "activeUsers", "inactiveUsers",
                "deletedUsers", "lockedUsers", "passwordExpiredUsers", "totalUsers"]

# Case-name prefixes with a known, explained difference (DIFFERENCES.md).
EXPECTED = {
    "401-": "the running Java build predates aca9929dd and still sends WWW-Authenticate: Basic realm=\"Realm\"",
}

RESULTS = {"SAME": 0, "EXPECTED": 0, "DIFF": 0}


def env_value(name):
    with open(os.path.join(ROOT, "config", "local.env")) as f:
        for line in f:
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip()
    raise SystemExit(f"{name} missing from config/local.env")


def sql(query):
    out = subprocess.run(["mysql", "-h127.0.0.1", "-uroot", "security", "-N", "-B", "-e", query], env=MYSQL_ENV,
                         capture_output=True, text=True, check=True)
    return [line.split("\t") for line in out.stdout.splitlines() if line.strip()]


def redis(*args):
    """One Redis command (RESP), authenticated with the password-only URL from local.env."""
    u = urllib.parse.urlparse(env_value("MODLIX__REDIS__URL"))
    pw = urllib.parse.unquote(u.password or u.username or "")

    def enc(parts):
        out = [f"*{len(parts)}\r\n".encode()]
        for p in parts:
            b = p if isinstance(p, bytes) else str(p).encode()
            out.append(f"${len(b)}\r\n".encode() + b + b"\r\n")
        return b"".join(out)

    s = socket.create_connection((u.hostname, u.port or 6379), timeout=5)
    f = s.makefile("rb")
    if pw:
        s.sendall(enc(["AUTH", pw]))
        f.readline()
    s.sendall(enc(list(args)))
    line = f.readline()
    s.close()
    return line.decode(errors="replace").strip()


def call(base, method, path, headers=None, body=None):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(base + path, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def parse(raw):
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return raw.decode(errors="replace")


def strip(v, kind):
    """Removes the IGNORED fields for this kind of case; returns a copy."""
    if not isinstance(v, dict):
        return v
    v = json.loads(json.dumps(v))
    for k in ["accessToken", "ssoToken", "token", "url", "appOneTimeToken", "appURL", "exceptionId", "stackTrace"]:
        v.pop(k, None)
    if isinstance(v.get("message"), str):
        v["message"] = re.sub(r"\d{4}-\d\d-\d\d-[0-9a-f]+", "<id>", v["message"])
    if isinstance(v.get("client"), dict):
        for k in CLIENT_FILLS:
            v["client"].pop(k, None)
    user = v.get("user")
    if kind == "anonymous" and isinstance(user, dict):
        user.pop("createdAt", None)
        user.pop("updatedAt", None)
    if kind == "basic":
        v.pop("accessTokenExpiryAt", None)
    if kind == "signin" and "accessTokenExpiryAt" in v:
        v["accessTokenExpiryAt"] = round(v["accessTokenExpiryAt"] / 10)
    return v


def authorities(v):
    try:
        return v["user"]["stringAuthorities"]
    except (KeyError, TypeError):
        return None


def report(name, verdict, detail=""):
    RESULTS[verdict] += 1
    print(f"{verdict:8} {name}{(': ' + detail) if detail else ''}")


def compare(name, java, rust, kind="plain"):
    rust, coded = error_parity.decode(java, rust)
    (js, jh, jb), (rs, rh, rb) = java, rust
    jv, rv = strip(parse(jb), kind), strip(parse(rb), kind)
    problems = []
    if js != rs:
        problems.append(f"status {js} vs {rs}")
    for h in HEADERS_COMPARED:
        if jh.get(h) != rh.get(h):
            problems.append(f"header {h}: {jh.get(h)!r} vs {rh.get(h)!r}")
    expected_only = []
    if jh.get("www-authenticate") != rh.get("www-authenticate"):
        expected_only.append("www-authenticate")
    if jv != rv:
        ja, ra = authorities(jv), authorities(rv)
        if ja is not None and ra is not None and ja != ra and sorted(ja) == sorted(ra):
            jv2, rv2 = json.loads(json.dumps(jv)), json.loads(json.dumps(rv))
            jv2["user"]["stringAuthorities"] = ra
            if jv2 == rv2:
                expected_only.append("stringAuthorities order")
            else:
                problems.append(f"body differs: {diff(jv, rv)}")
        else:
            problems.append(f"body differs: {diff(jv, rv)}")
    if problems:
        report(name, "DIFF", error_parity.detail(coded, "; ".join(problems)))
    elif error_parity.is_problem(coded):
        report(name, "DIFF", error_parity.detail(coded))
    elif expected_only:
        reason = next((r for p, r in EXPECTED.items() if name.startswith(p)), None)
        if "stringAuthorities order" in expected_only:
            reason = (reason + "; " if reason else "") + "same authorities, different order (Java served a list built before, cached in Redis)"
        report(name, "EXPECTED", error_parity.detail(coded, reason or ", ".join(expected_only)))
    else:
        v = error_parity.verdict("SAME", coded)
        report(name, v, error_parity.detail(coded) if v != "SAME" else "")


def diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if a.get(k) != b.get(k):
                return diff(a.get(k), b.get(k), f"{path}.{k}")
        return path
    return f"{path}: {json.dumps(a)[:160]} vs {json.dumps(b)[:160]}"


def both(method, path, headers=None, body=None):
    return call(JAVA, method, path, headers, body), call(RUST, method, path, headers, body)


def gw(client=None, app=None, host="localhost", port="8080", extra=None):
    h = {"X-Forwarded-Host": host, "X-Forwarded-Port": port, "X-Forwarded-Proto": "http", "X-Real-IP": "127.0.0.1"}
    if client is not None:
        h["clientCode"] = client
    if app is not None:
        h["appCode"] = app
    h.update(extra or {})
    return h


def sign_in(base, user_id, client, app, host="localhost", **flags):
    body = {"userId": user_id, "password": PASSWORD}
    body.update(flags)
    s, h, b = call(base, "POST", "/api/security/authenticate", gw(client, app, host), body)
    if s != 200:
        raise SystemExit(f"sign-in of {user_id} on {base} failed: {s} {b[:200]}")
    return json.loads(b)["accessToken"]


def users():
    """Active users with the plain local password, no failed attempts, and an app profile."""
    rows = sql(
        "select u.ID, c.CODE, min(a.APP_CODE) from security_user u join security_client c on c.ID = u.CLIENT_ID "
        "join security_profile_user pu on pu.USER_ID = u.ID join security_profile p on p.ID = pu.PROFILE_ID "
        "join security_app a on a.ID = p.APP_ID "
        f"where u.STATUS_CODE = 'ACTIVE' and u.PASSWORD = '{PASSWORD}' and u.PASSWORD_HASHED = 0 "
        "and coalesce(u.NO_FAILED_ATTEMPT, 0) = 0 and c.STATUS_CODE = 'ACTIVE' and u.ID in (142, 110, 226, 8, 221, 3991) "
        "group by u.ID, c.CODE order by u.ID")
    return [(int(r[0]), r[1], r[2]) for r in rows]


def hosts():
    rows = sql("select u.URL_PATTERN, c.CODE from security_client_url u join security_client c on c.ID = u.CLIENT_ID "
               "where u.URL_TYPE = 'LIVE' order by u.ID desc limit 8")
    return [(r[0], r[1]) for r in rows]


def main():
    ctx = "/api/security/internal/securityContextAuthentication"

    # Anonymous callers: by clientCode header, and by host as the client URLs name them.
    for client, app in [("SYSTEM", "appbuilder"), ("FIN", "leadzump"), ("SYSTEM", None), (None, None)]:
        compare(f"anonymous clientCode={client} appCode={app}", *both("GET", ctx, gw(client, app)), kind="anonymous")
    compare("anonymous unknown clientCode", *both("GET", ctx, gw("NOSUCHCLIENT", "appbuilder")))
    compare("anonymous empty clientCode", *both("GET", ctx, gw("", "appbuilder")))
    for pattern, code in hosts():
        host = re.sub(r"^https?://", "", pattern).split(":")[0].split("/")[0]
        compare(f"anonymous host {host} ({code})", *both("GET", ctx, gw(None, None, host)), kind="anonymous")
    compare("anonymous app subdomain host (Java 500, kept)", *both("GET", ctx, gw(None, None, "leadzump.local.modlix.com")))

    # Signed in: each user, a token minted by Java, used on both.
    tokens = {}
    for uid, client, app in users():
        t = sign_in(JAVA, uid, client, app)
        tokens[uid] = (t, client, app)
        h = gw(client, app, extra={"Authorization": f"Bearer {t}"})
        compare(f"signed-in user {uid} ({client}/{app}) Java token", *both("GET", ctx, h))
        compare(f"signed-in user {uid} again (Rust from its cache)", *both("GET", ctx, h))
        compare(f"verifyToken user {uid}", *both("GET", "/api/security/verifyToken", h))
        compare(f"refreshToken user {uid}", *both("GET", "/api/security/refreshToken", h), kind="signin")
        compare(f"external securityContextAuthentication user {uid}", *both("GET", "/api/security/securityContextAuthentication", h))
        compare(f"user/access user {uid} {app}", *both("POST", "/api/security/user/access", h, {"appCode": app}))
        compare(f"user/access user {uid} sitezump", *both("POST", "/api/security/user/access", h, {"appCode": "sitezump", "callbackUrl": "https://s/{token}"}))
        compare(f"token in the Authorization cookie user {uid}", *both("GET", ctx, gw(client, app, extra={"Cookie": f"Authorization={t}"})))
        compare(f"token from another host user {uid}", *both("GET", ctx, gw(client, app, host="other.example", extra={"Authorization": f"Bearer {t}"})))

    # Basic credentials.
    for cred, client, app in [("142:" + PASSWORD, "SYSTEM", "appbuilder"), ("kirangrandhi:" + PASSWORD, "SYSTEM", "appbuilder"),
                              ("110:" + PASSWORD, "FIN", "leadzump")]:
        h = gw(client, app, extra={"Authorization": "Basic " + base64.b64encode(cred.encode()).decode()})
        compare(f"basic {cred.split(':')[0]} {client}/{app}", *both("GET", ctx, h), kind="basic")

    # Sign-in responses side by side.
    for uid, (_, client, app) in tokens.items():
        body = {"userId": uid, "password": PASSWORD}
        compare(f"authenticate user {uid}", *both("POST", "/api/security/authenticate", gw(client, app), body), kind="signin")
    compare("authenticate by user name with remember-me", *both("POST", "/api/security/authenticate", gw("SYSTEM", "appbuilder"),
            {"userName": "kirangrandhi", "password": PASSWORD, "rememberMe": True}), kind="signin")
    js, rs = both("POST", "/api/security/authenticate", gw("SYSTEM", "appbuilder"), {"userId": 142, "password": PASSWORD, "cookie": True})
    compare("authenticate with cookie", js, rs, kind="signin")
    cookie_shape = lambda h: re.sub(r"Authorization=[^;]*|Expires=[^;]*", "X", h[1].get("set-cookie", ""))
    report("authenticate cookie attributes", "SAME" if cookie_shape(js) == cookie_shape(rs) else "DIFF", cookie_shape(rs))
    compare("authenticate with ssoToken", *both("POST", "/api/security/authenticate", gw("SYSTEM", "appbuilder"),
            {"userId": 142, "password": PASSWORD, "ssoToken": True}), kind="signin")
    compare("authenticate unknown user name", *both("POST", "/api/security/authenticate", gw("SYSTEM", "appbuilder"), {"userName": "nobody-zzz", "password": PASSWORD}))
    compare("authenticate without a password", *both("POST", "/api/security/authenticate", gw("SYSTEM", "appbuilder"), {"userName": "kirangrandhi"}))
    compare("authenticate unknown app falls back to a profile app", *both("POST", "/api/security/authenticate", gw("SYSTEM", "no-such-app"), {"userId": 142, "password": PASSWORD}), kind="signin")
    compare("authenticate bad JSON", *both("POST", "/api/security/authenticate", gw("SYSTEM", "appbuilder"), b"{"))
    compare("authenticate unknown clientCode", *both("POST", "/api/security/authenticate", gw("NOSUCHCLIENT", "appbuilder"), {"userId": 142, "password": PASSWORD}))
    compare("otp/generate flag false", *both("POST", "/api/security/authenticate/otp/generate", gw("SYSTEM", "appbuilder"), {"userId": 142}))
    compare("otp/generate unknown user", *both("POST", "/api/security/authenticate/otp/generate", gw("SYSTEM", "appbuilder"), {"userName": "nobody-zzz", "generateOtp": True}))
    compare("social blank state", *both("POST", "/api/security/authenticate/social", gw("SYSTEM", "appbuilder"), {"userName": "kiran@modlix.com"}))
    compare("social state nobody minted", *both("POST", "/api/security/authenticate/social", gw("SYSTEM", "appbuilder"), {"userName": "kiran@modlix.com", "socialRegisterState": "no-such-state"}))
    compare("wrong method on authenticate", *both("GET", "/api/security/authenticate", gw("SYSTEM", "appbuilder")))
    compare("verifyToken without a token", *both("GET", "/api/security/verifyToken", gw("SYSTEM", "appbuilder")))
    compare("verifyToken with a junk token", *both("GET", "/api/security/verifyToken", gw("SYSTEM", "appbuilder", extra={"Authorization": "Bearer junk"})))
    compare("redeem unknown one-time token", *both("GET", "/api/security/authenticateWithOneTimeToken/nosuchtoken", gw("SYSTEM", "appbuilder")))
    for method, path in [("GET", "/api/security/revoke"), ("GET", "/api/security/refreshToken"), ("POST", "/api/security/makeOneTimeToken"),
                         ("POST", "/api/security/internal/makeOneTimeToken"), ("POST", "/api/security/user/access"),
                         ("GET", "/api/security/securityContextAuthentication")]:
        compare(f"401-anonymous {method} {path}", *both(method, path, gw("SYSTEM", "appbuilder"), {} if method == "POST" else None))

    # One-time tokens minted on one side, redeemed on the other.
    jt = sign_in(JAVA, 142, "SYSTEM", "appbuilder")
    rt = sign_in(RUST, 142, "SYSTEM", "appbuilder")
    for minter, redeemer, t in [(JAVA, RUST, jt), (RUST, JAVA, rt)]:
        h = gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {t}"})
        s, _, b = call(minter, "POST", "/api/security/makeOneTimeToken", h, {"callbackUrl": "https://x{envDotPrefix}/{token}", "authMode": "BEARER"})
        ott = json.loads(b)
        ok = s == 200 and ott["url"] == f"https://x.local/{ott['token']}"
        s2, _, b2 = call(redeemer, "GET", f"/api/security/authenticateWithOneTimeToken/{ott['token']}", gw("SYSTEM", "appbuilder"))
        v = parse(b2) if s2 == 200 else {}
        ok = ok and s2 == 200 and v.get("user", {}).get("id") == 142 and v.get("authenticated") is False
        s3, _, _ = call(minter, "GET", f"/api/security/authenticateWithOneTimeToken/{ott['token']}", gw("SYSTEM", "appbuilder"))
        ok = ok and s3 == 403
        side = "Java->Rust" if minter == JAVA else "Rust->Java"
        report(f"one-time token minted {side}, redeemed once", "SAME" if ok else "DIFF", f"{s} {s2} {s3}")
    # A COOKIE one-time token sets the session cookie where it is redeemed.
    s, _, b = call(JAVA, "POST", "/api/security/makeOneTimeToken", gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {jt}"}), {"authMode": "COOKIE"})
    js = call(JAVA, "GET", f"/api/security/authenticateWithOneTimeToken/{json.loads(b)['token']}", gw("SYSTEM", "appbuilder"))
    s, _, b = call(JAVA, "POST", "/api/security/makeOneTimeToken", gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {jt}"}), {"authMode": "COOKIE"})
    rs = call(RUST, "GET", f"/api/security/authenticateWithOneTimeToken/{json.loads(b)['token']}", gw("SYSTEM", "appbuilder"))
    compare("redeem COOKIE one-time token", js, rs, kind="signin")
    shape = lambda r: re.sub(r"Authorization=[^;]*|Expires=[^;]*", "X", r[1].get("set-cookie", ""))
    report("redeem COOKIE one-time token cookie attributes", "SAME" if shape(js) == shape(rs) else "DIFF", f"{shape(js)} | {shape(rs)}")
    for name, body in [("makeOneTimeToken bad authMode", {"authMode": "header"}), ("makeOneTimeToken target authzump", {"targetAppCode": "authzump"}),
                       ("makeOneTimeToken untrusted target", {"targetAppCode": "sitezump"})]:
        js = call(JAVA, "POST", "/api/security/makeOneTimeToken", gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {jt}"}), body)
        rs = call(RUST, "POST", "/api/security/makeOneTimeToken", gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {jt}"}), body)
        compare(name, js, rs)
    js = call(JAVA, "POST", "/api/security/internal/makeOneTimeToken", gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {jt}"}), {"rememberMe": True})
    rs = call(RUST, "POST", "/api/security/internal/makeOneTimeToken", gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {jt}"}), {"rememberMe": True})
    compare("internal makeOneTimeToken rememberMe", js, rs)
    rows = sql("select REMEMBER_ME from security_one_time_token order by ID desc limit 2")
    report("internal makeOneTimeToken stores rememberMe on both", "SAME" if [r[0] for r in rows] == ["1", "1"] else "DIFF", str(rows))

    # Tokens across runtimes, and revocation in both directions.
    for minter, checker, label in [(JAVA, RUST, "Java token on Rust"), (RUST, JAVA, "Rust token on Java")]:
        t = sign_in(minter, 142, "SYSTEM", "appbuilder")
        h = gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {t}"})
        a = parse(call(minter, "GET", ctx, h)[2])
        b = parse(call(checker, "GET", ctx, h)[2])
        compare(f"{label}: context", (200, {}, json.dumps(a).encode()), (200, {}, json.dumps(b).encode()))
        call(minter, "GET", "/api/security/revoke", h)
        after = parse(call(checker, "GET", ctx, h)[2])
        report(f"{label}: revoked by the minter, refused by the other", "SAME" if after.get("authenticated") is False else "DIFF")
    # Java caches a token in Redis; a Rust revoke must remove it there too.
    t = sign_in(JAVA, 142, "SYSTEM", "appbuilder")
    h = gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {t}"})
    call(JAVA, "GET", ctx, h)
    time.sleep(0.3)
    cached_before = redis("HEXISTS", "cmn-tokenCache", t)
    call(RUST, "GET", "/api/security/revoke", h)
    time.sleep(0.3)
    cached_after = redis("HEXISTS", "cmn-tokenCache", t)
    java_after = parse(call(JAVA, "GET", ctx, h)[2])
    ok = cached_before == ":1" and cached_after == ":0" and java_after.get("authenticated") is False
    report("Rust revoke clears Java's cmn-tokenCache entry and Java refuses the token", "SAME" if ok else "DIFF",
           f"redis before {cached_before} after {cached_after}, java authenticated={java_after.get('authenticated')}")

    # An eviction published the way Java publishes it drops the Rust copy. Only a cache miss
    # reads the token row, and that stamps LAST_USED_AT (to the second): a hit leaves it alone.
    t = sign_in(RUST, 142, "SYSTEM", "appbuilder")
    h = gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {t}"})
    stamp = lambda: sql(f"select coalesce(LAST_USED_AT, 'null') from security_user_token where PART_TOKEN = '{t[-50:]}'")[0][0]
    call(RUST, "GET", ctx, h)
    first = stamp()
    time.sleep(1.2)
    call(RUST, "GET", ctx, h)
    hit = stamp()
    redis("PUBLISH", "evictionChannel", f"cmn-tokenCache:{t}")
    time.sleep(1.2)
    call(RUST, "GET", ctx, h)
    reread = stamp()
    ok = first != "null" and hit == first and reread > first
    report("eviction on evictionChannel drops the Rust token cache", "SAME" if ok else "DIFF",
           f"first {first}, cached {hit}, after eviction {reread}")
    call(RUST, "GET", "/api/security/revoke", h)

    # SSO logout on Rust revokes every token of the user, for Java too.
    a = sign_in(JAVA, 110, "FIN", "leadzump")
    b = sign_in(RUST, 110, "FIN", "leadzump")
    call(RUST, "GET", "/api/security/revoke?ssoLogout=true", gw("FIN", "leadzump", extra={"Authorization": f"Bearer {b}"}))
    states = [parse(call(base, "GET", ctx, gw("FIN", "leadzump", extra={"Authorization": f"Bearer {tok}"}))[2]).get("authenticated")
              for base in (JAVA, RUST) for tok in (a, b)]
    report("ssoLogout on Rust revokes every token of the user on both", "SAME" if states == [False] * 4 else "DIFF", str(states))

    # Clean up the Java-minted tokens of the side-by-side cases.
    for uid, (t, client, app) in tokens.items():
        call(JAVA, "GET", "/api/security/revoke", gw(client, app, extra={"Authorization": f"Bearer {t}"}))

    # Timing: securityContextAuthentication, signed in (cold = first call after sign-in, warm =
    # cached) and anonymous.
    for base, label in [(JAVA, "java"), (RUST, "rust")]:
        t = sign_in(base, 142, "SYSTEM", "appbuilder")
        h = gw("SYSTEM", "appbuilder", extra={"Authorization": f"Bearer {t}"})
        start = time.perf_counter()
        call(base, "GET", ctx, h)
        cold = (time.perf_counter() - start) * 1000
        warm = []
        for _ in range(200):
            start = time.perf_counter()
            call(base, "GET", ctx, h)
            warm.append((time.perf_counter() - start) * 1000)
        anon = []
        for _ in range(200):
            start = time.perf_counter()
            call(base, "GET", ctx, gw("SYSTEM", "appbuilder"))
            anon.append((time.perf_counter() - start) * 1000)
        warm.sort()
        anon.sort()
        print(f"TIMING   {label}: signed-in cold {cold:.1f} ms, warm p50 {warm[100]:.2f} ms p95 {warm[190]:.2f} ms; "
              f"anonymous p50 {anon[100]:.2f} ms p95 {anon[190]:.2f} ms")
        call(base, "GET", "/api/security/revoke", h)

    print(f"\nSUMMARY  SAME {RESULTS['SAME']}  EXPECTED {RESULTS['EXPECTED']}  DIFF {RESULTS['DIFF']}")
    sys.exit(1 if RESULTS["DIFF"] else 0)


if __name__ == "__main__":
    main()
