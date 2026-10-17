#!/usr/bin/env python3
"""Triggers the security and gateway errors through the all-Rust gateway, and prints what a
person sees: status, code, message and action.

Usage: error_scenarios.py [gateway_base] [--keep] [--only=<substring>]
       default gateway: http://localhost:8182 (every security route goes to the Rust units)
       --keep leaves the scratch data in place (it is removed by default)

Local stack only. Rules this script keeps:
- Java security gets no request from it: everything goes through the all-Rust gateway, whose
  security routes reach security-auth, security-internal and security-admin.
- Writes touch only scratch data it creates through the APIs, checked right before each call:
  two scratch clients (`ZZERA<run>`, `ZZERB<run>`, under SYSTEM) with appbuilder read access, a
  user in each, roles and designations in them. Real users' ids are never written to; the SYSTEM
  user 142 (local password `Pass@1234`) only acts, as the admin who creates and removes the
  scratch data.
- Wrong passwords go only to the scratch users, never to a real account.
- Everything is removed at the end (users and clients can only be marked DELETED).

The gateway's own errors: `GW.SERVICE_STARTING` comes from 8182 (a route whose service is not
running); the others need an upstream that misbehaves, so the script starts a scratch gateway
(the same binary, `target/release/gateway-rust`, on port 8199 with a config under
`target/scratch/errors/`) in front of small local stubs: a closed port, a slow server, one that
drops the connection, and a security stub that fails one host's resolution. 8182's catch-all
route means it has no path without a route, so `GW.NO_ROUTE` comes from the scratch gateway too.

At the end: every code seen, and the codes of the catalogues no scenario reached (and why).
"""
import base64
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import error_parity

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
FLAGS = [a for a in sys.argv[1:] if a.startswith("--")]
BASE = ARGS[0] if ARGS else "http://localhost:8182"
KEEP = "--keep" in FLAGS
ONLY = next((f.split("=", 1)[1] for f in FLAGS if f.startswith("--only=")), None)
P = "/api/security"
PASSWORD = "Pass@1234"
SCRATCH = os.path.join(ROOT, "target", "scratch", "errors")


def env_file():
    """config/local.env as a dict (secrets stay in memory, never printed)."""
    out = {}
    with open(os.path.join(ROOT, "config", "local.env")) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    return out


ENV = env_file()


def sql(query):
    out = subprocess.run(["mysql", "-h127.0.0.1", "-uroot", "security", "-N", "-B", "-e", query],
                         env={**os.environ, "MYSQL_PWD": ENV["MODLIX__DATABASE__PASSWORD"]},
                         capture_output=True, text=True, check=True)
    return [line.split("\t") for line in out.stdout.splitlines() if line.strip()]


def basic(user, password=PASSWORD):
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def hdrs(client="SYSTEM", app="appbuilder", auth=None, extra=None):
    h = {"clientCode": client, "appCode": app}
    if auth:
        h["Authorization"] = auth
    h.update(extra or {})
    return h


SYS = hdrs(auth=basic(142))


def call(method, path, headers=None, body=None, raw=None, base=None, timeout=30):
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    req = urllib.request.Request((base or BASE) + path, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if data is not None and raw is None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def ok(method, path, headers, body=None):
    s, _, b = call(method, path, headers, body)
    if s != 200:
        raise SystemExit(f"setup call {method} {path} answered {s}: {b[:300]!r}")
    return json.loads(b) if b else None


# ---- scratch data, checked before every write ----

CREATED = {"client": [], "user": [], "access": [], "role": [], "designation": []}


def mine(kind, oid):
    assert int(oid) in CREATED[kind], f"{kind} {oid} was not created by this run"
    return int(oid)


def setup(run):
    ctx = {"run": run}
    for side in ("A", "B"):
        code = f"ZZER{side}{run}"
        assert not sql(f"select ID from security_client where CODE = '{code}'"), f"client {code} exists already"
        c = ok("POST", f"{P}/clients", SYS, {"code": code, "name": f"ZZ errors {side}", "typeCode": "BUS",
                                              "tokenValidityMinutes": 60, "localeCode": "en"})
        CREATED["client"].append(int(c["id"]))
        ok("POST", f"{P}/applications/2/access", SYS, {"clientId": c["id"], "writeAccess": False})
        CREATED["access"].append(int(sql(f"select ID from security_app_access where CLIENT_ID = {int(c['id'])} and APP_ID = 2")[0][0]))
        u = ok("POST", f"{P}/users", SYS, {"clientId": c["id"], "userName": f"zzer{side.lower()}{run}",
                                            "emailId": f"zzer{side.lower()}{run}@example.invalid", "firstName": "Scratch",
                                            "statusCode": "ACTIVE"})
        CREATED["user"].append(int(u["id"]))
        ok("POST", f"{P}/users/{mine('user', u['id'])}/updatePassword", SYS, {"newPassword": PASSWORD})
        ctx[side] = {"client": int(c["id"]), "code": code, "user": int(u["id"]), "name": f"zzer{side.lower()}{run}",
                     "email": f"zzer{side.lower()}{run}@example.invalid"}
    # A's user may create and edit users and read roles (SYSTEM's app-less roles), but manages
    # no other client: the management refusals need such a caller.
    for role in ("User CREATE", "User UPDATE", "User READ", "Role READ", "Client UPDATE"):
        rid = sql(f"select ID from security_v2_role where NAME = '{role}' and CLIENT_ID = 1 and APP_ID is null limit 1")
        if rid:
            s, _, b = call("GET", f"{P}/users/{mine('user', ctx['A']['user'])}/assignRole/{int(rid[0][0])}", SYS)
            print(f"  setup: role {role} for A's user: {s}")
    return ctx


def cleanup():
    for rid in CREATED["role"]:
        call("DELETE", f"{P}/rolev2/{mine('role', rid)}", SYS)
    for did in CREATED["designation"]:
        call("DELETE", f"{P}/designations/{mine('designation', did)}", SYS)
    for uid in CREATED["user"]:
        call("DELETE", f"{P}/users/{mine('user', uid)}", SYS)
    for aid in CREATED["access"]:
        call("DELETE", f"{P}/applications/2/access?accessId={mine('access', aid)}", SYS)
    for cid in CREATED["client"]:
        call("GET", f"{P}/clients/makeClientActive?clientId={mine('client', cid)}", SYS)
        call("DELETE", f"{P}/clients/{mine('client', cid)}", SYS)
    left = sql("select count(*) from security_client where STATUS_CODE <> 'DELETED' and ID in ("
               + ",".join(str(c) for c in CREATED["client"] or [0]) + ")")
    print(f"\ncleanup: {len(CREATED['user'])} users and {len(CREATED['client'])} clients marked DELETED, "
          f"{len(CREATED['role'])} roles and {len(CREATED['designation'])} designations deleted; "
          f"clients not deleted: {left[0][0]}")


# ---- reporting ----

SEEN = {}
ROWS = []


def scenario(expected, title, resp):
    if ONLY and ONLY not in title and ONLY not in expected:
        return None
    s, h, b = resp
    try:
        v = json.loads(b) if b else None
    except ValueError:
        v = None
    code = v.get("code") if isinstance(v, dict) else None
    verdict = "ok" if code == expected else "UNEXPECTED"
    ROWS.append((verdict, expected, code))
    if code:
        SEEN.setdefault(code, title)
    print(f"\n[{verdict}] {title}\n  {s} {code or '(no code)'}  expected {expected}")
    if isinstance(v, dict):
        print(f"  message: {v.get('message')}")
        if v.get("action"):
            print(f"  action:  {v.get('action')}")
        if v.get("params"):
            print(f"  params:  {json.dumps(v.get('params'))}")
        print(f"  locale:  {v.get('locale')}    debug: {str(v.get('debugMessage'))[:140]}")
    else:
        print(f"  body: {b[:200]!r}")
    return v


# ---- security ----

def security(ctx):
    A, B = ctx["A"], ctx["B"]
    member_a = hdrs(A["code"], auth=basic(A["user"]))
    anon = hdrs()

    print("\n==== Signing in and the caller's context ====")
    scenario("COMMON.SIGN_IN_REQUIRED", "users list without signing in", call("GET", f"{P}/users", anon))
    scenario("COMMON.SIGNED_OUT", "users list with a token that is no longer valid",
             call("GET", f"{P}/users", hdrs(auth="Bearer not-a-token")))
    scenario("COMMON.SIGNED_OUT", "users list in Portuguese (no pt texts yet: English)",
             call("GET", f"{P}/users", hdrs(auth="Bearer not-a-token", extra={"Accept-Language": "pt-BR,pt;q=0.9"})))
    scenario("SEC.UNKNOWN_CLIENT", "a clientCode that names no client", call("GET", f"{P}/users", hdrs("ZZNOPE")))
    scenario("SEC.SIGN_IN_FAILED", "sign-in with an unknown user name",
             call("POST", f"{P}/authenticate", anon, {"userName": f"zz-nobody-{ctx['run']}", "password": "x"}))
    scenario("SEC.SIGN_IN_SECRET_MISSING", "sign-in without a password",
             call("POST", f"{P}/authenticate", hdrs(A["code"]), {"userName": A["name"]}))
    scenario("COMMON.BODY_UNREADABLE", "sign-in with a body that is not JSON",
             call("POST", f"{P}/authenticate", {**anon, "Content-Type": "application/json"}, raw=b"{"))
    scenario("COMMON.BODY_MISSING", "sign-in without a body",
             call("POST", f"{P}/authenticate", {**anon, "Content-Type": "application/json"}, raw=b""))
    scenario("COMMON.PAYLOAD_TOO_LARGE", "sign-in with a 2 MB body",
             call("POST", f"{P}/authenticate", {**anon, "Content-Type": "application/json"}, raw=b" " * (2 << 20)))
    scenario("COMMON.METHOD_NOT_ALLOWED", "GET on the sign-in address", call("GET", f"{P}/authenticate", anon))
    scenario("SEC.TOKEN_FORBIDDEN", "verifyToken without a token", call("GET", f"{P}/verifyToken", anon))
    scenario("SEC.TOKEN_UNAUTHORIZED", "verifyToken with a junk token", call("GET", f"{P}/verifyToken", hdrs(auth="Bearer junk")))
    scenario("SEC.SOCIAL_LOGIN_FAILED", "social sign-in without its state", call("POST", f"{P}/authenticate/social", anon, {}))
    scenario("SEC.USER_CREDENTIALS_MISMATCHED", "an unknown one-time token",
             call("GET", f"{P}/authenticateWithOneTimeToken/zz-unknown-{ctx['run']}", anon))
    scenario("SEC.UNSUPPORTED_AUTH_MODE", "one-time token with a wrong auth mode",
             call("POST", f"{P}/makeOneTimeToken", SYS, {"callbackUrl": "http://localhost/x", "authMode": "PIGEON"}))
    scenario("SEC.SSO_TARGET_APP_FORBIDDEN", "one-time token for an app the scratch user cannot use",
             call("POST", f"{P}/makeOneTimeToken", member_a, {"callbackUrl": "http://localhost/x", "targetAppCode": "leadzump",
                                                             "targetClientCode": "SYSTEM"}))

    print("\n==== Wrong passwords (scratch user B only) ====")
    b_signin = hdrs(B["code"])
    # The policy allows three; Java (and so Rust) locks on the attempt after the one that reached
    # the limit, answering "blocked" once, then the lock with its minutes.
    for i, expected in enumerate(["SEC.USER_PASSWORD_INVALID_ATTEMPTS"] * 3 + ["SEC.USER_ACCOUNT_BLOCKED", "SEC.USER_ACCOUNT_BLOCKED_LIMIT"], 1):
        scenario(expected, f"wrong password #{i} for scratch user B",
                 call("POST", f"{P}/authenticate", b_signin, {"userName": B["name"], "password": f"wrong-{i}"}))
    call("POST", f"{P}/users/unblockUser?userId={mine('user', B['user'])}", SYS)

    print("\n==== Permissions ====")
    scenario("COMMON.PERMISSION_REQUIRED", "scratch user B lists clients (needs Client READ)",
             call("GET", f"{P}/clients", hdrs(B["code"], auth=basic(B["user"]))))
    scenario("COMMON.SIGN_IN_REQUIRED", "anonymous members list (an anonymous caller is only asked to sign in)",
             call("GET", f"{P}/users/members", anon))
    member_b = hdrs(B["code"], auth=basic(B["user"]))
    scenario("SEC.FORBIDDEN_PERMISSION", "scratch user B (no User READ) reads scratch user A's details",
             call("GET", f"{P}/users/{mine('user', A['user'])}", member_b))
    scenario("SEC.FORBIDDEN_CREATE", "scratch user A creates a user in client B (not managed by A)",
             call("POST", f"{P}/users", member_a, {"clientId": B["client"], "userName": f"zzerx{ctx['run']}",
                                                   "emailId": f"zzerx{ctx['run']}@example.invalid"}))
    scenario("SEC.ORG_ITEM_FORBIDDEN", "scratch user A adds a designation to client B",
             call("POST", f"{P}/designations", member_a, {"clientId": B["client"], "name": "ZZ"}))
    scenario("COMMON.PERMISSION_REQUIRED", "scratch user B adds a designation (needs Client CREATE or UPDATE)",
             call("POST", f"{P}/designations", member_b, {"clientId": B["client"], "name": "ZZ"}))
    scenario("SEC.HIERARCHY_ERROR", "scratch user A sets B's user's password",
             call("POST", f"{P}/users/{mine('user', B['user'])}/updatePassword", member_a, {"newPassword": "Pass@12345"}))
    rid = sql("select ID from security_v2_role where NAME = 'User READ' and CLIENT_ID = 1 and APP_ID is null limit 1")
    if rid:
        scenario("SEC.ROLE_FORBIDDEN_FOR_SELECTED_USER", "scratch user A gives B's user a role",
                 call("GET", f"{P}/users/{mine('user', B['user'])}/assignRole/{int(rid[0][0])}", member_a))
        scenario("SEC.ROLE_REMOVE_ERROR", "scratch user A removes a role from B's user",
                 call("GET", f"{P}/users/{mine('user', B['user'])}/removeRole/{int(rid[0][0])}", member_a))
    scenario("SEC.ACTIVE_INACTIVE_ERROR", "scratch user A deactivates B's user",
             call("PATCH", f"{P}/users/makeUserInActive?userId={mine('user', B['user'])}", member_a))
    scenario("SEC.BILLING_FORBIDDEN", "the generic billing config list", call("GET", f"{P}/billing-configs", SYS))
    scenario("SEC.BUNDLE_LIST_FORBIDDEN", "the generic billing bundle list", call("GET", f"{P}/billing-bundles", SYS))
    scenario("SEC.ONLY_SYS_USER_CERTS", "certificates read by a non-SYSTEM user",
             call("GET", f"{P}/ssl/internal/certificates?url=http://localhost", member_a))

    print("\n==== Input ====")
    scenario("COMMON.PARAM_INVALID", "a user id that is not a number", call("GET", f"{P}/users/abc", SYS))
    scenario("COMMON.PARAM_MISSING", "clients by ids without ids", call("GET", f"{P}/clients/internal", SYS))
    scenario("COMMON.PARAM_INVALID", "clients by ids as one comma list", call("GET", f"{P}/clients/internal?clientIds=1,28", SYS))
    scenario("COMMON.FIELD_INVALID", "a user whose clientId is not a number (nothing is created)",
             call("POST", f"{P}/users", SYS, {"clientId": "abc", "userName": "x"}))
    scenario("COMMON.BODY_INVALID", "sign-in whose rememberMe is a list",
             call("POST", f"{P}/authenticate", anon, {"userName": "x", "password": "y", "rememberMe": [1]}))
    scenario("SEC.MANDATORY_APP_CODE", "an app's URL without the app code",
             call("GET", f"{P}/clienturls/internal/applications/property/url?appCode=", SYS))
    scenario("SEC.OBJECT_NOT_FOUND", "a client that does not exist", call("GET", f"{P}/clients/999999999", SYS))
    scenario("SEC.CLIENT_HIERARCHY_MISSING", "the hierarchy of a client that does not exist",
             call("GET", f"{P}/clients/internal/clientHierarchy?clientId=999999999", SYS))
    scenario("SEC.FIELD_NOT_UPDATABLE", "PATCH a scratch client's status with a value it cannot take",
             call("PATCH", f"{P}/clients/{mine('client', A['client'])}", SYS, {"statusCode": "NOPE"}))
    scenario("SEC.APP_CODE_NO_SPL_CHAR", "an app code with special characters (nothing is created)",
             call("POST", f"{P}/applications", SYS, {"appName": "ZZ errors", "appCode": "zz-err!", "appType": "APP"}))
    scenario("SEC.MANDATORY_APP_ID_CODE", "app properties without the app's id or code",
             call("GET", f"{P}/applications/property?clientId={mine('client', A['client'])}", SYS))
    scenario("SEC.MANDATORY_APP_ID_NAME", "an app property without its name (nothing is written)",
             call("POST", f"{P}/applications/property", SYS, {"appId": 2, "clientId": A["client"]}))
    scenario("SEC.APP_DEPENDENCY_SAME_APP_CODE", "an app depending on itself (nothing is written)",
             call("POST", f"{P}/applications/dependency", SYS, {"appCode": "appbuilder", "dependentAppCode": "appbuilder"}))
    scenario("SEC.PROFILE_NEEDS_APP", "a profile without an app in client A (nothing is created)",
             call("POST", f"{P}/app/profiles", SYS, {"clientId": A["client"], "name": "ZZ errors"}))
    scenario("SEC.USER_IDENTIFICATION_NOT_FOUND", "a user without any identity in client A",
             call("POST", f"{P}/users", SYS, {"clientId": A["client"]}))
    scenario("COMMON.INTERNAL_ERROR", "a second user with A's user name in client A (Java's 500 on the unique key, kept)",
             call("POST", f"{P}/users", SYS, {"clientId": A["client"], "userName": A["name"], "emailId": A["email"]}))
    scenario("SEC.NAME_MANDATORY", "a designation without a name in client A",
             call("POST", f"{P}/designations", SYS, {"clientId": A["client"], "name": " "}))
    s, h, b = call("POST", f"{P}/designations", SYS, {"clientId": A["client"], "name": "ZZ errors"})
    if s == 200:
        CREATED["designation"].append(int(json.loads(b)["id"]))
    scenario("SEC.NAME_TAKEN", "the same designation name twice in client A",
             call("POST", f"{P}/designations", SYS, {"clientId": A["client"], "name": "ZZ errors"}))
    roles = []
    for n in ("one", "two"):
        s, h, b = call("POST", f"{P}/rolev2", SYS, {"clientId": A["client"], "name": f"ZZ errors {n} {ctx['run']}"})
        if s == 200:
            roles.append(int(json.loads(b)["id"]))
            CREATED["role"].append(roles[-1])
        else:
            print(f"  (scratch role not created: {s} {b[:160]!r})")
    if len(roles) == 2:
        r1, r2 = (mine("role", r) for r in roles)
        scenario("SEC.SUB_ROLE_SELF", "a scratch role under itself", call("POST", f"{P}/rolev2/{r1}/subRoles/{r1}", SYS))
        call("POST", f"{P}/rolev2/{r1}/subRoles/{r2}", SYS)
        scenario("SEC.SUB_ROLE_CYCLE", "two scratch roles under each other", call("POST", f"{P}/rolev2/{r2}/subRoles/{r1}", SYS))
        call("DELETE", f"{P}/rolev2/{r1}/subRoles/{r2}", SYS)
    s, h, b = call("POST", f"{P}/designations", SYS, {"clientId": B["client"], "name": "ZZ errors B"})
    if s == 200:
        dsg = int(json.loads(b)["id"])
        CREATED["designation"].append(dsg)
        scenario("SEC.USER_DESIGNATION_MISMATCH", "A's user given a designation of client B",
                 call("PUT", f"{P}/users/{mine('user', A['user'])}/designation/{mine('designation', dsg)}", SYS))
    scenario("SEC.USER_REPORTING_ERROR", "A's user reporting to themselves",
             call("PUT", f"{P}/users/{mine('user', A['user'])}/reportingManager/{mine('user', A['user'])}", SYS))

    print("\n==== Passwords (scratch user A) ====")
    pw = f"{P}/users/{mine('user', A['user'])}/updatePassword"
    scenario("SEC.NEW_PASSWORD_MISSING", "password change without a new password", call("POST", pw, SYS, {}))
    scenario("SEC.MIN_LENGTH_ERROR", "a password that is too short", call("POST", pw, SYS, {"newPassword": "S@1a"}))
    scenario("SEC.SPACES_MISSING", "a password with spaces", call("POST", pw, SYS, {"newPassword": "Pass 1234@"}))
    scenario("SEC.CAPITAL_LETTERS_MISSING", "a password without a capital letter", call("POST", pw, SYS, {"newPassword": "pass@1234"}))
    scenario("SEC.SMALL_LETTERS_MISSING", "a password without a small letter", call("POST", pw, SYS, {"newPassword": "PASS@1234"}))
    scenario("SEC.NUMBERS_MISSING", "a password without a number", call("POST", pw, SYS, {"newPassword": "Pass@word"}))
    scenario("SEC.SPECIAL_CHARACTERS_MISSING", "a password without a special character", call("POST", pw, SYS, {"newPassword": "Pass12345"}))
    scenario("SEC.PASSWORD_USED_ERROR", "the current password set again by SYSTEM", call("POST", pw, SYS, {"newPassword": PASSWORD}))
    scenario("SEC.PASS_RESET_REQ_ERROR", "a signed-in user asks for a password reset",
             call("POST", f"{P}/users/reset/password/otp/generate", member_a, {"userName": A["name"]}))
    scenario("SEC.OLD_PASSWORD_MATCH", "scratch user A changes their password with a wrong current one",
             call("POST", f"{P}/users/updatePassword", member_a, {"oldPassword": "not-it", "newPassword": "Pass@12345"}))
    scenario("SEC.NEW_PASSWORD_MATCH", "scratch user A sets the same password again",
             call("POST", f"{P}/users/updatePassword", member_a, {"oldPassword": PASSWORD, "newPassword": PASSWORD}))

    print("\n==== Accounts that are blocked or inactive (scratch users) ====")
    call("PATCH", f"{P}/users/makeUserInActive?userId={mine('user', B['user'])}", SYS)
    scenario("SEC.USER_ACCOUNT_BLOCKED", "an inactive scratch user signs in",
             call("POST", f"{P}/authenticate", b_signin, {"userName": B["name"], "password": PASSWORD}))
    call("PATCH", f"{P}/users/makeUserActive?userId={mine('user', B['user'])}", SYS)
    call("GET", f"{P}/clients/makeClientInActive?clientId={mine('client', B['client'])}", SYS)
    scenario("SEC.INACTIVE_CLIENT", "a user of an inactive scratch client signs in",
             call("POST", f"{P}/authenticate", b_signin, {"userName": B["name"], "password": PASSWORD}))
    call("GET", f"{P}/clients/makeClientActive?clientId={mine('client', B['client'])}", SYS)

    print("\n==== Server faults ====")
    scenario("COMMON.INTERNAL_ERROR", "social sign-in with a state nobody minted (Java's 500, kept)",
             call("POST", f"{P}/authenticate/social", hdrs(A["code"]),
                  {"socialRegisterState": f"zz-none-{ctx['run']}", "userName": A["email"]}))


# ---- gateway ----

class Stub(BaseHTTPRequestHandler):
    """The upstreams that misbehave: `/slow` waits, `/readyz` is healthy, security's host
    resolution fails for the host `broken.example`."""

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path.startswith("/api/security/clients/internal/getClientNAppCodeNType"):
            if "broken.example" in self.path:
                self.send_response(500)
                self.end_headers()
                return
            body = b'["SYSTEM","appbuilder","LIVE"]'
        elif self.path.startswith("/api/slow"):
            time.sleep(3)
            body = b"late"
        else:
            body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def dropper(port, stop):
    """Accepts and closes every connection without answering."""
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    srv.settimeout(0.2)
    while not stop.is_set():
        try:
            c, _ = srv.accept()
            c.recv(1024)
            c.close()
        except OSError:
            pass
    srv.close()


def gateway():
    print("\n==== Gateway (8182) ====")
    scenario("GW.SERVICE_STARTING", "a route whose service is not running (schedular)", call("GET", "/api/schedular/x", hdrs()))

    print("\n==== Gateway (scratch instance on 8199, stub upstreams) ====")
    os.makedirs(SCRATCH, exist_ok=True)
    stub_port, drop_port, closed_port = free_port(), free_port(), free_port()
    stub = ThreadingHTTPServer(("127.0.0.1", stub_port), Stub)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    stop = threading.Event()
    threading.Thread(target=dropper, args=(drop_port, stop), daemon=True).start()
    cfg = os.path.join(SCRATCH, "gateway-scenarios.toml")
    with open(cfg, "w") as f:
        f.write(f"""# Written by tools/error_scenarios.py; removed when it ends.
[server]
port = 8199
shutdown_grace_seconds = 0

[telemetry]
log_format = "pretty"
log_level = "warn"

[redis]
cache_prefix = "zzerrors"
eviction_channel = "zzerrorsChannel"

[security]
upstream = "http://127.0.0.1:{stub_port}"

[pools.slow]
upstreams = ["http://127.0.0.1:{stub_port}"]

[pools.closed]
upstreams = ["http://127.0.0.1:{closed_port}"]

[pools.drop]
upstreams = ["http://127.0.0.1:{drop_port}"]

[[routes]]
id = "slow"
prefix = "/api/slow"
pool = "slow"
timeout_seconds = 1

[[routes]]
id = "closed"
prefix = "/api/closed"
pool = "closed"

[[routes]]
id = "drop"
prefix = "/api/drop"
pool = "drop"

[[routes]]
id = "ok"
prefix = "/api/ok"
pool = "slow"
""")
    binary = os.path.join(ROOT, "target", "release", "gateway-rust")
    env = {k: v for k, v in os.environ.items() if not k.startswith("MODLIX__")}
    env.update({"CONFIG_FILE": cfg, "MODLIX__REDIS__URL": ENV.get("MODLIX__REDIS__URL", "")})
    log = open(os.path.join(SCRATCH, "gateway-scenarios.log"), "w")
    proc = subprocess.Popen([binary], env=env, stdout=log, stderr=log)
    gw = "http://127.0.0.1:8199"
    try:
        for _ in range(60):
            try:
                if call("GET", "/readyz", base=gw, timeout=2)[0] == 200:
                    break
            except OSError:
                time.sleep(0.25)
        h = {"Host": "ok.example"}
        scenario("GW.NO_ROUTE", "a path no route serves", call("GET", "/nowhere", h, base=gw))
        scenario("GW.HOST_UNRESOLVED", "a host security cannot resolve", call("GET", "/api/ok/x", {"Host": "broken.example"}, base=gw))
        scenario("GW.SERVICE_UNAVAILABLE", "every instance refuses the connection", call("GET", "/api/closed/x", h, base=gw))
        scenario("GW.SERVICE_TIMEOUT", "the service answers after the route's timeout", call("GET", "/api/slow/x", h, base=gw))
        scenario("GW.SERVICE_FAILED", "the service drops the connection", call("GET", "/api/drop/x", h, base=gw))
        scenario("GW.SERVICE_TIMEOUT", "the same, in Portuguese (English until pt texts exist)",
                 call("GET", "/api/slow/x", {**h, "Accept-Language": "pt-BR"}, base=gw))
    finally:
        proc.terminate()
        proc.wait(timeout=10)
        stop.set()
        stub.shutdown()
        log.close()
        os.remove(cfg)


NOT_REACHED = {
    "certificates": "certificate issuing needs Let's Encrypt and real domains",
    "registration": "sign-up and social flows need an app with registration set up and an OTP or social provider",
    "sms": "sending an SMS needs the SMS provider",
    "invites": "invitation and access-request flows need an app with profiles set up for them",
    "java-only": "Java bundle keys the Rust units never raise",
}


def main():
    run = str(int(time.time()))[-6:]
    s, _, _ = call("GET", "/readyz")
    if s != 200:
        raise SystemExit(f"{BASE} is not ready ({s})")
    ctx = None
    try:
        print(f"Scratch run {run} through {BASE}")
        ctx = setup(run)
        security(ctx)
        gateway()
    finally:
        if KEEP:
            print(f"\n--keep: scratch data left: {json.dumps(CREATED)}")
        else:
            cleanup()
    unexpected = [r for r in ROWS if r[0] != "ok"]
    print(f"\n{len(ROWS)} scenarios, {len(ROWS) - len(unexpected)} as expected, {len(unexpected)} unexpected")
    codes = sorted(c for c in error_parity.CATALOGUE if c.split(".")[0] in ("COMMON", "SEC", "GW"))
    reached = [c for c in codes if c in SEEN]
    print(f"codes reached: {len(reached)} of {len(codes)} (COMMON, SEC, GW)")
    missing = [c for c in codes if c not in SEEN]
    by_reason = {}
    for c in missing:
        when = (error_parity.CATALOGUE[c].get("when") or "")
        reason = ("java-only" if "Not raised by the Rust units" in when else
                  "certificates" if any(w in when.lower() for w in ("certificate", "acme")) else
                  "sms" if "SMS" in when else
                  "registration" if any(w in when.lower() for w in ("regist", "sign-up", "social")) else
                  "invites" if any(w in when.lower() for w in ("invit", "access request")) else "other")
        by_reason.setdefault(reason, []).append(c)
    for reason, cs in sorted(by_reason.items()):
        print(f"  not reached ({NOT_REACHED.get(reason, 'no scenario yet')}): {', '.join(cs)}")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
