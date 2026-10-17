#!/usr/bin/env python3
"""Sends the same requests to the Java security service and to security-admin (piece 2: clients,
apps and hosting) and compares them.

Usage: parity_security_admin_clients.py [java_base] [rust_base] [--reads-only]
       defaults: http://localhost:8001  http://localhost:8113

Local stack only. Requests to Java go one at a time with a pause between them.

Callers: the SYSTEM user 142 (`clientCode: SYSTEM`), user 110 (an Owner of client FIN), user 8
(FIN, signed in with no authority) and anonymous callers; Basic `<id>:Pass@1234`, the users'
stored plain local password, so no attempt can be wrong.

Reads come from the local `security` schema. Writes touch only scratch objects each side creates
for itself and removes again: an app per side (`zzparityjava` / `zzparityrust`, with their draft
URL, a property, an access row, a dependency, a PIN policy, a client URL, a registration file
access and an integration), and a client per side (`ZZPJAV` / `ZZPRUS`), which the API can only
mark DELETED, so later runs bring the same two back. Nothing contacts Let's Encrypt or Cloudflare:
the SSL cases are the ones that answer before any authority call, and the renewal sweep is never
sent to Java (it would renew the local certificates for real).

Sign-ups: Java gets only what it refuses before writing anything (and no OTP is generated on an
app that verifies). The sign-up that succeeds runs on Rust alone, on Rust's scratch app, with a
fresh `zz.regb.parity.<tag>@example.com`; its client and user are marked DELETED through Rust's
routes, and reported as RUST-ONLY checks.

Compared: status, content type, and the body as JSON (`exceptionId`, `stackTrace` and the id in
`message` ignored; the scratch objects' ids, timestamps, codes and random hostnames masked).
Differences listed in crates/security/DIFFERENCES.md (piece 2) are reported as EXPECTED.
"""
import base64
import fcntl
import json
import os
import random
import re
import string
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import error_parity
import page_order  # a page's own key order changes with each load of Java's classes


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
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8113"
READS_ONLY = "--reads-only" in sys.argv
# Only the sign-up cases, on scratch apps made and removed for them (far fewer calls to Java).
REGISTRATION_ONLY = "--registration" in sys.argv
P = "/api/security"
PASSWORD = "Pass@1234"
RESULTS = {"SAME": 0, "EXPECTED": 0, "DIFF": 0, "RUST": 0}
# Per run, for the sign-up identities (never an existing one).
TAG = "".join(random.choice(string.ascii_lowercase) for _ in range(8))
MASKS = []  # (regex, replacement) applied to both sides' bodies


def sql(query):
    out = subprocess.run(["mysql", "-h127.0.0.1", "-uroot", "security", "-N", "-B", "-e", query], env=MYSQL_ENV,
                         capture_output=True, text=True, check=True)
    return [line.split("\t") for line in out.stdout.splitlines() if line.strip()]


def threads_connected():
    return int(sql("show status like 'Threads_connected'")[0][1])


def headers(user=None, client="SYSTEM", app="appbuilder", extra=None):
    h = {}
    if client is not None:
        h["clientCode"] = client
    if app is not None:
        h["appCode"] = app
    if user is not None:
        h["Authorization"] = "Basic " + base64.b64encode(f"{user}:{PASSWORD}".encode()).decode()
    h.update(extra or {})
    return h


SYS = headers(142)
OWNER = headers(110, "FIN")
PLAIN = headers(8, "FIN")
ANON = headers(None)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is a result here: it is compared, never followed (it may point at a provider)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def call(base, method, path, hdrs, body=None):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(base + P + path, data=data, method=method)
    for k, v in hdrs.items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with OPENER.open(req, timeout=60) as r:
            return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()
    except Exception as e:  # a hung or refused call is a result too
        return 0, {}, str(e).encode()


def parse(raw):
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return raw.decode(errors="replace")


def normal(v):
    if isinstance(v, dict) and "exceptionId" in v:
        v = dict(v)
        v.pop("exceptionId", None)
        v.pop("stackTrace", None)
        if isinstance(v.get("message"), str):
            v["message"] = re.sub(r"\d{4}-\d\d-\d\d-[0-9a-f]+", "<id>", v["message"])
    return mask(v)


def mask(v, key=None):
    """The scratch objects' ids, codes, hosts and times, masked so both sides compare."""
    if isinstance(v, dict):
        return {k: mask(x, k) for k, x in v.items()}
    if isinstance(v, list):
        return [mask(x) for x in v]
    if key in TIME_KEYS and isinstance(v, int):
        return 0
    if key == "id" and NEW_IDS[0] and isinstance(v, int):
        return "<new id>"
    if isinstance(v, int) and not isinstance(v, bool) and v in IDS:
        return "<id>"
    if isinstance(v, str):
        for rx, rep in MASKS:
            v = re.sub(rx, rep, v)
    return v


TIME_KEYS = {"createdAt", "updatedAt", "expiresAt", "lastValidatedAt"}
# Set while comparing what each side just created: the ids differ by construction.
NEW_IDS = [False]
IDS = set()


def report(name, verdict, detail=""):
    RESULTS[verdict] += 1
    print(f"{verdict:8} {name}{(': ' + detail) if detail else ''}", flush=True)


def diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        if list(a) != list(b) and set(a) == set(b):
            return f"{path}: key order {list(a)} vs {list(b)}"
        for k in sorted(set(a) | set(b)):
            if a.get(k) != b.get(k):
                return diff(a.get(k), b.get(k), f"{path}.{k}")
        return path
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return diff(x, y, f"{path}[{i}]")
    return f"{path}: {json.dumps(a)[:200]} vs {json.dumps(b)[:200]}"


USER_FILLS = ("profiles", "client", "managingClient", "createdByUser", "designation", "reportingTo")
CLIENT_FILLS = ("owners", "apps", "managagingClient", "createdByUser", "clientManagers")
CLIENT_COUNTS = ("activeUsers", "inactiveUsers", "deletedUsers", "lockedUsers", "passwordExpiredUsers", "totalUsers")
LEAKED = "Java cached objects keep earlier fills"


def strip_leaks(page):
    """A page's NESTED users and clients without the fills: Java's `readById(id, queryParams)`
    fills the cached object in place, so a user or client a page nests (an owner, the creator,
    the managing client) carries whatever an earlier request asked for. Only the page's own rows
    are filled by this request."""
    if not isinstance(page, dict) or not isinstance(page.get("content"), list):
        return page

    def user(u):
        return {k: v for k, v in u.items() if k not in USER_FILLS} if isinstance(u, dict) else u

    def client(c):
        if not isinstance(c, dict):
            return c
        c = {k: v for k, v in c.items() if k not in CLIENT_FILLS}
        return {k: (0 if k in CLIENT_COUNTS else v) for k, v in c.items()}

    rows = []
    for row in page["content"]:
        if isinstance(row, dict):
            row = dict(row)
            for k in ("owners", "clientManagers"):
                if isinstance(row.get(k), list):
                    row[k] = [user(u) for u in row[k]]
            if "createdByUser" in row:
                row["createdByUser"] = user(row["createdByUser"])
            if "managagingClient" in row:
                row["managagingClient"] = client(row["managagingClient"])
        rows.append(row)
    return {**page, "content": rows}


class JavaDown(Exception):
    """Java security stopped answering: the run stops there, without retrying."""


def break_ties(page, key="updatedAt"):
    """A page's rows with each run of equal `key` values put in id order. The default sort
    (`Query.DEFAULT_SORT`, `updatedAt` descending) says nothing about ties, so MySQL orders them
    by whatever its plan does, and Java's SELECT and Rust's differ in their columns: two scratch
    clients written in the same second came back in either order. Runs stay where they are, so
    a wrong order by `key` itself still shows."""
    if not isinstance(page, dict) or not isinstance(page.get("content"), list):
        return page
    rows, out = page["content"], []
    i = 0
    while i < len(rows):
        j = i + 1
        k = rows[i].get(key) if isinstance(rows[i], dict) else None
        while k is not None and j < len(rows) and isinstance(rows[j], dict) and rows[j].get(key) == k:
            j += 1
        out.extend(sorted(rows[i:j], key=lambda r: r.get("id", 0) if isinstance(r, dict) else 0))
        i = j
    return {**page, "content": out}


def compare(name, method, path, hdrs, body=None, expected=None, rust_path=None, rust_body=None, rust_hdrs=None, header_keys=(), leaks=False,
            ties=False):
    """Same request to both; `expected` names the DIFFERENCES.md entry that explains a difference.
    With `leaks`, a difference only in the nested objects' fills is that entry. With `ties`, rows
    the default sort leaves tied are compared in id order."""
    js, jh, jb = call(JAVA, method, path, hdrs, body)
    if js == 0:
        raise JavaDown(f"{name}: {jb.decode(errors='replace')}")
    time.sleep(0.25)
    rs, rh, rb = call(RUST, method, rust_path or path, rust_hdrs or hdrs, rust_body if rust_body is not None else body)
    (rs, rh, rb), coded = error_parity.decode((js, jh, jb), (rs, rh, rb))
    jp, rp = parse(jb), parse(rb)
    if ties:
        jp, rp = break_ties(jp), break_ties(rp)
    jv, rv = normal(jp), normal(rp)
    jv, rv, reordered = page_order.align(jv, rv)
    if reordered and not expected:
        expected, expected_page = page_order.NOTE, True
    else:
        expected_page = False
    if leaks and jv != rv and strip_leaks(jv) == strip_leaks(rv):
        jv, rv, expected = strip_leaks(jv), strip_leaks(rv), LEAKED
        expected_raw = True
    else:
        expected_raw = False
    jct, rct = jh.get("content-type"), rh.get("content-type")
    problems = []
    if js != rs:
        problems.append(f"status {js} vs {rs}")
    if jct != rct:
        problems.append(f"content-type {jct} vs {rct}")
    for k in header_keys:
        jk, rk = mask(jh.get(k)), mask(rh.get(k))
        if jk != rk:
            problems.append(f"{k} {jk} vs {rk}")
    if jv != rv or (isinstance(jv, dict) and isinstance(rv, dict) and list(jv) != list(rv)):
        problems.append(diff(jv, rv))
    if error_parity.is_problem(coded) and not expected:
        report(name, "DIFF", error_parity.detail(coded, "; ".join(problems))[:600])
    elif not problems and expected_raw:
        report(name, "EXPECTED", LEAKED)
    elif not problems and expected_page:
        report(name, "EXPECTED", error_parity.detail(coded, page_order.NOTE))
    elif not problems:
        v = error_parity.verdict("SAME", coded)
        report(name, v, error_parity.detail(coded) if v != "SAME" else "")
    elif expected:
        report(name, "EXPECTED", f"{expected} ({'; '.join(problems)[:200]})")
    else:
        report(name, "DIFF", "; ".join(problems)[:600])
    return (js, parse(jb)), (rs, parse(rb))


def q(params):
    return "?" + urllib.parse.urlencode(params, doseq=True)


# ------------------------------------------------------------------ reads

def reads():
    url_with_cert = sql("select URL_ID from security_ssl_certificate where CURRENT = 1 order by ID desc limit 1")[0][0]
    token = sql("select TOKEN from security_ssl_challenge order by ID desc limit 1")[0][0]
    policy_ids = {t: [r[0] for r in sql(f"select ID from security_client_{t}_policy order by ID limit 2")] for t in ("otp", "password", "pin")}
    url_ids = [r[0] for r in sql("select ID from security_client_url where URL_TYPE = 'LIVE' order by ID desc limit 2")]

    for who, h in (("system", SYS), ("owner", OWNER)):
        for base, t in (("clientOtpPolicy", "otp"), ("clientPasswordPolicy", "password"), ("clientPinPolicy", "pin")):
            compare(f"{who} {base} page", "GET", f"/{base}" + q({"size": 3}), h)
            compare(f"{who} {base} query", "POST", f"/{base}/query", h, {"size": 2, "sort": [{"property": "id", "direction": "DESC"}]})
            for pid in policy_ids[t] + ["999999", "x"]:
                compare(f"{who} {base}/{pid}", "GET", f"/{base}/{pid}", h)
        for c in ("1", "28", "4452"):
            compare(f"{who} client-activities {c}", "GET", f"/client-activities/{c}" + q({"size": 2}), h)
            compare(f"{who} client-activities {c} query", "POST", f"/client-activities/{c}/query", h,
                    {"size": 2, "sort": [{"property": "id", "direction": "DESC"}]})
        compare(f"{who} client-activities bad", "POST", "/client-activities", h, {"activityName": " "})
        compare(f"{who} clients page", "GET", "/clients" + q({"size": 2, "sort": "id,desc"}), h)
        compare(f"{who} clients page fills", "GET", "/clients" + q({"size": 2, "fetchUserCounts": "true", "fetchOwners": "true",
                                                                 "fetchApps": "true", "fetchCreatedByUser": "true"}), h, leaks=True)
        compare(f"{who} clients query", "POST", "/clients/query" + q({"fetchManagingClient": "true"}), h,
                {"size": 3, "condition": {"field": "typeCode", "value": "BUS"}}, leaks=True, ties=True)
        compare(f"{who} clients query, sort with a tie-break", "POST", "/clients/query", h,
                {"size": 3, "condition": {"field": "typeCode", "value": "BUS"},
                 "sort": [{"property": "updatedAt", "direction": "DESC"}, {"property": "id", "direction": "ASC"}]})
        for c in ("1", "28", "999999", "x"):
            compare(f"{who} clients/{c}", "GET", f"/clients/{c}", h)
        compare(f"{who} clients noMapping", "POST", "/clients/noMapping", h, {})
        compare(f"{who} makeClientActive bad", "GET", "/clients/makeClientActive" + q({"clientId": "x"}), h)
        compare(f"{who} clienturls page", "GET", "/clienturls" + q({"size": 3}), h)
        compare(f"{who} clienturls query", "POST", "/clienturls/query", h, {"size": 2, "condition": {"field": "appCode", "value": "leadzump"}})
        for u in url_ids + ["999999"]:
            compare(f"{who} clienturls/{u}", "GET", f"/clienturls/{u}", h)
        for app in ("appbuilder", "leadzump", "nope"):
            compare(f"{who} fetchUrls {app}", "GET", "/clienturls/fetchUrls" + q({"appCode": app, "suffix": "/x"}), h)
            compare(f"{who} urls {app}", "GET", "/clienturls/urls" + q({"appCode": app, "size": 3}), h)
            compare(f"{who} draft {app}", "GET", "/clienturls/draft" + q({"appCode": app}), h)
            compare(f"{who} appCode/{app}", "GET", f"/applications/appCode/{app}", h)
            compare(f"{who} app clients {app}", "GET", f"/applications/clients/{app}" + q({"onlyWriteAccess": "false", "size": 2}), h)
            compare(f"{who} findBaseClientCode {app}", "GET", f"/applications/findBaseClientCode/{app}", h)
            compare(f"{who} property {app}", "GET", "/applications/property" + q({"appCode": app}), h)
            compare(f"{who} property {app} client 1", "GET", "/applications/property" + q({"appCode": app, "clientId": 1}), h)
            compare(f"{who} dependencies {app}", "GET", "/applications/dependencies" + q({"appCode": app}), h)
            for part in ("appAccess", "fileAccess", "userRole", "nope"):
                compare(f"{who} reg {app} {part}", "POST", f"/applications/reg/{app}/{part}/query", h, {"page": 0, "size": 2})
        compare(f"{who} urls unmanaged client", "GET", "/clienturls/urls" + q({"appCode": "appbuilder", "clientCode": "NOPE"}), h)
        compare(f"{who} apps page", "GET", "/applications" + q({"size": 3}), h)
        compare(f"{who} apps query", "POST", "/applications/query", h, {"size": 3, "sort": [{"property": "appCode"}]})
        compare(f"{who} apps accessible", "POST", "/applications/accessible/query", h, {"size": 3})
        compare(f"{who} apps/2", "GET", "/applications/2", h)
        compare(f"{who} apps/999999", "GET", "/applications/999999", h)
        compare(f"{who} app clients no flag", "GET", "/applications/clients/appbuilder", h)
        compare(f"{who} clientHasReadAccess", "GET", "/applications/clientHasReadAccess?appCodes=appbuilder,leadzump&appCodes=x", h)
        compare(f"{who} clientHasReadAccess split", "GET", "/applications/clientHasReadAccess?appCodes=appbuilder,%20leadzump,nope", h)
        compare(f"{who} findAnyApps", "GET", "/applications/findAnyApps" + q({"size": 2}), h)
        compare(f"{who} hasDeleteAccess", "GET", "/applications/hasDeleteAccess" + q({"deleteAppCode": "appbuilder", "deleteClientCode": "FIN"}), h)
        compare(f"{who} property missing", "GET", "/applications/property", h)
        compare(f"{who} reg no page", "POST", "/applications/reg/cxapp/appAccess/query", h, {"size": 2})
        compare(f"{who} reg code and id", "POST", "/applications/reg/cxapp/appAccess/query", h, {"page": 0, "size": 2, "clientCode": "A", "clientId": 1})
        compare(f"{who} appRegIntegration page", "GET", "/appRegIntegration" + q({"size": 2}), h)
        compare(f"{who} appRegIntegration query", "POST", "/appRegIntegration/query", h, {"size": 2})
        compare(f"{who} appRegIntegration/999999", "GET", "/appRegIntegration/999999", h)
        compare(f"{who} makeTransport", "GET", "/transports/makeTransport" + q({"applicationCode": "appbuilder"}), h)
        compare(f"{who} createAndApply", "POST", "/transports/createAndApply", h, {})
        compare(f"{who} ssl page", "GET", "/ssl" + q({"urlId": url_with_cert, "size": 2}), h)
        compare(f"{who} ssl page no url", "GET", "/ssl", h)
        compare(f"{who} ssl page bad url", "GET", "/ssl?urlId=x", h)
        compare(f"{who} ssl query", "POST", "/ssl/query", h, {"size": 2, "condition": {"field": "urlId", "value": int(url_with_cert)}})
        compare(f"{who} ssl query no condition", "POST", "/ssl/query", h, {"size": 2})
        compare(f"{who} ssl request", "GET", "/ssl/request" + q({"urlId": url_with_cert}), h)
        compare(f"{who} ssl request missing url", "GET", "/ssl/request" + q({"urlId": 999999}), h)
        compare(f"{who} ssl certificate missing request", "GET", "/ssl/certificate" + q({"requestId": 999999}), h)
        compare(f"{who} ssl trigger missing challenge", "GET", "/ssl/request/challenge" + q({"challengeId": 999999}), h)
        compare(f"{who} ssl delete bad id", "DELETE", "/ssl/x", h)
        compare(f"{who} ssl delete missing", "DELETE", "/ssl/999999", h)
        compare(f"{who} ssl delete request missing url", "DELETE", "/ssl/request" + q({"urlId": 999999}), h)
        compare(f"{who} ssl create bad", "POST", "/ssl", h, {"domainNames": [], "urlId": 1})
        compare(f"{who} ssl create no domains", "POST", "/ssl", h, {"urlId": 1})
        compare(f"{who} ssl create existing", "POST", "/ssl", h, {"domainNames": ["x.com"], "urlId": int(url_with_cert)})
        compare(f"{who} ssl external no key", "POST", "/ssl/external", h, {"urlId": 1})
        compare(f"{who} ssl external bad crt", "POST", "/ssl/external", h, {"urlId": 1, "crtKeyUpload": "k", "crt": "garbage"},
                expected="ssl external debugMessage")
    for h, who in ((SYS, "system"), (ANON, "anonymous")):
        compare(f"{who} ssl token", "GET", f"/ssl/token/{token}", h)
        compare(f"{who} ssl token unknown", "GET", "/ssl/token/nope", h)
    compare("plain renew-certificates", "POST", "/ssl/internal/renew-certificates", PLAIN)

    # Spring Security and @PreAuthorize.
    for path in ("/applications?size=1", "/applications/2", "/clients?size=1", "/clients/28", "/clienturls?size=1",
                 "/clientPinPolicy/1", "/clients/makeClientActive", "/appRegIntegration?size=1", f"/ssl?urlId={url_with_cert}"):
        compare(f"plain {path}", "GET", path, PLAIN)
        compare(f"anonymous {path}", "GET", path, ANON)
    for path, body in (("/applications", {"appCode": "a-1"}), ("/clientOtpPolicy", {"appId": 999999999}),
                       ("/clienturls", {"urlPattern": "x.example.test"}), ("/clients", {"name": "x"}),
                       ("/appRegIntegration", {"platform": "GOOGLE"})):
        compare(f"plain POST {path}", "POST", path, PLAIN, body,
                expected="POST clients enforces Client_CREATE" if path == "/clients" else None)
    for policy in ("clientOtpPolicy", "clientPasswordPolicy", "clientPinPolicy"):
        compare(f"anonymous {policy} codes", "GET", f"/{policy}/codes/policy", ANON)
        compare(f"anonymous {policy} codes leadzump", "GET", f"/{policy}/codes/policy", headers(None, "SYSTEM", "leadzump"))
        compare(f"anonymous {policy} codes unknown app", "GET", f"/{policy}/codes/policy", headers(None, "SYSTEM", "nope"))
        compare(f"anonymous {policy} codes no app", "GET", f"/{policy}/codes/policy", headers(None, "SYSTEM", None))
    compare("anonymous applyAppCodeSuffix", "GET", "/applications/applyAppCodeSuffix" + q({"appCode": "abc"}), ANON,
            header_keys=("etag", "cache-control", "x-frame-options"))
    compare("anonymous applyAppCodePrefix", "GET", "/applications/applyAppCodePrefix" + q({"appCode": "abc"}), ANON,
            header_keys=("etag", "cache-control"))
    compare("anonymous dependencies", "GET", "/applications/dependencies" + q({"appCode": "leadzump"}), ANON)
    compare("anonymous callback", "GET", "/clients/socialRegister/callback", ANON)
    compare("anonymous callback unknown state", "GET", "/clients/socialRegister/callback" + q({"code": "x", "state": "nope"}), ANON)
    compare("anonymous evoke no integration", "GET", "/clients/socialRegister/evoke" + q({"platform": "GOOGLE"}), ANON)
    compare("anonymous evoke post no integration", "POST", "/clients/socialRegister/evoke" + q({"platform": "META"}), ANON)
    compare("anonymous evoke bad platform", "GET", "/clients/socialRegister/evoke" + q({"platform": "NOPE"}), ANON)
    registration_refusals()


def reg_type_on(app_code):
    """The REGISTRATION_TYPE property of SYSTEM on the app, read from the database."""
    r = sql(f"select p.VALUE from security_app_property p join security_app a on a.ID = p.APP_ID "
            f"where a.APP_CODE = '{app_code}' and p.CLIENT_ID = 1 and p.NAME = 'REGISTRATION_TYPE'")
    return r[0][0] if r else None


def registration_refusals():
    """Sign-ups Java refuses before it writes anything. appbuilder verifies its sign-ups by OTP, so
    an anonymous registration there stops at the OTP check at the latest (no OTP is ever sent:
    nothing here calls otp/generate on an app that verifies); checked first, and skipped if not."""
    email = f"zz.reg.parity.{TAG}@example.com"
    compare("register, no pass type", "POST", "/clients/register", ANON, {})
    compare("register, signed in, no pass type", "POST", "/clients/register", SYS, {})
    compare("register, unknown pass type", "POST", "/clients/register", ANON, {"passType": "NOPE"})
    compare("register, not an object", "POST", "/clients/register", ANON, [1])
    compare("register, no body and no content type", "POST", "/clients/register", ANON)
    compare("register, weak password", "POST", "/clients/register", ANON, {"passType": "PASSWORD", "password": "weak", "emailId": email})
    compare("otp verify, no pass type", "POST", "/clients/register/otp/verify", ANON, {})
    compare("otp verify, signed in", "POST", "/clients/register/otp/verify", SYS, {"emailId": email, "passType": "OTP"})
    if reg_type_on("appbuilder") == "REGISTRATION_TYPE_VERIFICATION":
        compare("register, OTP not given", "POST", "/clients/register", ANON, {"passType": "OTP", "emailId": email, "firstName": "ZZ"})
        compare("otp verify, wrong OTP", "POST", "/clients/register/otp/verify", ANON, {"passType": "OTP", "emailId": email, "otp": "0000"})
    else:
        report("register on appbuilder", "DIFF", "appbuilder does not verify sign-ups here; not sent")
    compare("socialRegister, no state", "POST", "/clients/socialRegister", ANON, {})
    compare("socialRegister, unknown state", "POST", "/clients/socialRegister", ANON, {"socialRegisterState": f"zz-no-state-{TAG}"})
    compare("register events, no user", "GET", "/clients/register/events", ANON, {})
    compare("register events, no content type", "GET", "/clients/register/events", ANON)
    compare("appRegister, anonymous", "POST", "/clients/appRegister", ANON)
    compare("appRegister, no parameters", "POST", "/clients/appRegister", SYS)
    compare("appRegister, not a number", "POST", "/clients/appRegister" + q({"appCode": "x", "clientId": "x", "userId": "1"}), SYS)


# ------------------------------------------------------------------ writes on scratch objects

APP = {"java": "zzparityjava", "rust": "zzparityrust"}
CLIENT = {"java": "ZZPJAV", "rust": "ZZPRUS"}


def app_id(code):
    r = sql(f"select ID from security_app where APP_CODE = '{code}'")
    return int(r[0][0]) if r else None


def cleanup_app(base, code):
    """Removes a scratch app left by an earlier run, through the APIs."""
    aid = app_id(code)
    if aid is None:
        return
    for t in ("otp", "password", "pin"):
        for (pid,) in sql(f"select ID from security_client_{t}_policy where APP_ID = {aid}"):
            name = {"otp": "clientOtpPolicy", "password": "clientPasswordPolicy", "pin": "clientPinPolicy"}[t]
            call(base, "DELETE", f"/{name}/{pid}", SYS)
            time.sleep(0.25)
    for (iid,) in sql(f"select ID from security_app_reg_integration where APP_ID = {aid}"):
        call(base, "DELETE", f"/appRegIntegration/{iid}", SYS)
        time.sleep(0.25)
    for table, part in (("security_app_reg_file_access", "fileAccess"), ("security_app_reg_access", "appAccess")):
        for (rid,) in sql(f"select ID from {table} where APP_ID = {aid}"):
            call(base, "DELETE", f"/applications/reg/{part}/{rid}", SYS)
            time.sleep(0.25)
    call(base, "DELETE", f"/applications/everything/{aid}" + q({"forceDelete": "true"}), SYS)
    time.sleep(0.25)


def masks_for(java_ids, rust_ids):
    MASKS.clear()
    IDS.clear()
    for side in ("java", "rust"):
        MASKS.append((APP[side], "<app>"))
        MASKS.append((CLIENT[side], "<client>"))
        MASKS.append((f"zzparity-{side}", "<host>"))
    for j, r in zip(java_ids, rust_ids):
        if j is not None and r is not None:
            IDS.update({j, r})
            MASKS.append((rf"\b{j}\b", "<id>"))
            MASKS.append((rf"\b{r}\b", "<id>"))
    MASKS.append((r"d[0-9a-f]{32}(\.local)?\.modlix\.com", "<draft>"))
    MASKS.append((r"t-[0-9a-f]{32}(\.local)?\.modlix\.com", "<draft-token-host>"))
    MASKS.append((r"^[0-9a-f]{32}$", "<token>"))
    MASKS.append((r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[0-9a-f]{4}-[0-9a-f]{12}", "<uuid>"))


def both(name, method, java_path, rust_path, body_java=None, body_rust=None, hdrs=SYS, hdrs_rust=None, expected=None, new=False, header_keys=()):
    NEW_IDS[0] = new
    try:
        return compare(name, method, java_path, hdrs, body_java, rust_path=rust_path, rust_body=body_rust, rust_hdrs=hdrs_rust, expected=expected,
                       header_keys=header_keys)
    finally:
        NEW_IDS[0] = False


def writes():
    for side, base in (("java", JAVA), ("rust", RUST)):
        cleanup_app(base, APP[side])

    # ---- apps ----
    body = {s: {"appName": "ZZ Parity", "appCode": APP[s], "appType": "APP", "appUsageType": "B2C"} for s in APP}
    masks_for([], [])
    (_, ja), (_, ra) = both("app create", "POST", "/applications", "/applications", body["java"], body["rust"], new=True)
    jid, rid = app_id(APP["java"]), app_id(APP["rust"])
    if jid is None or rid is None:
        report("app create left no app", "DIFF", f"{jid} {rid}")
        return
    masks_for([jid], [rid])
    both("app read", "GET", f"/applications/{jid}", f"/applications/{rid}")
    both("app draft url", "GET", "/clienturls/draft" + q({"appCode": APP["java"]}), "/clienturls/draft" + q({"appCode": APP["rust"]}), new=True)
    both("app put", "PUT", f"/applications/{jid}", f"/applications/{rid}",
         {"appName": "ZZ Parity 2", "appAccessType": "ANY", "appUsageType": "B2B", "status": "ACTIVE"},
         {"appName": "ZZ Parity 2", "appAccessType": "ANY", "appUsageType": "B2B", "status": "ACTIVE"})
    both("app patch", "PATCH", f"/applications/{jid}", f"/applications/{rid}", {"thumbUrl": "x.png", "id": 1}, {"thumbUrl": "x.png", "id": 1})
    both("app patch bad enum", "PATCH", f"/applications/{jid}", f"/applications/{rid}", {"appType": "NOPE"}, {"appType": "NOPE"})

    # properties
    both("property set", "POST", "/applications/property", "/applications/property",
         {"appId": jid, "clientId": 1, "name": "ZZP", "value": "v1"}, {"appId": rid, "clientId": 1, "name": "ZZP", "value": "v1"})
    both("property set missing", "POST", "/applications/property", "/applications/property", {"appId": jid}, {"appId": rid})
    both("property read", "GET", "/applications/property" + q({"appCode": APP["java"]}), "/applications/property" + q({"appCode": APP["rust"]}), new=True)
    both("property delete", "DELETE", "/applications/property" + q({"clientId": 1, "appId": jid, "name": "ZZP"}),
         "/applications/property" + q({"clientId": 1, "appId": rid, "name": "ZZP"}))

    # access
    both("access add", "POST", f"/applications/{jid}/access", f"/applications/{rid}/access", {"clientId": 28, "writeAccess": False},
         {"clientId": 28, "writeAccess": False})
    ja_id = sql(f"select ID from security_app_access where APP_ID = {jid} and CLIENT_ID = 28")
    ra_id = sql(f"select ID from security_app_access where APP_ID = {rid} and CLIENT_ID = 28")
    if ja_id and ra_id:
        masks_for([jid, int(ja_id[0][0])], [rid, int(ra_id[0][0])])
        both("access update", "PATCH", f"/applications/{jid}/access", f"/applications/{rid}/access",
             {"id": int(ja_id[0][0]), "writeAccess": True}, {"id": int(ra_id[0][0]), "writeAccess": True})
        both("access update unchanged", "PATCH", f"/applications/{jid}/access", f"/applications/{rid}/access",
             {"id": int(ja_id[0][0]), "writeAccess": True}, {"id": int(ra_id[0][0]), "writeAccess": True})
        both("app clients", "GET", f"/applications/clients/{APP['java']}" + q({"onlyWriteAccess": "true"}),
             f"/applications/clients/{APP['rust']}" + q({"onlyWriteAccess": "true"}))
        both("access remove", "DELETE", f"/applications/{jid}/access" + q({"accessId": ja_id[0][0]}),
             f"/applications/{rid}/access" + q({"accessId": ra_id[0][0]}))
    else:
        report("access add left no row", "DIFF", f"{ja_id} {ra_id}")
    both("access update missing", "PATCH", f"/applications/{jid}/access", f"/applications/{rid}/access",
         {"id": 999999999, "writeAccess": True}, {"id": 999999999, "writeAccess": True})

    # dependencies
    both("dependency add", "POST", "/applications/dependency", "/applications/dependency",
         {"appCode": APP["java"], "dependentAppCode": "appbuilder"}, {"appCode": APP["rust"], "dependentAppCode": "appbuilder"})
    both("dependency same", "POST", "/applications/dependency", "/applications/dependency",
         {"appCode": APP["java"], "dependentAppCode": APP["java"]}, {"appCode": APP["rust"], "dependentAppCode": APP["rust"]})
    both("dependencies", "GET", "/applications/dependencies" + q({"appCode": APP["java"]}), "/applications/dependencies" + q({"appCode": APP["rust"]}))
    both("dependency remove", "DELETE", "/applications/dependency" + q({"appCode": APP["java"], "dependencyCode": "appbuilder"}),
         "/applications/dependency" + q({"appCode": APP["rust"], "dependencyCode": "appbuilder"}))

    # PIN policy on the scratch app
    (js, jp), (rs, rp) = both("pin policy create", "POST", "/clientPinPolicy", "/clientPinPolicy",
                              {"appId": jid, "clientId": 1, "length": 6}, {"appId": rid, "clientId": 1, "length": 6}, new=True)
    if isinstance(jp, dict) and isinstance(rp, dict) and "id" in jp and "id" in rp:
        masks_for([jid, jp["id"]], [rid, rp["id"]])
        both("pin policy create again", "POST", "/clientPinPolicy", "/clientPinPolicy", {"appId": jid, "clientId": 1}, {"appId": rid, "clientId": 1})
        both("pin policy read", "GET", f"/clientPinPolicy/{jp['id']}", f"/clientPinPolicy/{rp['id']}")
        both("pin policy put", "PUT", f"/clientPinPolicy/{jp['id']}", f"/clientPinPolicy/{rp['id']}", {"noFailedAttempts": 4}, {"noFailedAttempts": 4})
        both("pin policy patch", "PATCH", f"/clientPinPolicy/{jp['id']}", f"/clientPinPolicy/{rp['id']}", {"length": 8, "noFailedAttempts": 9},
             {"length": 8, "noFailedAttempts": 9})
        both("pin policy patch null", "PATCH", f"/clientPinPolicy/{jp['id']}", f"/clientPinPolicy/{rp['id']}", {"length": "x"}, {"length": "x"})
        both("pin policy delete", "DELETE", f"/clientPinPolicy/{jp['id']}", f"/clientPinPolicy/{rp['id']}")
    masks_for([jid], [rid])

    # client URL on the scratch app
    (js, ju), (rs, ru) = both("client url create", "POST", "/clienturls", "/clienturls",
                              {"appCode": APP["java"], "urlPattern": "https://zzparity-java.example.test///"},
                              {"appCode": APP["rust"], "urlPattern": "https://zzparity-rust.example.test///"}, new=True)
    both("client url on an app's host", "POST", "/clienturls", "/clienturls",
         {"appCode": APP["java"], "urlPattern": "appbuilder.local.modlix.com"}, {"appCode": APP["rust"], "urlPattern": "appbuilder.local.modlix.com"})
    if isinstance(ju, dict) and isinstance(ru, dict) and "id" in ju and "id" in ru:
        masks_for([jid, ju["id"]], [rid, ru["id"]])
        both("client url read", "GET", f"/clienturls/{ju['id']}", f"/clienturls/{ru['id']}")
        both("ssl request create (no authority on either side reached)", "POST", "/ssl", "/ssl",
             {"domainNames": ["a.other.test"], "urlId": ju["id"]}, {"domainNames": ["a.other.test"], "urlId": ru["id"]},
             hdrs=OWNER)
        both("client url delete", "DELETE", f"/clienturls/{ju['id']}", f"/clienturls/{ru['id']}")
    masks_for([jid], [rid])

    # draft tokens
    both("draft token", "POST", "/clienturls/draft/token" + q({"appCode": APP["java"]}), "/clienturls/draft/token" + q({"appCode": APP["rust"]}))
    both("draft token again", "POST", "/clienturls/draft/token" + q({"appCode": APP["java"]}), "/clienturls/draft/token" + q({"appCode": APP["rust"]}))
    both("draft token extend unknown", "POST", "/clienturls/draft/token/extend" + q({"token": "nope"}),
         "/clienturls/draft/token/extend" + q({"token": "nope"}))
    both("draft url rotate", "POST", "/clienturls/draft" + q({"appCode": APP["java"]}), "/clienturls/draft" + q({"appCode": APP["rust"]}), new=True)

    # registration objects
    fa = {"clientType": "BUS", "level": "CLIENT", "resourceType": "STATIC", "accessName": "zz", "path": "/zz", "writeAccess": True}
    (js, jr), (rs, rr) = both("reg fileAccess create", "POST", f"/applications/reg/{APP['java']}/fileAccess", f"/applications/reg/{APP['rust']}/fileAccess",
                              fa, fa, new=True)
    both("reg fileAccess query", "POST", f"/applications/reg/{APP['java']}/fileAccess/query", f"/applications/reg/{APP['rust']}/fileAccess/query",
         {"page": 0, "size": 5}, {"page": 0, "size": 5}, new=True)
    if isinstance(jr, dict) and isinstance(rr, dict) and "id" in jr and "id" in rr:
        masks_for([jid, jr["id"]], [rid, rr["id"]])
        both("reg fileAccess delete", "DELETE", f"/applications/reg/fileAccess/{jr['id']}", f"/applications/reg/fileAccess/{rr['id']}")
    masks_for([jid], [rid])

    # integration, evoked, then removed (its states go with it)
    intg = lambda aid: {"appId": aid, "clientId": 1, "platform": "GOOGLE", "intgId": "zz-client-id", "intgSecret": "zz-not-a-secret",
                        "loginUri": "https://zz.example.test/login", "signupUri": "https://zz.example.test/signup"}
    (js, ji), (rs, ri) = both("integration create", "POST", "/appRegIntegration", "/appRegIntegration", intg(jid), intg(rid), new=True)
    if isinstance(ji, dict) and isinstance(ri, dict) and "id" in ji and "id" in ri:
        masks_for([jid, ji["id"]], [rid, ri["id"]])
        both("integration read", "GET", f"/appRegIntegration/{ji['id']}", f"/appRegIntegration/{ri['id']}")
        evoke = {"X-Forwarded-Host": "zz.example.test"}
        both("evoke", "POST", "/clients/socialRegister/evoke" + q({"platform": "GOOGLE"}), "/clients/socialRegister/evoke" + q({"platform": "GOOGLE"}),
             hdrs=headers(None, "SYSTEM", APP["java"], evoke), hdrs_rust=headers(None, "SYSTEM", APP["rust"], evoke))
        both("evoke redirect", "GET", "/clients/socialRegister/evoke" + q({"platform": "GOOGLE", "appCode": "nope"}),
             "/clients/socialRegister/evoke" + q({"platform": "GOOGLE", "appCode": "nope"}),
             hdrs=headers(None, "SYSTEM", APP["java"], evoke), hdrs_rust=headers(None, "SYSTEM", APP["rust"], evoke), header_keys=("location",))
        # The consent screen cancelled (no code): Java's states on Java, Rust's on Rust.
        for label, cond in (("without an app", "not like '%appCode%'"), ("for an app with no address", "like '%appCode%'")):
            js_ = sql(f"select STATE from security_app_reg_integration_tokens where INTEGRATION_ID = {ji['id']} and REQUEST_PARAM {cond} limit 1")
            rs_ = sql(f"select STATE from security_app_reg_integration_tokens where INTEGRATION_ID = {ri['id']} and REQUEST_PARAM {cond} limit 1")
            if js_ and rs_:
                both(f"callback cancelled {label}", "GET", "/clients/socialRegister/callback" + q({"state": js_[0][0]}),
                     "/clients/socialRegister/callback" + q({"state": rs_[0][0]}), hdrs=ANON, header_keys=("location",))
            else:
                report(f"callback cancelled {label}", "DIFF", f"states {js_} {rs_}")
        both("integration delete", "DELETE", f"/appRegIntegration/{ji['id']}", f"/appRegIntegration/{ri['id']}")
    masks_for([jid], [rid])

    registrations(jid, rid)
    masks_for([jid], [rid])

    # archive, then delete
    both("app delete (archives)", "DELETE", f"/applications/{jid}", f"/applications/{rid}")
    both("app read archived", "GET", f"/applications/{jid}", f"/applications/{rid}")
    both("app delete (deletes)", "DELETE", f"/applications/{jid}", f"/applications/{rid}")
    both("app read deleted", "GET", f"/applications/{jid}", f"/applications/{rid}")

    # ---- clients ----
    ids = {}
    for side, base in (("java", JAVA), ("rust", RUST)):
        r = sql(f"select ID from security_client where CODE = '{CLIENT[side]}'")
        ids[side] = int(r[0][0]) if r else None
    masks_for([], [])
    if ids["java"] is None and ids["rust"] is None:
        body = {s: {"code": CLIENT[s], "name": "ZZ Parity", "typeCode": "BUS", "businessType": "COMMON", "timeZone": "Asia/Kolkata",
                    "website": "  zz.example.test  "} for s in CLIENT}
        both("client create", "POST", "/clients", "/clients", body["java"], body["rust"], new=True)
        for side in ("java", "rust"):
            r = sql(f"select ID from security_client where CODE = '{CLIENT[side]}'")
            ids[side] = int(r[0][0]) if r else None
    if ids["java"] is None or ids["rust"] is None:
        report("scratch clients", "DIFF", f"{ids}")
        return
    jc, rc = ids["java"], ids["rust"]
    masks_for([jc], [rc])
    revive = lambda s: {"code": CLIENT[s], "name": "ZZ Parity", "typeCode": "BUS", "businessType": "COMMON", "timeZone": "Asia/Kolkata",
                        "tokenValidityMinutes": 30, "statusCode": "ACTIVE", "levelType": "SYSTEM"}
    both("client put", "PUT", f"/clients/{jc}", f"/clients/{rc}", revive("java"), revive("rust"))
    both("client patch", "PATCH", f"/clients/{jc}", f"/clients/{rc}", {"description": "  zz  ", "industry": "x"}, {"description": "  zz  ", "industry": "x"})
    both("client patch primitive null", "PATCH", f"/clients/{jc}", f"/clients/{rc}", {"tokenValidityMinutes": None}, {"tokenValidityMinutes": None})
    both("client read", "GET", f"/clients/{jc}", f"/clients/{rc}")
    both("client inactive", "GET", "/clients/makeClientInActive" + q({"clientId": jc}), "/clients/makeClientInActive" + q({"clientId": rc}))
    both("client active", "GET", "/clients/makeClientActive" + q({"clientId": jc}), "/clients/makeClientActive" + q({"clientId": rc}))
    both("client active again", "GET", "/clients/makeClientActive" + q({"clientId": jc}), "/clients/makeClientActive" + q({"clientId": rc}))
    both("client read as owner of FIN", "GET", f"/clients/{jc}", f"/clients/{rc}", hdrs=OWNER)
    both("client delete", "DELETE", f"/clients/{jc}", f"/clients/{rc}")
    both("client read deleted", "GET", f"/clients/{jc}", f"/clients/{rc}")


def registrations(jid, rid):
    """Sign-ups on the scratch apps (B2B by now, no registration type). Java gets only what it
    refuses before writing; the one that succeeds runs on Rust alone, on Rust's app, and its client
    and user are marked DELETED (its access row and the property removed) before the app goes."""
    if reg_type_on(APP["java"]) is not None:
        report("registrations", "DIFF", f"{APP['java']} has a REGISTRATION_TYPE; no sign-up sent to Java")
        return
    jh, rh = headers(None, "SYSTEM", APP["java"]), headers(None, "SYSTEM", APP["rust"])
    email = f"zz.regb.parity.{TAG}@example.com"
    biz = {"passType": "OTP", "emailId": email, "clientName": "ZZ Parity Reg", "businessClient": True}
    both("register otp generate, app without registration", "POST", "/clients/register/otp/generate", "/clients/register/otp/generate",
         {"emailId": email}, {"emailId": email}, hdrs=jh, hdrs_rust=rh)
    both("register, no registration on the app", "POST", "/clients/register", "/clients/register", biz, biz, hdrs=jh, hdrs_rust=rh)
    both("register, individual on a B2B app", "POST", "/clients/register", "/clients/register",
         {**biz, "businessClient": False}, {**biz, "businessClient": False}, hdrs=jh, hdrs_rust=rh)
    both("register, subdomain suffix refused", "POST", "/clients/register", "/clients/register",
         {**biz, "subDomain": "zzx", "subDomainSuffix": ".nope.test"}, {**biz, "subDomain": "zzx", "subDomainSuffix": ".nope.test"}, hdrs=jh, hdrs_rust=rh)
    both("register, subdomain is an app", "POST", "/clients/register", "/clients/register",
         {**biz, "subDomain": APP["java"]}, {**biz, "subDomain": APP["rust"]}, hdrs=jh, hdrs_rust=rh)
    both("otp verify, no registration on the app", "POST", "/clients/register/otp/verify", "/clients/register/otp/verify", biz, biz, hdrs=jh, hdrs_rust=rh)

    # Rust alone from here on writes: its app takes sign-ups without verification.
    st, _, b = call(RUST, "POST", "/applications/property", SYS,
                    {"appId": rid, "clientId": 1, "name": "REGISTRATION_TYPE", "value": "REGISTRATION_TYPE_NO_VERIFICATION"})
    if st != 200 or reg_type_on(APP["java"]) is not None:
        report("RUST register setup", "DIFF", f"{st} {b[:200]!r}")
        return
    body = {"passType": "PASSWORD", "password": "Zz!Parity12345", "emailId": email, "clientName": "ZZ Parity Reg", "businessClient": True}
    st, h, b = call(RUST, "POST", "/clients/register", rh, body)
    v = parse(b)
    ok = (st == 200 and isinstance(v, dict) and v.get("created") is True and isinstance(v.get("userId"), int)
          and (v.get("authentication") or {}).get("accessToken") and "Authorization=" in (h.get("set-cookie") or ""))
    report("RUST register, business", "RUST" if ok else "DIFF", "" if ok else f"{st} {b[:300]!r}")
    uid = v.get("userId") if isinstance(v, dict) else None
    cid = sql(f"select CLIENT_ID from security_user where ID = {int(uid)}")[0][0] if isinstance(uid, int) else None
    if cid is not None:
        # Java and Rust on the user and client just made (read only on Java's side).
        masks_for([jid, int(uid), int(cid)], [rid, int(uid), int(cid)])
        both("register events, OTP: nothing to sign in with", "GET", "/clients/register/events", "/clients/register/events",
             {"userId": uid, "passType": "OTP"}, {"userId": uid, "passType": "OTP"}, hdrs=ANON)
        both("register events, no pass type", "GET", "/clients/register/events", "/clients/register/events", {"userId": uid}, {"userId": uid}, hdrs=ANON)
        both("appRegister, not an owner", "POST", "/clients/appRegister" + q({"appCode": APP["java"], "clientId": cid, "userId": uid}),
             "/clients/appRegister" + q({"appCode": APP["rust"], "clientId": cid, "userId": uid}))
        # Removed through Rust's routes.
        for (aid,) in sql(f"select ID from security_app_access where APP_ID = {rid} and CLIENT_ID = {int(cid)}"):
            call(RUST, "DELETE", f"/applications/{rid}/access" + q({"accessId": aid}), SYS)
        call(RUST, "DELETE", f"/users/{int(uid)}", SYS)
        call(RUST, "DELETE", f"/clients/{int(cid)}", SYS)
        left = sql(f"select STATUS_CODE from security_user where ID = {int(uid)} union all select STATUS_CODE from security_client where ID = {int(cid)}")
        report("RUST register cleanup", "RUST" if [r[0] for r in left] == ["DELETED", "DELETED"] else "DIFF", "" if left else "rows missing")
    call(RUST, "DELETE", "/applications/property" + q({"clientId": 1, "appId": rid, "name": "REGISTRATION_TYPE"}), SYS)


def registration_run():
    registration_refusals()
    for side, base in (("java", JAVA), ("rust", RUST)):
        cleanup_app(base, APP[side])
    body = {s: {"appName": "ZZ Parity", "appCode": APP[s], "appType": "APP", "appUsageType": "B2B", "appAccessType": "ANY"} for s in APP}
    masks_for([], [])
    both("app create (B2B)", "POST", "/applications", "/applications", body["java"], body["rust"], new=True)
    jid, rid = app_id(APP["java"]), app_id(APP["rust"])
    if jid is None or rid is None:
        report("app create left no app", "DIFF", f"{jid} {rid}")
    else:
        masks_for([jid], [rid])
        registrations(jid, rid)
    for side, base in (("java", JAVA), ("rust", RUST)):
        cleanup_app(base, APP[side])


LOCK = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "target", "parity_security_admin_clients.lock")


def one_run_at_a_time():
    """Two runs at once share the scratch objects: one run's writes land between the other's Java
    and Rust calls (a scratch client updated in between lists first on one side only), and a run
    starting removes the other's scratch apps. So a run waits for the one before to finish."""
    fd = open(LOCK, "w")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("Another run of this script is going; waiting for it to finish.", flush=True)
        fcntl.flock(fd, fcntl.LOCK_EX)
    return fd


def main():
    lock = one_run_at_a_time()  # noqa: F841 (held until exit)
    n = threads_connected()
    if n > 120:
        print(f"MySQL has {n} connections; waiting is better than starving it. Try again later.")
        sys.exit(2)
    try:
        if REGISTRATION_ONLY:
            registration_run()
        else:
            reads()
            if not READS_ONLY:
                writes()
    except JavaDown as e:
        # No retries and no more requests to Java. Rust's scratch objects go now; Java's (if the
        # unanswered call made any) go at the start of the next run.
        print(f"\nJava security stopped answering ({e}); stopping. Try again once it answers.")
        cleanup_app(RUST, APP["rust"])
        for (cid,) in sql(f"select ID from security_client where CODE = '{CLIENT['rust']}' and STATUS_CODE <> 'DELETED'"):
            call(RUST, "DELETE", f"/clients/{cid}", SYS)
        print(f"{RESULTS['SAME']} SAME, {RESULTS['EXPECTED']} EXPECTED, {RESULTS['DIFF']} DIFF (incomplete)")
        sys.exit(3)
    print(f"\n{RESULTS['SAME']} SAME, {RESULTS['EXPECTED']} EXPECTED, {RESULTS['DIFF']} DIFF, {RESULTS['RUST']} RUST-ONLY checks passed")
    sys.exit(1 if RESULTS["DIFF"] else 0)


if __name__ == "__main__":
    main()
