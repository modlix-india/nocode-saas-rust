#!/usr/bin/env python3
"""Sends the same requests to the Java security service and to security-admin (piece 1: users,
profiles, roles, organisation, OTP, authority expressions) and compares them.

Usage: parity_security_admin_users.py [java_base] [rust_base] [--reads-only] [--resume-after=N]
       defaults: http://localhost:8001  http://localhost:8113
       --resume-after=N skips (sends nothing for) the first N read comparisons, to carry on a run
       that stopped when Java stopped answering; --pause=S waits S seconds (default 0.2) before
       each request to Java.

Local stack only. Requests to Java go one at a time with a pause between them, over one kept-alive
connection (so they stay on one of its event loops), and the run stops (rather than retrying)
when Java stops answering.

Callers: the SYSTEM user 142, FIN users 110 / 114 / 221 / 230 (Basic `<id>:Pass@1234`, their stored
plain local password, so no attempt can be wrong), anonymous callers, and the scratch users the
write section creates (their password is set through the Rust unit, see below).

Reads come from the local `security` schema and change nothing.

Writes touch only scratch objects made in this run, and every id a write names is one this run
created, checked right before the call: per side a client made for the run (`ZZPUJ<run>` for Java,
`ZZPUR<run>` for Rust) and one below it (`ZZPUJK<run>`, `ZZPURK<run>`), each with appbuilder read
access, and in them departments, designations, roles, users, client managers, invites, access
requests, two profiles and an override of one by the client below; real roles are only named as
the lines of the scratch profiles. All of it is removed at the end (users and clients are only
marked DELETED). Java success paths that publish events (an invite, a password change or reset,
an OTP) run on Rust only (its events are logged, not published); Java gets their refusals. Java's
profile override create is not called (it hung Java once); Rust creates the overrides and both
sides read them back.

Compared: status, content type, and the body as JSON in order (`exceptionId`, `stackTrace` and the
id in `message` ignored; scratch ids, timestamps, names and tokens masked). Differences listed in
crates/security/DIFFERENCES.md (piece 1) are reported as EXPECTED.
"""
import base64
import http.client
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import error_parity
import page_order  # a page's own key order changes with each load of Java's classes

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
JAVA = ARGS[0] if len(ARGS) > 0 else "http://localhost:8001"
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8113"
READS_ONLY = "--reads-only" in sys.argv
RESUME_AFTER = next((int(a.split("=", 1)[1]) for a in sys.argv if a.startswith("--resume-after=")), 0)
READ_PHASE = {"on": True, "seen": 0, "skipped": 0}
P = "/api/security"
PASSWORD = "Pass@1234"
RESULTS = {"SAME": 0, "EXPECTED": 0, "DIFF": 0}
PAUSE = next((float(a.split("=", 1)[1]) for a in sys.argv if a.startswith("--pause=")), 0.2)  # seconds before each Java request

# Fields Java fills into the cached Client / User objects (and an earlier read can carry).
LEAKED = {"owners", "managagingClient", "apps", "createdByUser", "clientManagers", "activeUsers", "inactiveUsers",
          "deletedUsers", "lockedUsers", "passwordExpiredUsers", "totalUsers", "profiles", "client", "managingClient",
          "designation", "reportingUser"}

# KIRun's parser texts for malformed expressions (kirun-rust follows kirun-js).
KIRUN_TEXT = {"Authorities.A +", "Authorities.A && Authorities.B", "()"}



def db_password():
    """The local MySQL password: MODLIX__DATABASE__PASSWORD, else config/local.env (never printed)."""
    pw = os.environ.get("MODLIX__DATABASE__PASSWORD")
    if pw:
        return pw
    env = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "local.env")
    with open(env) as f:
        for line in f:
            if line.startswith("MODLIX__DATABASE__PASSWORD="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    raise SystemExit("MODLIX__DATABASE__PASSWORD is not set; source config/local.env")

def sql(query):
    out = subprocess.run(["mysql", "-h127.0.0.1", "-uroot", "security", "-N", "-B", "-e", query],
                         env={**os.environ, "MYSQL_PWD": db_password()}, capture_output=True, text=True, check=True)
    return [line.split("\t") for line in out.stdout.splitlines() if line.strip()]


class JavaDown(Exception):
    pass


JAVA_CONN = {}  # one kept-alive connection to Java: its requests stay on one of its event loops


def java_call(method, path, hdrs, data):
    """One request to Java over the kept-alive connection (opened again only when Java closed it)."""
    u = urllib.parse.urlparse(JAVA)
    for attempt in (0, 1):
        conn = JAVA_CONN.get("c")
        if conn is None:
            conn = JAVA_CONN["c"] = http.client.HTTPConnection(u.hostname, u.port or 80, timeout=60)
        try:
            conn.request(method, P + path, body=data, headers=hdrs)
        except (http.client.HTTPException, ConnectionError, BrokenPipeError):
            # Java closed the idle connection before this request went out: open a new one, once.
            conn.close()
            JAVA_CONN.pop("c", None)
            if attempt:
                raise
            continue
        r = conn.getresponse()
        body = r.read()
        if r.getheader("connection", "").lower() == "close":
            conn.close()
            JAVA_CONN.pop("c", None)
        return r.status, r.getheader("content-type"), body


def call(base, method, path, hdrs, body=None):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    h = dict(hdrs or {})
    if data is not None:
        h["Content-Type"] = "application/json"
    if base == JAVA:
        time.sleep(PAUSE)
        try:
            return java_call(method, path, h, data)
        except Exception as e:  # noqa: BLE001 - a hung call stops the run
            JAVA_CONN.pop("c", None)
            raise JavaDown(f"{method} {path}: {e}")
    req = urllib.request.Request(base + P + path, data=data, method=method)
    for k, v in h.items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.headers.get("content-type"), r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("content-type"), e.read()
    except Exception as e:  # noqa: BLE001
        return 0, None, str(e).encode()


def headers(user=None, client="SYSTEM", app="appbuilder"):
    h = {"X-Forwarded-Host": "localhost", "X-Forwarded-Port": "8080", "X-Forwarded-Proto": "http", "clientCode": client, "appCode": app}
    if user:
        h["Authorization"] = "Basic " + base64.b64encode(f"{user}:{PASSWORD}".encode()).decode()
    return h


SYS = headers(142)
ANON = headers()


def parse(raw):
    try:
        return json.loads(raw) if raw else None
    except ValueError:
        return raw.decode(errors="replace")


MASKS = []  # (text, replacement) for scratch names and codes


def normal(v, ids=()):
    if isinstance(v, dict):
        v = dict(v)
        if "exceptionId" in v:
            v.pop("exceptionId", None)
            v.pop("stackTrace", None)
            if isinstance(v.get("message"), str):
                v["message"] = re.sub(r"\d{4}-\d\d-\d\d-[0-9a-f]+", "<id>", v["message"])
        out = {}
        for k, x in v.items():
            if k in ("createdAt", "updatedAt", "accessToken", "accessTokenExpiryAt", "inviteCode", "requestId"):
                out[k] = "<x>" if x is not None else None
            elif k in ids and x is not None:
                out[k] = "<id>"
            else:
                out[k] = normal(x, ids)
        return out
    if isinstance(v, list):
        return [normal(x, ids) for x in v]
    if isinstance(v, str):
        for a, b in MASKS:
            v = v.replace(a, b)
        v = re.sub(r"Duplicate entry '[0-9]+-[0-9]+'", "Duplicate entry '<id>-<id>'", v)
        v = re.sub(r"^[0-9]+(?= (role|profile) forbidden)", "<n>", v)
        return re.sub(r"\b(5[0-9]{3}|[0-9]{4,})\b(?= (role|profile) forbidden| user)", "<n>", v)
    return v


def without_leaks(v, top=True):
    if isinstance(v, list):
        return [without_leaks(x, top) for x in v]
    if isinstance(v, dict):
        return {k: without_leaks(x, k == "content" and top) for k, x in v.items() if not (k in LEAKED and not top)}
    return v


def by_id(v):
    return sorted(v, key=lambda x: json.dumps(x.get("id")) if isinstance(x, dict) else "") if isinstance(v, list) else v


def report(name, verdict, detail=""):
    RESULTS[verdict] += 1
    print(f"{verdict:8} {name}{(': ' + detail) if detail else ''}", flush=True)


def diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in list(dict.fromkeys(list(a) + list(b))):
            if a.get(k) != b.get(k):
                return diff(a.get(k), b.get(k), f"{path}.{k}")
        return f"{path}: key order {list(a)} vs {list(b)}"
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return diff(x, y, f"{path}[{i}]")
    return f"{path}: {json.dumps(a)[:200]} vs {json.dumps(b)[:200]}"


def same(a, b):
    return json.dumps(a) == json.dumps(b)


def judge(name, j, r, ids=(), expected=None, unordered=None, leaks=False):
    r, coded = error_parity.decode(j, r)
    jv, rv = normal(parse(j[2]), ids), normal(parse(r[2]), ids)
    jv, rv, reordered = page_order.align(jv, rv)
    problems = []
    if j[0] != r[0]:
        problems.append(f"status {j[0]} vs {r[0]}")
    if (j[1] or "").split(";")[0] != (r[1] or "").split(";")[0]:
        problems.append(f"content-type {j[1]!r} vs {r[1]!r}")
    note = None
    if not same(jv, rv):
        jl, rl = (without_leaks(jv), without_leaks(rv)) if leaks else (jv, rv)
        if same(jl, rl):
            note = "Java's cached objects carry fields an earlier fill set on them"
        elif unordered:
            sj, sr = unordered(jl), unordered(rl)
            if same(sj, sr):
                note = "same items, another order (Java collects them with a concurrent flatMap)"
            else:
                problems.append(f"body differs: {diff(sj, sr)}")
        else:
            problems.append(f"body differs: {diff(jl, rl)}")
    if reordered and not problems and not note:
        note = page_order.NOTE
    if problems and expected:
        report(name, "EXPECTED", expected)
    elif error_parity.is_problem(coded):
        report(name, "DIFF", error_parity.detail(coded, "; ".join(problems)))
    elif problems:
        report(name, "DIFF", "; ".join(problems))
    elif note:
        report(name, "EXPECTED", error_parity.detail(coded, note))
    else:
        v = error_parity.verdict("SAME", coded)
        report(name, v, error_parity.detail(coded) if v != "SAME" else "")
    return parse(j[2]), parse(r[2])


def compare(name, method, path, hdrs=SYS, body=None, **kw):
    if READ_PHASE["on"]:
        READ_PHASE["seen"] += 1
        if READ_PHASE["seen"] <= RESUME_AFTER:
            READ_PHASE["skipped"] += 1
            return None, None
    return judge(name, call(JAVA, method, path, hdrs, body), call(RUST, method, path, hdrs, body), **kw)


def both(name, method, jpath, rpath, jbody=None, rbody=None, jh=SYS, rh=None, **kw):
    """One request per side, on that side's own scratch objects."""
    rh = rh or jh
    return judge(name, call(JAVA, method, jpath, jh, jbody), call(RUST, method, rpath, rh, rbody if rbody is not None else jbody), **kw)


def q(params):
    return "?" + urllib.parse.urlencode(params, doseq=True)


def page_items(v):
    if isinstance(v, dict) and isinstance(v.get("content"), list):
        return {**v, "content": by_id(v["content"])}
    return by_id(v) if isinstance(v, list) else v


def page_items_masked(v):
    """A page compared as a set of rows, for pages whose scratch ids are masked (so `by_id` cannot sort)."""
    key = lambda x: json.dumps(x, sort_keys=True)
    if isinstance(v, dict) and isinstance(v.get("content"), list):
        return {**v, "content": sorted(v["content"], key=key)}
    return sorted(v, key=key) if isinstance(v, list) else v


def picker_sorted(v):
    """findUserClients sorts by client name only; Java's ties come in lookup completion order."""
    if not isinstance(v, list):
        return v
    return sorted(v, key=lambda x: (str((x.get("client") or {}).get("name") or "").lower(), json.dumps(x.get("userId"))) if isinstance(x, dict) else ("", ""))


def profiles_sorted(v):
    def fix(x):
        if isinstance(x, dict):
            return {k: (by_id(fix(y)) if k == "profiles" else fix(y)) for k, y in x.items()}
        if isinstance(x, list):
            return [fix(y) for y in x]
        return x
    return fix(v)


# ------------------------------------------------------------------------------------------ reads

EXPRESSIONS = ["", "   ", None, "Authorities.Logged_IN", "Authorities.A and Authorities.B", "Authorities.A or Authorities.B or Authorities.C",
               "Authorities.A and Authorities.B or Authorities.C", "Authorities.A or Authorities.B and Authorities.C",
               "(Authorities.A or Authorities.B) and Authorities.C", "Authorities.A and (Authorities.B or Authorities.C)",
               "not Authorities.A", "not (Authorities.A and Authorities.B)", "Authorities.A[0]", "true", "1", "'x'",
               "Authorities.A = 1", "Authorities.A +", "((", "Authorities..A", "and", "Authorities.A and",
               "a.b.c and (d or not e) or f", "not not Authorities.A",
               "Authorities.A and (Authorities.B and (Authorities.C or Authorities.D))", "Authorities.A && Authorities.B",
               "Authorities.A AND Authorities.B", "Authorities. A", "()", "x and (y or z) or w and v", "2 > 1", "{{Authorities.A}}"]


def reads():
    callers = [("SYSTEM", SYS), ("FIN owner 110", headers(110, "FIN")), ("FIN 114 leadzump", headers(114, "FIN", "leadzump")),
               ("FIN 221 creatorprogram", headers(221, "FIN", "creatorprogram")), ("FIN2 230", headers(230, "FIN2", "leadzump"))]

    for e in EXPRESSIONS:
        compare(f"authorities/parse {e!r}", "POST", "/authorities/parse", SYS, {"expression": e} if e is not None else {},
                expected="KIRun's parser text for a malformed expression (DIFFERENCES.md U2)" if e in KIRUN_TEXT else None)
    compare("authorities/parse anonymous", "POST", "/authorities/parse", ANON, {"expression": "a"})
    compare("authorities/parse array body", "POST", "/authorities/parse", SYS, b"[1]")

    for label, h in callers:
        compare(f"designations {label}", "GET", "/designations" + q({"size": 50, "fetchParentDesignation": "true", "fetchDepartment": "true",
                                                                       "fetchNextDesignation": "true"}), h)
        compare(f"departments {label}", "GET", "/departments" + q({"size": 50, "fetchParentDepartment": "true"}), h)
        compare(f"rolev2 {label}", "GET", "/rolev2" + q({"size": 40}), h)
        compare(f"rolev2 page 2 {label}", "GET", "/rolev2" + q({"size": 20, "page": 2, "sort": "name,desc"}), h)
        compare(f"rolev2 query {label}", "POST", "/rolev2/query", h, {"size": 15, "condition": {"field": "appId", "operator": "EQUALS", "value": 270}})
        for app in ["leadzump", "appbuilder", "nothing", "nosuch"]:
            compare(f"assignable {app} {label}", "GET", f"/rolev2/assignable/{app}", h)
        compare(f"users {label}", "GET", "/users" + q({"size": 30}), h)
        compare(f"users fills {label}", "GET", "/users" + q({"size": 10, "fetchClients": "true", "fetchManagingClients": "true",
                                                              "fetchDesignation": "true", "fetchReportingTo": "true", "fetchCreatedBy": "true"}), h, leaks=True)
        compare(f"users profiles {label}", "GET", "/users" + q({"size": 10, "fetchProfiles": "true", "appCode": "leadzump"}), h,
                unordered=profiles_sorted)
        compare(f"users query {label}", "POST", "/users/query", h, {"size": 5, "condition": {"field": "clientId", "operator": "EQUALS", "value": 28}})
        compare(f"members {label}", "GET", "/users/members", h)
        compare(f"members search {label}", "GET", "/users/members" + q({"q": "a", "size": 3, "page": 1, "includeInactive": "true"}), h)
        compare(f"sub-org {label}", "GET", "/users/sub-org", h)
        compare(f"invites {label}", "GET", "/users/invites" + q({"size": 20}), h)
        compare(f"requests {label}", "GET", "/users/requests" + q({"size": 20}), h)
        for app in ["270", "2", "848", "132"]:
            compare(f"app {app} profiles {label}", "GET", f"/app/{app}/profiles", h, unordered=page_items)
    compare("designation 999999", "GET", "/designations/999999")
    compare("designation abc", "GET", "/designations/abc")
    compare("rolev2 14 sub roles", "GET", "/rolev2/14/subRoles")
    compare("rolev2 999999", "GET", "/rolev2/999999")
    compare("users anonymous", "GET", "/users", ANON)
    compare("users noMapping", "POST", "/users/noMapping", SYS, {})
    compare("users exists none", "GET", "/users/exists")
    compare("user 110", "GET", "/users/110")
    compare("user 999999", "GET", "/users/999999")
    compare("assigned profiles 110 app 270", "GET", "/users/110/app/270/assignedProfiles", unordered=by_id)

    profile_ids = [r[0] for r in sql("select ID from security_profile order by ID")]
    for label, h in callers[:3]:
        for pid in profile_ids:
            compare(f"profile {pid} {label}", "GET", f"/app/profiles/{pid}", h)

    users = [r[0] for r in sql("select ID from security_user where CLIENT_ID in (1, 28) and STATUS_CODE = 'ACTIVE' order by ID limit 4")]
    for u in users:
        # Java reads each managed client with a concurrent flatMap, so the page comes in completion
        # order (DIFFERENCES.md U3): compared by id.
        compare(f"client-managers of {u}", "GET", f"/client-managers/{u}", SYS, leaks=True, unordered=page_items)

    em = "zzparity-otp@example.invalid"
    for b in [{}, {"emailId": em, "otp": "1"}, {"emailId": em, "otp": "1", "purpose": "LOGIN"}, {"emailId": em, "otp": "1", "purpose": "login"},
              {"emailId": em, "otp": "1", "purpose": 1}, {"emailId": em, "purpose": ""}, b"[1]"]:
        compare(f"otp verify {b!r}", "POST", "/otp/verify", ANON, b)
    for h in [headers(None, "NOSUCH"), headers(None, "SYSTEM", "nosuchapp"), ANON]:
        compare(f"otp generate, nothing sent {h['clientCode']}/{h['appCode']}", "POST", "/otp/generate", h,
                {"phoneNumber": "+910000000000", "purpose": "VERIFICATION"})
    compare("otp generate bad purpose", "POST", "/otp/generate", ANON, {"purpose": "bad"})

    for b in [{"userName": "kiran@fincity.com"}, {}]:
        compare(f"findUserClients {b}", "POST", "/users/findUserClients", SYS, b, leaks=True, unordered=picker_sorted)
    compare("findUserClients bad appLevel", "POST", "/users/findUserClients?appLevel=x", SYS, {"userName": "x"})
    compare("reset otp generate signed in", "POST", "/users/reset/password/otp/generate", SYS, {"userName": "x@example.invalid"})
    compare("reset password, no authRequest", "POST", "/users/reset/password", ANON, {"newPassword": PASSWORD})


# ----------------------------------------------------------------------------------------- writes

CREATED = {"java": set(), "rust": set()}  # ("kind", id) this run made

# The roles a scratch profile names (real roles, only ever named as its lines): Owner, User
# CREATE / READ / UPDATE, Role READ, Profile READ / DELETE, and Role DELETE as a line that is not
# assignable.
OWNER_LINES = {"own": {"roleId": 196, "order": 0},
               "admin": {"name": "Admin", "order": 1, "subArrangements": {
                   "u1": {"roleId": 69}, "u2": {"roleId": 70}, "u3": {"roleId": 71}, "r1": {"roleId": 80},
                   "p1": {"roleId": 192}, "p2": {"roleId": 194}, "x": {"roleId": 82, "assignable": False}}}}
ROOT_LINES = {"g": {"name": "Group", "order": 0, "subArrangements": {"g1": {"roleId": 80}, "g2": {"roleId": 70}}},
              "r": {"roleId": 192, "order": 1}}


def mine(side, kind, oid):
    assert (kind, int(oid)) in CREATED[side], f"{side} {kind} {oid} was not created by this run"
    return oid


def made(side, kind, oid):
    if oid is not None:
        CREATED[side].add((kind, int(oid)))
    return oid


def only(side, kind):
    """The one object of this kind this run made for the side."""
    found = [i for k, i in CREATED[side] if k == kind]
    assert len(found) == 1, (side, kind, found)
    return found[0]


def new_client(side, kind, code, name, parent=None):
    """A scratch client made through Java for this run (so a later run never reuses one), with
    appbuilder read access granted through the Rust unit (Java would announce it)."""
    assert not sql(f"select ID from security_client where CODE = '{code}'"), f"client {code} exists already"
    body = {"code": code, "name": name, "typeCode": "BUS", "tokenValidityMinutes": 60, "localeCode": "en"}
    if parent is not None:
        body["parentClientId"] = parent
    st, _, raw = call(JAVA, "POST", "/clients", SYS, body)
    assert st == 200, raw
    cid = made(side, kind, json.loads(raw)["id"])
    st, _, raw = call(RUST, "POST", "/applications/2/access", SYS, {"clientId": cid, "writeAccess": False})
    assert st == 200, raw
    made(side, "access", sql(f"select ID from security_app_access where CLIENT_ID = {cid} and APP_ID = 2")[0][0])
    return cid


def rust_only(method, path, hdrs, body):
    st, _, raw = call(RUST, method, path, hdrs, body)
    assert st == 200, (path, st, raw[:300])
    return parse(raw)


def constant_otp():
    """SYSTEM's constant appbuilder OTP (the scratch clients inherit SYSTEM's OTP policy)."""
    rows = sql("select CONSTANT_VALUE from security_client_otp_policy where CLIENT_ID = 1 and APP_ID = 2 and IS_CONSTANT = 1")
    return rows[0][0].strip() if rows and rows[0][0] not in ("", "NULL") else None


def writes():
    run = str(int(time.time()))[-6:]
    codes_of = {"java": f"ZZPUJ{run}", "rust": f"ZZPUR{run}"}
    below_of = {"java": f"ZZPUJK{run}", "rust": f"ZZPURK{run}"}
    cj = new_client("java", "client", codes_of["java"], "ZZ parity users java")
    cr = new_client("rust", "client", codes_of["rust"], "ZZ parity users rust")
    kj = new_client("java", "below", below_of["java"], "ZZ parity users java below", cj)
    kr = new_client("rust", "below", below_of["rust"], "ZZ parity users rust below", cr)
    MASKS.extend([(below_of["java"], "<below>"), (below_of["rust"], "<below>"), (codes_of["java"], "<code>"), (codes_of["rust"], "<code>"),
                  ("ZZ parity users java", "<name>"), ("ZZ parity users rust", "<name>"),
                  (f"zzpuj{run}", "<who>"), (f"zzpur{run}", "<who>"), ("ZZPU-J", "<n>"), ("ZZPU-R", "<n>")])
    ids_org = ("id", "departmentId", "parentDesignationId", "parentDepartmentId", "nextDesignationId", "clientId")
    none = 999999999

    # ---- departments and designations ----
    dj, dr = both("department create", "POST", "/departments", "/departments", {"clientId": cj, "name": " ZZPU-J dep ", "description": "d"},
                  {"clientId": cr, "name": " ZZPU-R dep ", "description": "d"}, ids=ids_org)
    made("java", "department", dj.get("id")), made("rust", "department", dr.get("id"))
    both("department name taken", "POST", "/departments", "/departments", {"clientId": cj, "name": "ZZPU-J dep"}, {"clientId": cr, "name": "ZZPU-R dep"})
    compare("department blank name", "POST", "/departments", SYS, {"clientId": cj, "name": "  "})
    # The other side's department: one of another client.
    both("department parent of another client", "POST", "/departments", "/departments",
         {"clientId": cj, "name": "x", "parentDepartmentId": mine("rust", "department", dr["id"])},
         {"clientId": cr, "name": "x", "parentDepartmentId": mine("java", "department", dj["id"])})
    compare("department unknown parent", "POST", "/departments", SYS, {"clientId": cj, "name": "x", "parentDepartmentId": none})
    sj, sr = both("designation create", "POST", "/designations", "/designations",
                  {"clientId": cj, "name": "ZZPU-J lead", "departmentId": dj["id"]}, {"clientId": cr, "name": "ZZPU-R lead", "departmentId": dr["id"]}, ids=ids_org)
    made("java", "designation", sj.get("id")), made("rust", "designation", sr.get("id"))
    both("designation list of client", "GET", "/designations" + q({"clientId": cj, "fetchDepartment": "true"}),
         "/designations" + q({"clientId": cr, "fetchDepartment": "true"}), ids=ids_org)
    both("designation put", "PUT", f"/designations/{mine('java', 'designation', sj['id'])}", f"/designations/{mine('rust', 'designation', sr['id'])}",
         {"clientId": cj, "name": "ZZPU-J lead2", "description": "x", "departmentId": dj["id"]},
         {"clientId": cr, "name": "ZZPU-R lead2", "description": "x", "departmentId": dr["id"]}, ids=ids_org)
    both("designation patch", "PATCH", f"/designations/{mine('java', 'designation', sj['id'])}", f"/designations/{mine('rust', 'designation', sr['id'])}",
         {"description": "p", "profileId": [none]}, ids=ids_org)
    both("designation patch bad ULong", "PATCH", f"/designations/{sj['id']}", f"/designations/{sr['id']}", {"departmentId": "x"})
    both("department patch", "PATCH", f"/departments/{mine('java', 'department', dj['id'])}", f"/departments/{mine('rust', 'department', dr['id'])}",
         {"description": "p2"}, ids=ids_org)

    # ---- roles ----
    rj, rr = both("role create", "POST", "/rolev2", "/rolev2", {"clientId": cj, "name": "ZZPU-J role A", "shortName": "A"},
                  {"clientId": cr, "name": "ZZPU-R role A", "shortName": "A"}, ids=("id", "clientId"))
    made("java", "role", rj.get("id")), made("rust", "role", rr.get("id"))
    rj2, rr2 = both("role create B", "POST", "/rolev2", "/rolev2", {"clientId": cj, "name": "ZZPU-J role B"}, {"clientId": cr, "name": "ZZPU-R role B"},
                    ids=("id", "clientId"))
    made("java", "role", rj2.get("id")), made("rust", "role", rr2.get("id"))
    compare("role create without name", "POST", "/rolev2", SYS, {"clientId": cj})
    # A client in the body is not taken (the other side's scratch client here).
    both("role put", "PUT", f"/rolev2/{mine('java', 'role', rj['id'])}", f"/rolev2/{mine('rust', 'role', rr['id'])}",
         {"name": "ZZPU-J role A2", "clientId": cr}, {"name": "ZZPU-R role A2", "clientId": cj}, ids=("id", "clientId"))
    both("role patch", "PATCH", f"/rolev2/{mine('java', 'role', rj['id'])}", f"/rolev2/{mine('rust', 'role', rr['id'])}", {"description": "p"},
         ids=("id", "clientId"))
    both("role patch bad ULong", "PATCH", f"/rolev2/{rj['id']}", f"/rolev2/{rr['id']}", {"appId": "x"})
    both("sub role add", "POST", f"/rolev2/{rj['id']}/subRoles/{mine('java', 'role', rj2['id'])}", f"/rolev2/{rr['id']}/subRoles/{mine('rust', 'role', rr2['id'])}")
    both("sub role cycle", "POST", f"/rolev2/{rj2['id']}/subRoles/{rj['id']}", f"/rolev2/{rr2['id']}/subRoles/{rr['id']}")
    both("sub role self", "POST", f"/rolev2/{rj['id']}/subRoles/{rj['id']}", f"/rolev2/{rr['id']}/subRoles/{rr['id']}")
    both("sub roles", "GET", f"/rolev2/{rj['id']}/subRoles", f"/rolev2/{rr['id']}/subRoles", ids=("id", "clientId"))
    both("sub role remove", "DELETE", f"/rolev2/{rj['id']}/subRoles/{rj2['id']}", f"/rolev2/{rr['id']}/subRoles/{rr2['id']}")

    # ---- profiles ----
    ids_prof = ("id", "rootProfileId", "clientId")
    compare("profile without app", "POST", "/app/profiles", SYS, {"clientId": cj, "name": "x"})
    compare("profile blank name", "POST", "/app/profiles", SYS, {"appId": 2, "clientId": cj, "name": "  "})
    compare("profile role out of reach", "POST", "/app/profiles", SYS, {"appId": 2, "clientId": cj, "name": "x", "arrangement": {"k": {"roleId": none}}})
    pj, pr = both("profile create", "POST", "/app/profiles", "/app/profiles",
                  {"appId": 2, "clientId": cj, "name": f"ZZPU-J prof {run}", "arrangement": OWNER_LINES},
                  {"appId": 2, "clientId": cr, "name": f"ZZPU-R prof {run}", "arrangement": OWNER_LINES}, ids=ids_prof)
    made("java", "profile", (pj or {}).get("id")), made("rust", "profile", (pr or {}).get("id"))
    MASKS.extend([(f"ZZPU-J prof {run}", "<p>"), (f"ZZPU-R prof {run}", "<p>"), (f"ZZPU-J root {run}", "<r>"), (f"ZZPU-R root {run}", "<r>")])
    both("profile name taken", "POST", "/app/profiles", "/app/profiles", {"appId": 2, "clientId": cj, "name": f"ZZPU-J prof {run}"},
         {"appId": 2, "clientId": cr, "name": f"ZZPU-R prof {run}"})
    both("profile update", "PUT", "/app/profiles", "/app/profiles",
         {"id": mine("java", "profile", pj["id"]), "appId": 2, "clientId": cj, "name": f"ZZPU-J prof {run}", "description": "d2", "arrangement": OWNER_LINES},
         {"id": mine("rust", "profile", pr["id"]), "appId": 2, "clientId": cr, "name": f"ZZPU-R prof {run}", "description": "d2", "arrangement": OWNER_LINES},
         ids=ids_prof)
    both("profile restrict", "POST", f"/app/profiles/{pj['id']}/restrictClient/{mine('java', 'below', kj)}",
         f"/app/profiles/{pr['id']}/restrictClient/{mine('rust', 'below', kr)}")
    both("profile restrict again", "POST", f"/app/profiles/{pj['id']}/restrictClient/{kj}", f"/app/profiles/{pr['id']}/restrictClient/{kr}")
    # A second profile, for the client below to override.
    qj, qr = both("root profile create", "POST", "/app/profiles", "/app/profiles",
                  {"appId": 2, "clientId": cj, "name": f"ZZPU-J root {run}", "title": "Root", "arrangement": ROOT_LINES},
                  {"appId": 2, "clientId": cr, "name": f"ZZPU-R root {run}", "title": "Root", "arrangement": ROOT_LINES}, ids=ids_prof)
    made("java", "profile", (qj or {}).get("id")), made("rust", "profile", (qr or {}).get("id"))

    # ---- users ----
    ids_user = ("id", "clientId", "reportingTo", "designationId", "updatedBy", "createdBy", "userId")
    uj, ur = both("user create", "POST", "/users", "/users",
                  {"clientId": cj, "userName": f"zzpuj{run}a", "emailId": f"zzpuj{run}a@example.invalid", "firstName": "One", "statusCode": "ACTIVE"},
                  {"clientId": cr, "userName": f"zzpur{run}a", "emailId": f"zzpur{run}a@example.invalid", "firstName": "One", "statusCode": "ACTIVE"}, ids=ids_user)
    made("java", "user", uj.get("id")), made("rust", "user", ur.get("id"))
    uj2, ur2 = both("user create reporting", "POST", "/users", "/users",
                    {"clientId": cj, "userName": f"zzpuj{run}b", "emailId": f"zzpuj{run}b@example.invalid", "reportingTo": uj["id"], "localeCode": "en",
                     "statusCode": "ACTIVE"},
                    {"clientId": cr, "userName": f"zzpur{run}b", "emailId": f"zzpur{run}b@example.invalid", "reportingTo": ur["id"], "localeCode": "en",
                     "statusCode": "ACTIVE"}, ids=ids_user)
    made("java", "user", uj2.get("id")), made("rust", "user", ur2.get("id"))
    uj4, ur4 = both("user create below", "POST", "/users", "/users",
                    {"clientId": kj, "userName": f"zzpuj{run}d", "emailId": f"zzpuj{run}d@example.invalid", "statusCode": "ACTIVE"},
                    {"clientId": kr, "userName": f"zzpur{run}d", "emailId": f"zzpur{run}d@example.invalid", "statusCode": "ACTIVE"}, ids=ids_user)
    made("java", "user", uj4.get("id")), made("rust", "user", ur4.get("id"))
    compare("user create no identity", "POST", "/users", SYS, {"clientId": cj})
    compare("user create unknown client", "POST", "/users", SYS, {"clientId": none, "userName": "x"})
    both("user put", "PUT", f"/users/{mine('java', 'user', uj['id'])}", f"/users/{mine('rust', 'user', ur['id'])}",
         {"clientId": cj, "userName": f"zzpuj{run}a", "emailId": f"zzpuj{run}a@example.invalid", "firstName": "Two", "statusCode": "ACTIVE", "timeZone": "Asia/Kolkata"},
         {"clientId": cr, "userName": f"zzpur{run}a", "emailId": f"zzpur{run}a@example.invalid", "firstName": "Two", "statusCode": "ACTIVE", "timeZone": "Asia/Kolkata"},
         ids=ids_user)
    both("user put without client", "PUT", f"/users/{uj['id']}", f"/users/{ur['id']}", {"userName": "x"})
    both("user put identity taken", "PUT", f"/users/{uj['id']}", f"/users/{ur['id']}",
         {"clientId": cj, "userName": f"zzpuj{run}a", "emailId": f"zzpuj{run}b@example.invalid"},
         {"clientId": cr, "userName": f"zzpur{run}a", "emailId": f"zzpur{run}b@example.invalid"})
    both("user patch", "PATCH", f"/users/{mine('java', 'user', uj['id'])}", f"/users/{mine('rust', 'user', ur['id'])}", {"lastName": "P"}, ids=ids_user)
    both("user patch null userName", "PATCH", f"/users/{uj['id']}", f"/users/{ur['id']}", {"userName": None})
    both("user patch bad ULong", "PATCH", f"/users/{uj['id']}", f"/users/{ur['id']}", {"reportingTo": "x"})
    both("user inactive", "PATCH", f"/users/makeUserInActive?userId={uj['id']}", f"/users/makeUserInActive?userId={ur['id']}")
    both("user active", "PATCH", f"/users/makeUserActive?userId={uj['id']}", f"/users/makeUserActive?userId={ur['id']}")
    both("user unblock", "POST", f"/users/unblockUser?userId={uj['id']}", f"/users/unblockUser?userId={ur['id']}")
    both("user designation", "PUT", f"/users/{mine('java', 'user', uj2['id'])}/designation/{sj['id']}", f"/users/{mine('rust', 'user', ur2['id'])}/designation/{sr['id']}",
         ids=ids_user)
    both("user designation of another client", "PUT", f"/users/{uj2['id']}/designation/{sr['id']}", f"/users/{ur2['id']}/designation/{sj['id']}")
    both("user manager self", "PUT", f"/users/{uj2['id']}/reportingManager/{uj2['id']}", f"/users/{ur2['id']}/reportingManager/{ur2['id']}")
    both("user manager clear", "DELETE", f"/users/{uj2['id']}/reportingManager", f"/users/{ur2['id']}/reportingManager", ids=ids_user)
    both("user manager set", "PUT", f"/users/{uj2['id']}/reportingManager/{uj['id']}", f"/users/{ur2['id']}/reportingManager/{ur['id']}", ids=ids_user)
    # SYSTEM may not hand out a role of the scratch client (Java reads the client id as the app id).
    both("assign scratch role as SYSTEM", "GET", f"/users/{uj['id']}/assignRole/{rj['id']}", f"/users/{ur['id']}/assignRole/{rr['id']}")
    both("assign profile", "GET", f"/users/{uj['id']}/assignProfile/{mine('java', 'profile', pj['id'])}",
         f"/users/{ur['id']}/assignProfile/{mine('rust', 'profile', pr['id'])}")
    both("assign profile below", "GET", f"/users/{mine('java', 'user', uj4['id'])}/assignProfile/{pj['id']}",
         f"/users/{mine('rust', 'user', ur4['id'])}/assignProfile/{pr['id']}")
    both("assigned profiles", "GET", f"/users/{uj['id']}/app/2/assignedProfiles", f"/users/{ur['id']}/app/2/assignedProfiles", ids=ids_prof)

    # Passwords: refusals on both; the change itself on Rust (Java announces it).
    for b in [{}, {"newPassword": "short"}, {"newPassword": "Pass 1234@"}, {"newPassword": "12345", "passType": "PIN"},
              {"newPassword": PASSWORD, "passType": None}, {"newPassword": PASSWORD, "passType": "OTP"}]:
        both(f"update password {b}", "POST", f"/users/{uj['id']}/updatePassword", f"/users/{ur['id']}/updatePassword", b)
    for side, u in (("java", uj), ("rust", ur), ("java", uj2), ("rust", ur2), ("java", uj4), ("rust", ur4)):
        rust_only("POST", f"/users/{mine(side, 'user', u['id'])}/updatePassword", SYS, {"newPassword": PASSWORD})
    hj, hr = headers(uj["id"], codes_of["java"]), headers(ur["id"], codes_of["rust"])
    hj2, hr2 = headers(uj2["id"], codes_of["java"]), headers(ur2["id"], codes_of["rust"])
    hj4, hr4 = headers(uj4["id"], below_of["java"]), headers(ur4["id"], below_of["rust"])
    both("self password same", "POST", "/users/updatePassword", "/users/updatePassword", {"oldPassword": PASSWORD, "newPassword": PASSWORD}, jh=hj, rh=hr)
    both("self read", "GET", f"/users/{uj['id']}", f"/users/{ur['id']}", jh=hj, rh=hr, ids=ids_user)
    # The owner hands out the client's own role.
    both("assign role as owner", "GET", f"/users/{uj2['id']}/assignRole/{rj['id']}", f"/users/{ur2['id']}/assignRole/{rr['id']}", jh=hj, rh=hr)
    both("assign role as owner again", "GET", f"/users/{uj2['id']}/assignRole/{rj['id']}", f"/users/{ur2['id']}/assignRole/{rr['id']}", jh=hj, rh=hr)
    both("remove role as owner", "GET", f"/users/{uj2['id']}/removeRole/{rj['id']}", f"/users/{ur2['id']}/removeRole/{rr['id']}", jh=hj, rh=hr)
    # A member without authorities, each request naming the other side's scratch client.
    for m, jpath, rpath, jbody, rbody in [
            ("POST", "/users", "/users", {"clientId": cr, "userName": "x"}, {"clientId": cj, "userName": "x"}),
            ("POST", "/rolev2", "/rolev2", {"clientId": cr, "name": "x"}, {"clientId": cj, "name": "x"}),
            ("POST", "/app/profiles", "/app/profiles", {"appId": 2, "clientId": cr, "name": "x"}, {"appId": 2, "clientId": cj, "name": "x"}),
            ("POST", "/designations", "/designations", {"clientId": cr, "name": "x"}, {"clientId": cj, "name": "x"}),
            ("GET", "/users", "/users", None, None), ("GET", "/rolev2", "/rolev2", None, None),
            ("PATCH", f"/users/makeUserActive?userId={uj['id']}", f"/users/makeUserActive?userId={ur['id']}", None, None),
            ("GET", "/users/members", "/users/members", None, None)]:
        both(f"member {m} {jpath.split('?')[0]}", m, jpath, rpath, jbody, rbody, jh=hj2, rh=hr2, ids=ids_user,
             expected="Rust applies UserService.create / RoleV2Service.create's @PreAuthorize (DIFFERENCES.md U1)"
             if jpath in ("/users", "/rolev2") and m == "POST" else None)

    # ---- client managers (each user of a side managing the other side's scratch client) ----
    both("manager add", "POST", f"/client-managers/{uj2['id']}/{cr}", f"/client-managers/{ur2['id']}/{cj}")
    both("manager add own client", "POST", f"/client-managers/{uj2['id']}/{cj}", f"/client-managers/{ur2['id']}/{cr}")
    both("clients of manager", "GET", f"/client-managers/{uj2['id']}", f"/client-managers/{ur2['id']}", ids=("id",), leaks=True)
    both("manager replace", "POST", f"/client-managers/{cr}?oldManagerId={uj2['id']}&newManagerId={uj['id']}",
         f"/client-managers/{cj}?oldManagerId={ur2['id']}&newManagerId={ur['id']}")
    both("manager migrate", "POST", f"/client-managers/migrateTo/{uj2['id']}?fromUid={uj['id']}&removeManager=true",
         f"/client-managers/migrateTo/{ur2['id']}?fromUid={ur['id']}&removeManager=true")
    both("manager migrate to self", "POST", f"/client-managers/migrateTo/{uj2['id']}?fromUid={uj2['id']}",
         f"/client-managers/migrateTo/{ur2['id']}?fromUid={ur2['id']}")
    both("manager sync", "PUT", f"/client-managers/{cr}/managers", f"/client-managers/{cj}/managers", [uj2["id"]], [ur2["id"]])
    both("manager sync empty", "PUT", f"/client-managers/{cr}/managers", f"/client-managers/{cj}/managers", [], [])
    both("manager remove", "DELETE", f"/client-managers/{uj2['id']}/{cr}", f"/client-managers/{ur2['id']}/{cj}")

    # ---- invites (made on Rust: Java announces an invite) ----
    both("invite of an existing identity", "POST", "/users/invite", "/users/invite", {"clientId": cj, "emailId": f"zzpuj{run}a@example.invalid", "phoneNumber": "1"},
         {"clientId": cr, "emailId": f"zzpur{run}a@example.invalid", "phoneNumber": "1"})
    both("invite reporting to another client", "POST", "/users/invite", "/users/invite",
         {"clientId": cj, "emailId": "x@example.invalid", "reportingTo": mine("rust", "user", ur["id"])},
         {"clientId": cr, "emailId": "x@example.invalid", "reportingTo": mine("java", "user", uj["id"])})
    compare("invite reporting to no one", "POST", "/users/invite", SYS, {"clientId": cj, "emailId": "x@example.invalid", "reportingTo": none})
    codes = {}
    for side, cid in (("java", cj), ("rust", cr)):
        tag = "zzpuj" if side == "java" else "zzpur"
        v = rust_only("POST", "/users/invite", SYS, {"clientId": cid, "emailId": f"{tag}{run}i@example.invalid", "firstName": "Inv"})
        codes[side] = v["userRequest"]["inviteCode"]
        made(side, "invite", v["userRequest"]["id"])
    both("invite pending", "POST", "/users/invite", "/users/invite", {"clientId": cj, "emailId": f"zzpuj{run}i@example.invalid"},
         {"clientId": cr, "emailId": f"zzpur{run}i@example.invalid"})
    both("invite details", "GET", f"/users/inviteDetails/{codes['java']}", f"/users/inviteDetails/{codes['rust']}", jh=ANON, ids=("id", "clientId", "createdBy"))
    both("invites of client", "GET", "/users/invites" + q({"clientId": cj}), "/users/invites" + q({"clientId": cr}), ids=("id", "clientId", "createdBy"))
    an_j, an_r = headers(None, codes_of["java"]), headers(None, codes_of["rust"])
    both("accept invite, no pass type", "POST", "/users/acceptInvite", "/users/acceptInvite", {"inviteCode": codes["java"]}, {"inviteCode": codes["rust"]},
         jh=an_j, rh=an_r)
    both("accept invite, weak password", "POST", "/users/acceptInvite", "/users/acceptInvite",
         {"inviteCode": codes["java"], "passType": "PASSWORD", "password": "short"}, {"inviteCode": codes["rust"], "passType": "PASSWORD", "password": "short"},
         jh=an_j, rh=an_r)
    aj, ar = both("accept invite", "POST", "/users/acceptInvite", "/users/acceptInvite",
                  {"inviteCode": codes["java"], "passType": "PASSWORD", "password": PASSWORD},
                  {"inviteCode": codes["rust"], "passType": "PASSWORD", "password": PASSWORD}, jh=an_j, rh=an_r, ids=ids_user + ("loggedInClientId",))
    made("java", "user", (aj or {}).get("userId")), made("rust", "user", (ar or {}).get("userId"))
    both("accept invite again", "POST", "/users/acceptInvite", "/users/acceptInvite",
         {"inviteCode": codes["java"], "passType": "PASSWORD", "password": PASSWORD},
         {"inviteCode": codes["rust"], "passType": "PASSWORD", "password": PASSWORD}, jh=an_j, rh=an_r)
    compare("accept unknown invite", "POST", "/users/acceptInvite", an_j, {"inviteCode": "nope", "passType": "PASSWORD", "password": PASSWORD})
    for side, cid in (("java", cj), ("rust", cr)):
        tag = "zzpuj" if side == "java" else "zzpur"
        v = rust_only("POST", "/users/invite", SYS, {"clientId": cid, "emailId": f"{tag}{run}k@example.invalid"})
        codes[side] = v["userRequest"]["inviteCode"]
        made(side, "invite", v["userRequest"]["id"])
    both("invite revoke", "DELETE", f"/users/invite/{codes['java']}", f"/users/invite/{codes['rust']}")
    both("invite revoke again", "DELETE", f"/users/invite/{codes['java']}", f"/users/invite/{codes['rust']}")

    # ---- access requests (no events) ----
    both("pending request none", "GET", "/users/request?appCode=appbuilder", "/users/request?appCode=appbuilder", jh=hj2, rh=hr2)
    qrj, qrr = both("request create", "POST", "/users/request", "/users/request", {"appCode": "appbuilder"}, jh=hj2, rh=hr2,
                    ids=("id", "userId", "clientId", "createdBy"))
    made("java", "request", (qrj or {}).get("id")), made("rust", "request", (qrr or {}).get("id"))
    both("request again", "POST", "/users/request", "/users/request", {"appCode": "appbuilder"}, jh=hj2, rh=hr2)
    both("pending request", "GET", "/users/request?appCode=appbuilder", "/users/request?appCode=appbuilder", jh=hj2, rh=hr2)
    both("request user", "GET", f"/users/requestUser/{qrj['requestId']}", f"/users/requestUser/{qrr['requestId']}", ids=ids_user)
    both("requests of requester", "POST", "/users/requests/query?requesterSearch=" + f"zzpuj{run}b", "/users/requests/query?requesterSearch=" + f"zzpur{run}b",
         {"size": 5}, ids=("id", "userId", "clientId", "createdBy"))
    both("request accept, no profile", "POST", "/users/acceptRequest", "/users/acceptRequest", {"requestId": qrj["requestId"]}, {"requestId": qrr["requestId"]})
    both("request accept, unknown profile", "POST", "/users/acceptRequest", "/users/acceptRequest",
         {"requestId": qrj["requestId"], "profileId": none}, {"requestId": qrr["requestId"], "profileId": none})
    both("request accept", "POST", "/users/acceptRequest", "/users/acceptRequest", {"requestId": qrj["requestId"], "profileId": mine("java", "profile", pj["id"])},
         {"requestId": qrr["requestId"], "profileId": mine("rust", "profile", pr["id"])})
    both("request reject after accept", "POST", f"/users/rejectRequest/{qrj['requestId']}", f"/users/rejectRequest/{qrr['requestId']}")

    # ---- the override by the client below (made on Rust: Java's override create hung it once) ----
    for side, root, below in (("java", qj, kj), ("rust", qr, kr)):
        lines = json.loads(json.dumps(parse(call(RUST, "GET", f"/app/profiles/{mine(side, 'profile', root['id'])}", SYS)[2])["arrangement"]))
        for line in lines.values():
            for k in ("role", "name", "shortName", "description", "assignable"):
                line.pop(k, None)
            for sub in line.get("subArrangements", {}).values():
                for k in ("role", "name", "shortName", "description", "assignable"):
                    sub.pop(k, None)
        del lines["g"]["subArrangements"]["g2"]
        lines["g"]["order"] = 5
        lines["zzextra"] = {"name": "Extra", "order": 9}
        body = {"rootProfileId": mine(side, "profile", root["id"]), "appId": 2, "clientId": mine(side, "below", below), "name": root["name"],
                "title": "Mine", "arrangement": lines}
        assert "id" not in body
        made(side, "override", rust_only("POST", "/app/profiles", SYS, body)["id"])
    both("override read through the root below", "GET", f"/app/profiles/{qj['id']}", f"/app/profiles/{qr['id']}", jh=hj4, rh=hr4, ids=ids_prof)
    both("root read above", "GET", f"/app/profiles/{qj['id']}", f"/app/profiles/{qr['id']}", jh=hj, rh=hr, ids=ids_prof)
    both("override read by id below", "GET", f"/app/profiles/{only('java', 'override')}", f"/app/profiles/{only('rust', 'override')}", jh=hj4, rh=hr4,
         ids=ids_prof)
    both("app profiles below", "GET", "/app/2/profiles", "/app/2/profiles", jh=hj4, rh=hr4, unordered=page_items_masked, ids=ids_prof)
    both("app profiles as owner", "GET", "/app/2/profiles", "/app/2/profiles", jh=hj, rh=hr, unordered=page_items_masked, ids=ids_prof)
    both("root delete while overridden", "DELETE", f"/app/profiles/{qj['id']}", f"/app/profiles/{qr['id']}", jh=hj, rh=hr)

    # ---- OTP and the password reset (OTPs made on Rust: Java mails them; Java gets the refusals) ----
    otp = constant_otp()
    if otp:
        for side, u in (("java", uj), ("rust", ur)):
            rust_only("POST", "/users/reset/password/otp/generate", headers(None, codes_of[side]), {"userName": u["emailId"]})
        both("reset verify wrong", "POST", "/users/reset/password/otp/verify", "/users/reset/password/otp/verify", {"userName": uj["emailId"], "otp": "000000"},
             {"userName": ur["emailId"], "otp": "000000"}, jh=an_j, rh=an_r)
        both("reset verify", "POST", "/users/reset/password/otp/verify", "/users/reset/password/otp/verify", {"userName": uj["emailId"], "otp": otp},
             {"userName": ur["emailId"], "otp": otp}, jh=an_j, rh=an_r)
        both("reset wrong otp", "POST", "/users/reset/password", "/users/reset/password",
             {"authRequest": {"userName": uj["emailId"], "otp": "000000"}, "newPassword": "Pass@5678"},
             {"authRequest": {"userName": ur["emailId"], "otp": "000000"}, "newPassword": "Pass@5678"}, jh=an_j, rh=an_r)
        both("reset reused password", "POST", "/users/reset/password", "/users/reset/password",
             {"authRequest": {"userName": uj["emailId"], "otp": otp}, "newPassword": PASSWORD},
             {"authRequest": {"userName": ur["emailId"], "otp": otp}, "newPassword": PASSWORD}, jh=an_j, rh=an_r)
    both("find user clients", "POST", "/users/findUserClients", "/users/findUserClients", {"userName": uj["emailId"]}, {"userName": ur["emailId"]},
         jh=an_j, rh=an_r, ids=("userId", "id"), leaks=True, unordered=picker_sorted)

    cleanup({"java": hj4, "rust": hr4}, {"java": hj, "rust": hr})


def cleanup(below_callers, owner_callers):
    """Removes what this run made, each object by its own side and checked as this run's (users
    and clients can only be marked DELETED). An override is removed by the user below that made
    the read, its root then by the owner above."""
    for side, base in (("java", JAVA), ("rust", RUST)):
        made_here = sorted(CREATED[side])
        for kind, oid in made_here:
            if kind == "override":
                call(base, "DELETE", f"/app/profiles/{mine(side, 'override', oid)}", below_callers[side])
        # The root first: the owner's rights come from the other profile.
        for kind, oid in reversed(made_here):
            if kind == "profile":
                call(base, "DELETE", f"/app/profiles/{mine(side, 'profile', oid)}", owner_callers[side])
        for kind, oid in made_here:
            if kind == "role":
                call(base, "DELETE", f"/rolev2/{mine(side, 'role', oid)}", SYS)
        for kind, oid in made_here:
            if kind == "designation":
                call(base, "DELETE", f"/designations/{mine(side, 'designation', oid)}", SYS)
        for kind, oid in made_here:
            if kind == "department":
                call(base, "DELETE", f"/departments/{mine(side, 'department', oid)}", SYS)
        for kind, oid in made_here:
            if kind == "user":
                call(base, "DELETE", f"/users/{mine(side, 'user', oid)}", SYS)
    for side in ("java", "rust"):
        made_here = sorted(CREATED[side])
        for kind, oid in made_here:
            if kind == "access":
                call(RUST, "DELETE", f"/applications/2/access?accessId={mine(side, 'access', oid)}", SYS)
        for kind in ("below", "client"):
            for k, oid in made_here:
                if k == kind:
                    call(JAVA, "DELETE", f"/clients/{mine(side, kind, oid)}", SYS)
    left = sql("select count(*) from security_profile where ID in (" + ",".join(
        str(i) for s in CREATED.values() for k, i in s if k in ("profile", "override")) + ")") if any(
        k in ("profile", "override") for s in CREATED.values() for k, _ in s) else [["0"]]
    if left[0][0] != "0":
        print(f"cleanup: {left[0][0]} scratch profiles are left")


def main():
    if int(sql("show status like 'Threads_connected'")[0][1]) > 120:
        print("MySQL has more than 120 connections; not starting")
        return 1
    try:
        reads()
        READ_PHASE["on"] = False
        if READ_PHASE["skipped"]:
            print(f"(skipped the first {READ_PHASE['skipped']} read comparisons)")
        if not READS_ONLY:
            writes()
    except JavaDown as e:
        print(f"Java security stopped answering ({e}); stopped here, not retrying")
        print(f"\nSAME {RESULTS['SAME']}  EXPECTED {RESULTS['EXPECTED']}  DIFF {RESULTS['DIFF']}  (incomplete)")
        return 2
    print(f"\nSAME {RESULTS['SAME']}  EXPECTED {RESULTS['EXPECTED']}  DIFF {RESULTS['DIFF']}")
    return 1 if RESULTS["DIFF"] else 0


if __name__ == "__main__":
    sys.exit(main())
