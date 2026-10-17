#!/usr/bin/env python3
"""Sends the same requests to the Java security service and to security-internal and compares them.

Usage: parity_security_internal.py [java_base] [rust_base]
       defaults: http://localhost:8001  http://localhost:8112

Local stack only, read-only. Cases come from the local `security` schema (read with the mysql
CLI): clients, users, apps, client URLs and billing configs that exist there. Callers are the
anonymous SYSTEM caller (how services call these routes), an anonymous caller on a tenant's host,
and signed-in users (Basic `<id>:Pass@1234` for users whose stored password is that plain text,
so no attempt can be wrong). Nothing is created; the billing routes that charge
(`meter/security`, `reconcile`, a charge that would debit) are not called.

Compared: status, content type, and the body as JSON values (`exceptionId`, `stackTrace` and the
id in `message` ignored). Differences explained in crates/security/DIFFERENCES.md are reported as
EXPECTED.
"""
import base64
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

import error_parity
import page_order  # a page's own key order changes with each load of Java's classes

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
JAVA = ARGS[0] if len(ARGS) > 0 else "http://localhost:8001"
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8112"
P = "/api/security"
PASSWORD = "Pass@1234"
RESULTS = {"SAME": 0, "EXPECTED": 0, "DIFF": 0}

# Properties Java fills into the Client / User objects it caches (fillDetails sets them on the
# cached instance), so a later plain read on that JVM can carry them. Rust never mutates a
# cached row. Reported as EXPECTED when they are the only difference.
LEAKED = {"owners", "managagingClient", "apps", "createdByUser", "clientManagers", "activeUsers", "inactiveUsers",
          "deletedUsers", "lockedUsers", "passwordExpiredUsers", "totalUsers", "profiles", "client",
          "managingClient", "designation", "reportingUser"}



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


def call(base, method, path, headers=None, body=None):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(base + path, data=data, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
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


def strip(v):
    if isinstance(v, dict) and "exceptionId" in v:
        v = dict(v)
        v.pop("exceptionId", None)
        v.pop("stackTrace", None)
        if isinstance(v.get("message"), str):
            v["message"] = re.sub(r"\d{4}-\d\d-\d\d-[0-9a-f]+", "<id>", v["message"])
    return v


def without_leaks(v, keep, top=True):
    """Drops the LEAKED properties at every depth, except the requested ones (`keep`) on the
    top-level objects (the list items, or a page's content)."""
    if isinstance(v, list):
        return [without_leaks(x, keep, top) for x in v]
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            if k == "content" and top:
                out[k] = without_leaks(x, keep, True)
            elif k in LEAKED and not (top and k in keep):
                continue
            else:
                out[k] = without_leaks(x, keep, False)
        return out
    return v


def by_id(v):
    return sorted(v, key=lambda x: x.get("id", 0) if isinstance(x, dict) else 0) if isinstance(v, list) else v


def report(name, verdict, detail=""):
    RESULTS[verdict] += 1
    print(f"{verdict:8} {name}{(': ' + detail) if detail else ''}")


def diff(a, b, path=""):
    if isinstance(a, dict) and isinstance(b, dict):
        for k in sorted(set(a) | set(b)):
            if a.get(k) != b.get(k):
                return diff(a.get(k), b.get(k), f"{path}.{k}")
        return path
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return diff(x, y, f"{path}[{i}]")
    return f"{path}: {json.dumps(a)[:200]} vs {json.dumps(b)[:200]}"


def page_key_orders(a, b):
    """The key order of a `Page` (and of its `pageable`) on both sides, when either body is one.
    JSON values compare equal whatever their key order, so a page writer with the wrong property
    order is only caught here."""
    if not (isinstance(a, dict) and isinstance(b, dict) and "pageable" in a and "pageable" in b):
        return None
    orders = (list(a), list(b))
    if isinstance(a.get("pageable"), dict) and isinstance(b.get("pageable"), dict):
        orders = (orders[0] + ["|"] + list(a["pageable"]), orders[1] + ["|"] + list(b["pageable"]))
    return orders


def sort_key_lists(v, key):
    """The lists under `key` (at any depth) sorted by id."""
    if isinstance(v, list):
        return [sort_key_lists(x, key) for x in v]
    if isinstance(v, dict):
        return {k: (by_id(sort_key_lists(x, key)) if k == key else sort_key_lists(x, key)) for k, x in v.items()}
    return v


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


def boundary_ties(page, key="updatedAt"):
    """The rows tied with the page's LAST row, replaced by their count. When a run of equal
    `key` values crosses the page boundary, which of them land on this page is up to MySQL's plan
    (the default sort has no tie-break), and Java's and Rust's plans differ. Everything before
    that run is still compared row by row, and the count still has to match."""
    if not isinstance(page, dict) or not isinstance(page.get("content"), list) or not page["content"]:
        return page
    rows = page["content"]
    last = rows[-1].get(key) if isinstance(rows[-1], dict) else None
    if last is None:
        return page
    kept = [r for r in rows if not (isinstance(r, dict) and r.get(key) == last)]
    return {**page, "content": kept + [{"tied_at_page_end": len(rows) - len(kept)}]}


def compare(name, method, path, headers=None, body=None, expected=None, keep=(), unordered=False, unordered_key=None, ties=False):
    """With `ties`, rows the default sort leaves tied are compared in id order (break_ties)."""
    j = call(JAVA, method, path, headers, body)
    r = call(RUST, method, path, headers, body)
    r, coded = error_parity.decode(j, r)
    jv, rv = parse(j[2]), parse(r[2])
    if ties:
        jv, rv = boundary_ties(break_ties(jv)), boundary_ties(break_ties(rv))
    jv, rv = strip(jv), strip(rv)
    problems = []
    orders = page_key_orders(jv, rv)
    jv, rv, reordered = page_order.align(jv, rv)
    if orders and orders[0] != orders[1] and not reordered:
        problems.append(f"page key order {orders[0]} vs {orders[1]}")
    if j[0] != r[0]:
        problems.append(f"status {j[0]} vs {r[0]}")
    if j[1].get("content-type") != r[1].get("content-type"):
        problems.append(f"content-type {j[1].get('content-type')!r} vs {r[1].get('content-type')!r}")
    leak_only = False
    if jv != rv:
        jl, rl = without_leaks(jv, set(keep)), without_leaks(rv, set(keep))
        if unordered_key and jl != rl and sort_key_lists(jl, unordered_key) == sort_key_lists(rl, unordered_key):
            jl = rl
            leak_only = None
        if jl == rl and leak_only is None:
            pass
        elif jl == rl:
            leak_only = True
        elif unordered and isinstance(jl, list) and isinstance(rl, list) and (
                sorted(map(json.dumps, jl)) == sorted(map(json.dumps, rl)) or by_id(jl) == by_id(rl)):
            leak_only = None
        else:
            problems.append(f"body differs: {diff(jl, rl)}")
    if problems and expected:
        report(name, "EXPECTED", expected)
    elif error_parity.is_problem(coded):
        report(name, "DIFF", error_parity.detail(coded, "; ".join(problems)))
    elif problems:
        report(name, "DIFF", "; ".join(problems))
    elif leak_only:
        report(name, "EXPECTED", "Java's cached object carries fields an earlier fill set on it")
    elif leak_only is None:
        report(name, "EXPECTED", "same items, another order (Java collects them with a concurrent flatMap)")
    elif reordered:
        report(name, "EXPECTED", error_parity.detail(coded, page_order.NOTE))
    else:
        v = error_parity.verdict("SAME", coded)
        report(name, v, error_parity.detail(coded) if v != "SAME" else "")
    return jv


def anonymous(host="localhost", client=None, app=None):
    h = {"X-Forwarded-Host": host, "X-Forwarded-Port": "8080", "X-Forwarded-Proto": "http"}
    if client:
        h["clientCode"] = client
    if app:
        h["appCode"] = app
    return h


def basic(user_id, client, app):
    h = anonymous(client=client, app=app)
    h["Authorization"] = "Basic " + base64.b64encode(f"{user_id}:{PASSWORD}".encode()).decode()
    return h


def q(params):
    return "?" + urllib.parse.urlencode(params, doseq=True)


def main():
    clients = sql("select c.ID, c.CODE from security_client c join security_client_hierarchy h on h.CLIENT_ID = c.ID "
                  "where c.ID in (1, 28, 29, 4445) or c.ID in (select CLIENT_ID from security_client_url) order by c.ID limit 12")
    client_ids = [int(c[0]) for c in clients]
    codes = [c[1] for c in clients]
    apps = [r[0] for r in sql("select APP_CODE from security_app order by ID limit 14")] + ["nope"]
    users = [int(r[0]) for r in sql("select ID from security_user where CLIENT_ID in (1, 28) order by ID limit 8")]
    signers = [(int(r[0]), r[1], r[2]) for r in sql(
        "select u.ID, c.CODE, min(a.APP_CODE) from security_user u join security_client c on c.ID = u.CLIENT_ID "
        "join security_profile_user pu on pu.USER_ID = u.ID join security_profile p on p.ID = pu.PROFILE_ID "
        "join security_app a on a.ID = p.APP_ID "
        f"where u.STATUS_CODE = 'ACTIVE' and u.PASSWORD = '{PASSWORD}' and u.PASSWORD_HASHED = 0 "
        "and coalesce(u.NO_FAILED_ATTEMPT, 0) = 0 and u.ID in (142, 110, 8, 221) group by u.ID, c.CODE order by u.ID")]
    hosts = [(re.sub(r"^https?://", "", r[0]).split(":")[0].split("/")[0], r[1]) for r in sql(
        "select u.URL_PATTERN, c.CODE from security_client_url u join security_client c on c.ID = u.CLIENT_ID "
        "where u.URL_TYPE = 'LIVE' order by u.ID desc limit 4")]
    sysh = anonymous()

    # ---- clients ----
    for code in codes + ["NOPE"]:
        compare(f"getClientByCode {code}", "GET", f"{P}/clients/internal/getClientByCode" + q({"clientCode": code}), sysh)
        compare(f"validateClientCode {code}", "GET", f"{P}/clients/internal/validateClientCode" + q({"clientCode": code}), sysh)
        compare(f"clientHierarchyCodes {code}", "GET", f"{P}/clients/internal/clientHierarchyCodes" + q({"clientCode": code}), sysh)
    for cid in client_ids + [999999]:
        compare(f"getClientById {cid}", "GET", f"{P}/clients/internal/getClientById" + q({"clientId": cid}), sysh)
        compare(f"clientHierarchy {cid}", "GET", f"{P}/clients/internal/clientHierarchy" + q({"clientId": cid}), sysh)
        compare(f"managingClientIds {cid}", "GET", f"{P}/clients/internal/managingClientIds" + q({"clientId": cid}), sysh)
        compare(f"clients/internal/{cid}", "GET", f"{P}/clients/internal/{cid}", sysh)
    fills = ["fetchUserCounts", "fetchOwners", "fetchManagingClient", "fetchApps", "fetchCreatedByUser", "fetchClientManagers"]
    counts = {"activeUsers", "inactiveUsers", "deletedUsers", "lockedUsers", "passwordExpiredUsers", "totalUsers"}
    kept = {"fetchUserCounts": counts, "fetchOwners": {"owners"}, "fetchManagingClient": {"managagingClient"}, "fetchApps": {"apps"},
            "fetchCreatedByUser": {"createdByUser"}, "fetchClientManagers": {"clientManagers"}}
    for f in fills:
        compare(f"clients/internal/28 {f}", "GET", f"{P}/clients/internal/28" + q({f: "true"}), sysh, keep=kept[f])
        # Java fills the managing client and the creator with a concurrent flatMap: any order.
        compare(f"clients batch {f}", "POST", f"{P}/clients/internal/batch" + q({f: "true"}), sysh, body=client_ids, keep=kept[f],
                unordered=f in ("fetchManagingClient", "fetchCreatedByUser"))
    compare("clients by ids", "GET", f"{P}/clients/internal" + q({"clientIds": client_ids[:4]}), sysh)
    compare("clients by ids, all fills", "GET", f"{P}/clients/internal" + q({"clientIds": client_ids[:4], **{f: "true" for f in fills}, "appCode": "leadzump"}), sysh,
            keep=set().union(*kept.values()), unordered=True)
    compare("clients by ids, comma list", "GET", f"{P}/clients/internal?clientIds=1,28", sysh)
    compare("clients by ids, empty", "GET", f"{P}/clients/internal?clientIds=", sysh)
    compare("clients by ids, missing", "GET", f"{P}/clients/internal", sysh)
    compare("activeClientCodes", "POST", f"{P}/clients/internal/activeClientCodes", sysh, body=codes + ["NOPE"])
    compare("activeClientCodes empty", "POST", f"{P}/clients/internal/activeClientCodes", sysh, body=[])
    compare("activeClientCodes no body", "POST", f"{P}/clients/internal/activeClientCodes", sysh)
    compare("clientIdsOfManagers", "POST", f"{P}/clients/internal/clientIdsOfManagers", sysh, body=users)
    compare("clientIdsOfManagers empty", "POST", f"{P}/clients/internal/clientIdsOfManagers", sysh, body=[])
    for u in users[:4]:
        compare(f"clientIdsOfManager {u}", "GET", f"{P}/clients/internal/clientIdsOfManager" + q({"managerId": u}), sysh)
    compare("denorm full", "POST", f"{P}/clients/internal/clients/denorm/full", sysh, body=client_ids + [999999])
    compare("denorm full empty", "POST", f"{P}/clients/internal/clients/denorm/full", sysh, body=[])
    for m in client_ids[:4]:
        for c in client_ids[:6]:
            compare(f"doesClientManageClient {m} {c}", "GET", f"{P}/clients/internal/doesClientManageClient" + q({"managingClientId": m, "clientId": c}), sysh)
    for m in codes[:3]:
        compare(f"doesClientManageClientCode {m}", "GET", f"{P}/clients/internal/doesClientManageClientCode" + q({"managingClientCode": m, "clientCode": codes[-1]}), sysh)
        compare(f"filterManagedClientCodes {m}", "POST", f"{P}/clients/internal/filterManagedClientCodes" + q({"managingClientCode": m}), sysh,
                body=codes + ["NOPE", codes[0]], unordered=True)
    compare("doesClientManageClientCode unknown", "GET", f"{P}/clients/internal/doesClientManageClientCode" + q({"managingClientCode": "NOPE", "clientCode": "SYSTEM"}), sysh)
    for u in users[:4]:
        for code in codes[:3]:
            compare(f"isUserPartOfHierarchy {u} {code}", "GET", f"{P}/clients/internal/isUserPartOfHierarchy" + q({"userId": u, "clientCode": code}), sysh)
    for u, code, app in signers:
        cid = int(sql(f"select CLIENT_ID from security_user where ID = {u}")[0][0])
        for target in client_ids[:5]:
            compare(f"isUserClientManageClient {u} -> {target}", "GET", f"{P}/clients/internal/isUserClientManageClient" +
                    q({"appCode": app, "userId": u, "userClientId": cid, "targetClientId": target}), sysh)
    compare("isUserClientManageClient no ids (Java NPE)", "GET", f"{P}/clients/internal/isUserClientManageClient", sysh)
    for host, _ in hosts + [("localhost", None), ("leadzump.local.modlix.com", None), ("nowhere.example", None)]:
        for port in ("8080", "443"):
            compare(f"getClientNAppCode {host}:{port}", "GET", f"{P}/clients/internal/getClientNAppCode" + q({"scheme": "https", "host": host, "port": port}), sysh)
            compare(f"getClientNAppCodeNType {host}:{port}", "GET", f"{P}/clients/internal/getClientNAppCodeNType" + q({"scheme": "https", "host": host, "port": port}), sysh)
    conditions = [
        {"field": "code", "operator": "STRING_LOOSE_EQUAL", "value": "FIN"},
        {"field": "typeCode", "value": "BUS"},
        {"field": "id", "operator": "IN", "value": ",".join(map(str, client_ids))},
        {"field": "user.emailId", "operator": "STRING_LOOSE_EQUAL", "value": "modlix"},
        {"field": "appCode", "value": "leadzump"},
        {"field": "appId", "operator": "IN", "multiValue": [2, 3], "negate": True},
        {"operator": "OR", "conditions": [{"field": "code", "value": "SYSTEM"}, {"field": "levelType", "value": "CUSTOMER"}]},
        {"fieldExpr": {"function": "LOWER", "fields": ["code"]}, "value": "fin"},
        {"field": "createdAt", "operator": "GREATER_THAN", "value": 1700000000},
    ]
    for i, c in enumerate(conditions):
        compare(f"clients query {i}", "POST", f"{P}/clients/internal/query", sysh, body={"size": 5, "condition": c,
                                                                                       "sort": [{"property": "id", "direction": "ASC"}]})
    compare("clients query, default sort, page 1", "POST", f"{P}/clients/internal/query", sysh, body={"page": 1, "size": 3}, ties=True)
    compare("clients query, fills", "POST", f"{P}/clients/internal/query" + q({"fetchOwners": "true", "fetchUserCounts": "true", "fetchManagingClient": "true"}),
            sysh, body={"size": 4, "condition": conditions[1], "sort": [{"property": "id"}]}, keep=counts | {"owners", "managagingClient"})
    compare("clients query, bad condition", "POST", f"{P}/clients/internal/query", sysh, body={"condition": {"value": 1}})
    compare("clients query, bad value (Java 500)", "POST", f"{P}/clients/internal/query", sysh, body={"condition": {"field": "id", "value": "x"}})
    for host, code in hosts[:2]:
        compare(f"clients query as anonymous on {host}", "POST", f"{P}/clients/internal/query", anonymous(host),
                body={"size": 5, "sort": [{"property": "id"}]})
        compare(f"clients by ids as anonymous on {host}", "GET", f"{P}/clients/internal" + q({"clientIds": client_ids[:4]}), anonymous(host))
    for u, code, app in signers:
        h = basic(u, code, app)
        compare(f"clients query as {u}", "POST", f"{P}/clients/internal/query", h, body={"size": 5, "sort": [{"property": "id"}]})
        compare(f"users query as {u}", "POST", f"{P}/users/internal/query", h, body={"size": 5, "sort": [{"property": "id"}]})

    # ---- applications ----
    for a in apps:
        compare(f"appCode {a}", "GET", f"{P}/applications/internal/appCode/{a}", sysh)
        compare(f"appStatus {a}", "GET", f"{P}/applications/internal/appStatus/{a}", sysh)
        compare(f"explicitInfo {a}", "GET", f"{P}/applications/internal/explicitInfo/{a}", sysh)
        compare(f"dependencies {a}", "GET", f"{P}/applications/internal/dependencies" + q({"appCode": a}), sysh)
        compare(f"writeAccessClientCodes {a}", "GET", f"{P}/applications/internal/writeAccessClientCodes" + q({"appCode": a}), sysh)
        for code in codes[:3]:
            compare(f"hasReadAccess {a} {code}", "GET", f"{P}/applications/internal/hasReadAccess" + q({"appCode": a, "clientCode": code}), sysh)
            compare(f"hasWriteAccess {a} {code}", "GET", f"{P}/applications/internal/hasWriteAccess" + q({"appCode": a, "clientCode": code}), sysh)
            compare(f"appInheritance {a} {code}", "GET", f"{P}/applications/internal/appInheritance" + q({"appCode": a, "urlClientCode": codes[1], "clientCode": code}), sysh)
    compare("appInheritance missing clientCode", "GET", f"{P}/applications/internal/appInheritance" + q({"appCode": "x", "urlClientCode": "y"}), sysh)

    # ---- users ----
    for u in users + [99999999]:
        compare(f"users/internal/{u}", "GET", f"{P}/users/internal/{u}", sysh)
    ukept = {"fetchClients": "client", "fetchManagingClients": "managingClient", "fetchCreatedBy": "createdByUser",
             "fetchDesignation": "designation", "fetchReportingTo": "reportingUser"}
    for f, k in ukept.items():
        compare(f"users/internal/{users[1]} {f}", "GET", f"{P}/users/internal/{users[1]}" + q({f: "true"}), sysh, keep={k})
        compare(f"users batch {f}", "POST", f"{P}/users/internal/batch" + q({f: "true"}), sysh, body=users, keep={k})
    # The profiles are read concurrently in Java (flatMap), so their order is whatever finished first.
    for u in users[:4]:
        for app in ("appbuilder", "leadzump"):
            compare(f"users fetchProfiles {u} {app}", "GET", f"{P}/users/internal/{u}" + q({"fetchProfiles": "true", "appCode": app}), sysh,
                    keep={"profiles"}, unordered_key="profiles")
    compare("users batch fetchProfiles", "POST", f"{P}/users/internal/batch" + q({"fetchProfiles": "true", "appCode": "leadzump"}), sysh,
            body=users, keep={"profiles"}, unordered_key="profiles")
    compare("users by ids", "GET", f"{P}/users/internal" + q({"userIds": users[:3]}), sysh)
    compare("users of clients batch", "POST", f"{P}/users/internal/clients/batch", sysh, body=client_ids[:3])
    compare("users of clients batch, appCode filter", "POST", f"{P}/users/internal/clients/batch" + q({"appCode": "leadzump", "fetchClients": "true"}),
            sysh, body=[28, 29], keep={"client"})
    for body in [{"appCode": "leadzump", "clientCode": "FIN"}, {"appCode": "leadzump", "clientId": 28, "userIds": users},
                 {"clientCode": "FIN"}, {"appCode": "appbuilder"}]:
        compare(f"notification {body}", "POST", f"{P}/users/internal/notification", sysh, body=body)
        compare(f"processor {body}", "POST", f"{P}/users/internal/processor", sysh, body=body)
    for a in ["leadzump", "appbuilder", "sitezump", "nope"]:
        for code in ["FIN", "SYSTEM", "FIN2", "NOPE"]:
            compare(f"adminEmails {a} {code}", "GET", f"{P}/users/internal/adminEmails", anonymous(client=code, app=a))
            compare(f"ownerEmails {a} {code}", "GET", f"{P}/users/internal/ownerEmails", anonymous(client=code, app=a))
    for u, code, app in signers:
        cid = int(sql(f"select CLIENT_ID from security_user where ID = {u}")[0][0])
        compare(f"sub-org {u}", "GET", f"{P}/users/internal/{u}/sub-org" + q({"appCode": app, "clientId": cid}), sysh)
    profiles = [r[0] for r in sql("select ID from security_profile order by ID limit 6")]
    for a in ["appbuilder", "leadzump", "nope"]:
        compare(f"profile users {a}", "GET", f"{P}/app/profiles/internal/users" + q({"profileIds": profiles}), anonymous(app=a))
    user_conditions = [
        {"field": "clientId", "value": 28},
        {"field": "profile.name", "operator": "STRING_LOOSE_EQUAL", "value": "Owner"},
        {"field": "appCode", "value": "leadzump"},
        {"field": "appId", "operator": "IN", "value": "2,3", "negate": True},
        {"operator": "AND", "conditions": [{"field": "statusCode", "value": "ACTIVE"}, {"field": "emailId", "operator": "LIKE", "value": "%modlix%"}]},
    ]
    for i, c in enumerate(user_conditions):
        compare(f"users query {i}", "POST", f"{P}/users/internal/query", sysh, body={"size": 5, "condition": c, "sort": [{"property": "id"}]})
    compare("users query, fills", "POST", f"{P}/users/internal/query" + q({"fetchClients": "true", "fetchCreatedBy": "true"}), sysh,
            body={"size": 3, "condition": user_conditions[0], "sort": [{"property": "id"}]}, keep={"client", "createdByUser"})
    for host, _ in hosts[:2]:
        compare(f"users by ids as anonymous on {host}", "GET", f"{P}/users/internal" + q({"userIds": users[:4]}), anonymous(host))

    # ---- client urls ----
    for a in ["appbuilder", "leadzump", "sitezump", "nope"]:
        for code in ["SYSTEM", "FIN", "NOPE"]:
            compare(f"app url {a} {code}", "GET", f"{P}/clienturls/internal/applications/property/url" + q({"appCode": a, "clientCode": code}), sysh)
        compare(f"app url {a} (URL client)", "GET", f"{P}/clienturls/internal/applications/property/url" + q({"appCode": a}), anonymous(client="FIN"))
    compare("app url blank app", "GET", f"{P}/clienturls/internal/applications/property/url" + q({"appCode": ""}), sysh)
    for host in ["t-0123456789abcdef0123456789abcdef.local.modlix.com", "app.local.modlix.com", ""]:
        compare(f"draft resolve {host!r}", "GET", f"{P}/clienturls/internal/draft/token/resolve" + q({"host": host, "appCode": "x"}), sysh)

    # ---- billing (read-only) ----
    for a in ["security.app.rent", "security.site.rent", "security.user", "ai.llm.tokens", "core.storage.rows", "nope"]:
        compare(f"instructions {a}", "GET", f"{P}/internal/billing/instructions" + q({"action": a}), sysh)
    suspended = sql("select cl.CODE, a.APP_CODE from security_wallet w join security_client cl on cl.ID = w.CLIENT_ID "
                    "join security_app a on a.ID = w.APP_ID where w.STATUS = 'SUSPENDED' limit 3")
    for code, app in suspended + [["FIN", "leadzump"], ["SYSTEM", "leadzump"], ["NOPE", "leadzump"], ["FIN", "nope"]]:
        compare(f"ai-allowed {app} {code}", "GET", f"{P}/internal/billing/ai-allowed" + q({"appCode": app, "clientCode": code}), sysh)
        compare(f"hosting {app} {code}", "GET", f"{P}/internal/billing/hosting" + q({"urlAppCode": app, "urlClientCode": code}), sysh)
    compare("serving-status", "GET", f"{P}/internal/billing/serving-status" + q({"urlAppCode": "appbuilder", "urlClientCode": "SYSTEM", "clientId": 1}), sysh,
            expected="Java cannot convert clientId: InternalBillingController has no ULong binder (DIFFERENCES.md)")
    compare("charge nothing", "POST", f"{P}/internal/billing/charge", sysh, body=[])
    compare("charge without a config", "POST", f"{P}/internal/billing/charge", sysh,
            body=[{"configClientId": 999999, "billedClientId": 1, "appId": 2, "actionKey": "security.app.rent", "quantity": 3, "date": 1792108800, "windowIndex": 1}])
    compare("charge-ai without a config", "POST", f"{P}/internal/billing/charge-ai", sysh,
            body={"appCode": "appbuilder", "clientCode": "SYSTEM", "model": "parity", "weightedTokens": 10, "requestId": "parity-no-config"})
    compare("charge-ai unknown client", "POST", f"{P}/internal/billing/charge-ai", sysh, body={"appCode": "leadzump", "clientCode": "NOPE"})
    compare("charge bad body", "POST", f"{P}/internal/billing/charge", sysh, body={"x": 1})

    # ---- cache and certificates ----
    sys_basic = basic(142, "SYSTEM", "appbuilder")
    for path in ["/internal/cache", "/internal/cache/stats", "/ssl/internal/certificates"]:
        compare(f"anonymous {path}", "GET", P + path, sysh)
    compare("evict a scratch cache", "DELETE", f"{P}/internal/cache/parityScratchCache", sys_basic)
    for name in ["internal/cache", "internal/cache/stats"]:
        j, r = call(JAVA, "GET", f"{P}/{name}", sys_basic), call(RUST, "GET", f"{P}/{name}", sys_basic)
        shape = j[0] == r[0] == 200 and type(parse(j[2])) is type(parse(r[2]))
        report(f"{name} (this instance's caches)", "EXPECTED" if shape else "DIFF",
               "each runtime lists its own caches; status and shape match" if shape else f"{j[0]} vs {r[0]}")
    jc, rc = call(JAVA, "GET", f"{P}/ssl/internal/certificates", sys_basic), call(RUST, "GET", f"{P}/ssl/internal/certificates", sys_basic)
    same = jc[0] == rc[0] and jc[2] == rc[2] and jc[1].get("etag") == rc[1].get("etag")
    report("certificates as SYSTEM (bytes, ETag)", "SAME" if same else "DIFF", "" if same else f"{jc[0]} vs {rc[0]}, etag {jc[1].get('etag')} vs {rc[1].get('etag')}")
    etag = (jc[1].get("etag") or "").strip('"')
    compare("certificates If-None-Match", "GET", f"{P}/ssl/internal/certificates", {**sys_basic, "If-None-Match": etag})
    for u, code, app in signers:
        if code != "SYSTEM":
            compare(f"certificates as {u} ({code})", "GET", f"{P}/ssl/internal/certificates", basic(u, code, app))
            break

    # ---- errors ----
    compare("405 on a GET route", "POST", f"{P}/clients/internal/getClientByCode", sysh, body={})
    compare("type mismatch in a path", "GET", f"{P}/users/internal/abc", sysh)
    compare("missing parameter", "GET", f"{P}/clients/internal/clientHierarchy", sysh)
    compare("unknown clientCode header", "GET", f"{P}/clients/internal/getClientByCode" + q({"clientCode": "SYSTEM"}), anonymous(client="NOSUCHCLIENT"))

    print(f"\nSAME {RESULTS['SAME']}  EXPECTED {RESULTS['EXPECTED']}  DIFF {RESULTS['DIFF']}")
    return 1 if RESULTS["DIFF"] else 0


if __name__ == "__main__":
    sys.exit(main())
