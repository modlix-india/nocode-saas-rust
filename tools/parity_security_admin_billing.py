#!/usr/bin/env python3
"""Sends the same billing requests to the Java security service and to security-admin and compares them.

Usage: parity_security_admin_billing.py [java_base] [rust_base]
       defaults: http://localhost:8001  http://localhost:8113

Local stack only. Requests go out one at a time (Java security must never see a burst).

Reads: billing configs and bundles, the serving bundles, the billing profile, quotes, invoices
(the seller's page, the buyer's page, the query form), wallets (the wallet, its status, ledger,
plan and the balance preview), for SYSTEM (142), an owner of FIN (110) and two callers with
nothing but Logged_IN on sitezump (8 on FIN, 11 on RAJAA). Signed-in callers use a bearer token
minted once per user on Java with the plain-text local password.

Money paths are only driven to their refusals, which come before anything is written or any
payment API is called: purchase/order with an unknown bundle or a client the caller does not
manage, repay of a PAID invoice (re-checked in the database right before the call), of another
client's invoice or an unknown one, credit with unknown codes or without the rights, the webhook
with an unknown payment or a wrong signature. Nothing reaches Razorpay and no wallet, invoice,
payment or real bundle changes.

Writes: billing configs and bundles on the scratch apps other parity scripts made
(`coreedparity` for Java, `shellparity` for Rust), INACTIVE and with every rate zero so no
metering or gate ever reads them, created, changed and deleted through each service's own API.

Compared: status, content type, and the body as JSON values (`exceptionId`, `stackTrace` and the
id in `message` ignored; ids and times of the scratch rows ignored). Gateway credentials are never
printed. Differences explained in crates/security/DIFFERENCES.md are reported as EXPECTED.
"""
import os
import json
import re
import subprocess
import sys
import time
import urllib.error
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
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8113"
P = "/api/security"
PASSWORD = "Pass@1234"
RESULTS = {"SAME": 0, "EXPECTED": 0, "DIFF": 0}
SECRET_KEYS = {"paymentGatewayConfig", "keyId", "keySecret", "webhookSecret"}
SCRATCH_JAVA_APP, SCRATCH_RUST_APP = "coreedparity", "shellparity"


def sql(query):
    out = subprocess.run(["mysql", "-h127.0.0.1", "-uroot", "security", "-N", "-B", "-e", query], env=MYSQL_ENV,
                         capture_output=True, text=True, check=True)
    return [line.split("\t") for line in out.stdout.splitlines() if line.strip()]


def connections_ok():
    """Waits while the local MySQL is busy (over 120 connections)."""
    for _ in range(30):
        n = int(sql("SHOW STATUS LIKE 'Threads_connected'")[0][1])
        if n <= 120:
            return
        print(f"... MySQL has {n} connections, waiting")
        time.sleep(10)
    sys.exit("MySQL stays above 120 connections; stopping")


def call(base, method, path, headers=None, body=None, raw=None):
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
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


def redact(v):
    if isinstance(v, dict):
        return {k: ("<redacted>" if k in SECRET_KEYS else redact(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [redact(x) for x in v]
    return v


def scrub(v, keys):
    """Drops the given properties at every depth (ids and times of scratch rows)."""
    if isinstance(v, dict):
        return {k: scrub(x, keys) for k, x in v.items() if k not in keys}
    if isinstance(v, list):
        return [scrub(x, keys) for x in v]
    return v


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
    return f"{path}: {json.dumps(redact(a))[:200]} vs {json.dumps(redact(b))[:200]}"


def judge(name, j, r, expected=None, ignore=()):
    r, coded = error_parity.decode(j, r)
    jv, rv = strip(parse(j[2])), strip(parse(r[2]))
    if ignore:
        jv, rv = scrub(jv, set(ignore)), scrub(rv, set(ignore))
    problems = []
    if j[0] != r[0]:
        problems.append(f"status {j[0]} vs {r[0]}")
    if j[1].get("content-type") != r[1].get("content-type"):
        problems.append(f"content-type {j[1].get('content-type')!r} vs {r[1].get('content-type')!r}")
    if jv != rv:
        problems.append(f"body differs: {diff(jv, rv)}")
    elif json.dumps(jv) != json.dumps(rv):
        problems.append("same values, another property order")
    elif not ignore and "exceptionId" not in (j[2][:40].decode(errors="replace")) and j[2] != r[2]:
        problems.append("same JSON, other bytes (Jackson's pretty printing or number text)")
    if problems and expected:
        report(name, "EXPECTED", expected)
    elif error_parity.is_problem(coded):
        report(name, "DIFF", error_parity.detail(coded, "; ".join(problems)))
    elif problems:
        report(name, "DIFF", "; ".join(problems))
    else:
        v = error_parity.verdict("SAME", coded)
        report(name, v, error_parity.detail(coded) if v != "SAME" else "")
    return jv, rv


def compare(name, method, path, headers=None, body=None, raw=None, expected=None, ignore=()):
    j = call(JAVA, method, path, headers, body, raw)
    r = call(RUST, method, path, headers, body, raw)
    return judge(name, j, r, expected, ignore)


def mint(user, client, app):
    """A bearer token from Java for a user whose stored password is the plain local one."""
    stored = sql(f"select PASSWORD, PASSWORD_HASHED, STATUS_CODE from security_user where ID = {int(user)}")
    if not stored or stored[0] != [PASSWORD, "0", "ACTIVE"]:
        sys.exit(f"user {user} does not have the plain local password; refusing to sign in")
    h = {"clientCode": client, "appCode": app, "X-Forwarded-Host": "localhost", "X-Forwarded-Port": "8080",
         "X-Forwarded-Proto": "http"}
    s, _, b = call(JAVA, "POST", f"{P}/authenticate", h, {"userId": user, "password": PASSWORD, "rememberMe": False})
    if s != 200:
        sys.exit(f"signing in {user} on Java answered {s}")
    return json.loads(b)["accessToken"]


def H(token, app=None, client=None):
    h = {"X-Forwarded-Host": "localhost", "X-Forwarded-Port": "8080", "X-Forwarded-Proto": "http"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    if app:
        h["appCode"] = app
    if client:
        h["clientCode"] = client
    return h


def reads(t):
    sys_t, owner_t, plain_t, indv_t = t["142"], t["110"], t["8"], t["11"]
    configs = [int(r[0]) for r in sql("select ID from security_app_billing_config order by ID")]
    bundles = [int(r[0]) for r in sql("select ID from security_app_billing_bundle order by ID")]
    apps = [r[0] for r in sql("select distinct a.APP_CODE from security_app_billing_config c join security_app a on a.ID = c.APP_ID")]
    app_ids = [int(r[0]) for r in sql("select distinct APP_ID from security_app_billing_config")]

    # ---- billing-configs ----
    for cid in configs + [999999]:
        compare(f"config {cid} SYSTEM", "GET", f"{P}/billing-configs/{cid}", H(sys_t, "appbuilder", "SYSTEM"))
        compare(f"config {cid} FIN owner", "GET", f"{P}/billing-configs/{cid}", H(owner_t, "sitezump", "FIN"))
    compare("config abc", "GET", f"{P}/billing-configs/abc", H(sys_t, "appbuilder", "SYSTEM"))
    for aid in app_ids + [999999]:
        compare(f"configs of app {aid} SYSTEM", "GET", f"{P}/billing-configs/app/{aid}", H(sys_t, "appbuilder", "SYSTEM"))
        compare(f"configs of app {aid} FIN", "GET", f"{P}/billing-configs/app/{aid}", H(owner_t, "sitezump", "FIN"))
    compare("configs list", "GET", f"{P}/billing-configs?size=2", H(sys_t, "appbuilder", "SYSTEM"))
    compare("configs query", "POST", f"{P}/billing-configs/query", H(sys_t, "appbuilder", "SYSTEM"), {"size": 2})
    compare("configs query bad body", "POST", f"{P}/billing-configs/query", H(sys_t, "appbuilder", "SYSTEM"), raw=b"[")
    compare("configs query no body", "POST", f"{P}/billing-configs/query", H(sys_t, "appbuilder", "SYSTEM"), raw=b"")
    compare("configs anonymous", "GET", f"{P}/billing-configs/1", H(None, "appbuilder", "SYSTEM"))
    compare("config create denied", "POST", f"{P}/billing-configs", H(plain_t, "sitezump", "FIN"), {"clientId": 28, "appId": 246})
    compare("config create bad enum", "POST", f"{P}/billing-configs", H(sys_t, "appbuilder", "SYSTEM"), {"status": "NOPE"})
    # Only while FIN (28) cannot edit sitezump (246): with edit access this would create a config.
    if not sql("select 1 from security_app_access where CLIENT_ID = 28 and APP_ID = 246 and EDIT_ACCESS = 1"):
        compare("config create without app access", "POST", f"{P}/billing-configs", H(owner_t, "sitezump", "FIN"),
                {"clientId": 28, "appId": 246, "status": "INACTIVE"})
    compare("config put missing", "PUT", f"{P}/billing-configs/999999", H(sys_t, "appbuilder", "SYSTEM"), {"status": "INACTIVE"})
    compare("config put denied", "PUT", f"{P}/billing-configs/1", H(plain_t, "sitezump", "FIN"), {"status": "INACTIVE"})
    compare("config put by a non-manager", "PUT", f"{P}/billing-configs/1", H(owner_t, "sitezump", "FIN"), {"status": "INACTIVE"})
    compare("config patch missing", "PATCH", f"{P}/billing-configs/999999", H(sys_t, "appbuilder", "SYSTEM"), {"status": "INACTIVE"})
    compare("config patch not visible", "PATCH", f"{P}/billing-configs/1", H(owner_t, "sitezump", "FIN"), {"status": "INACTIVE"})
    compare("config delete missing", "DELETE", f"{P}/billing-configs/999999", H(sys_t, "appbuilder", "SYSTEM"))
    compare("config delete denied", "DELETE", f"{P}/billing-configs/1", H(plain_t, "sitezump", "FIN"))
    compare("config delete by a non-manager", "DELETE", f"{P}/billing-configs/1", H(owner_t, "sitezump", "FIN"))

    # ---- billing-bundles ----
    for bid in bundles + [999999]:
        compare(f"bundle {bid}", "GET", f"{P}/billing-bundles/{bid}", H(plain_t, "sitezump", "FIN"))
    for cid in configs + [999999]:
        compare(f"bundles of config {cid}", "GET", f"{P}/billing-bundles/config/{cid}", H(indv_t, "sitezump", "RAJAA"))
    compare("bundles of config abc", "GET", f"{P}/billing-bundles/config/abc", H(sys_t, "appbuilder", "SYSTEM"))
    compare("bundles list", "GET", f"{P}/billing-bundles", H(sys_t, "appbuilder", "SYSTEM"))
    compare("bundles query", "POST", f"{P}/billing-bundles/query", H(sys_t, "appbuilder", "SYSTEM"), {})
    for app in apps + ["nope"]:
        for client in ["SYSTEM", "FIN", "RAJAA", "NOPE"]:
            compare(f"serving {app} {client}", "GET", f"{P}/billing-bundles/serving", H(None, app, client))
    compare("serving signed in", "GET", f"{P}/billing-bundles/serving", H(owner_t, "sitezump", "FIN"))
    compare("serving without app", "GET", f"{P}/billing-bundles/serving", H(None, None, "SYSTEM"))
    compare("serving without client", "GET", f"{P}/billing-bundles/serving", H(sys_t, "sitezump", None))
    compare("bundle create denied", "POST", f"{P}/billing-bundles", H(plain_t, "sitezump", "FIN"), {"billingConfigId": 1})
    compare("bundle create unknown config", "POST", f"{P}/billing-bundles", H(sys_t, "appbuilder", "SYSTEM"), {"billingConfigId": 999999})
    compare("bundle create no config", "POST", f"{P}/billing-bundles", H(sys_t, "appbuilder", "SYSTEM"), {"label": "x"})
    compare("bundle create by a non-manager", "POST", f"{P}/billing-bundles", H(owner_t, "sitezump", "FIN"), {"billingConfigId": 1, "label": "x"})
    compare("bundle put missing", "PUT", f"{P}/billing-bundles/999999", H(sys_t, "appbuilder", "SYSTEM"), {"label": "x"})
    compare("bundle put by a non-manager", "PUT", f"{P}/billing-bundles/1", H(owner_t, "sitezump", "FIN"), {"label": "x"})
    compare("bundle patch by a non-manager", "PATCH", f"{P}/billing-bundles/1", H(owner_t, "sitezump", "FIN"), {"label": "x"})
    compare("bundle patch bad value", "PATCH", f"{P}/billing-bundles/1", H(owner_t, "sitezump", "FIN"), {"tokens": "abc"})
    compare("bundle delete by a non-manager", "DELETE", f"{P}/billing-bundles/1", H(owner_t, "sitezump", "FIN"))

    # ---- billing-profile ----
    for app in apps + ["nope"]:
        compare(f"profile {app} SYSTEM", "GET", f"{P}/billing-profile", H(sys_t, app, "SYSTEM"))
        compare(f"profile {app} FIN owner", "GET", f"{P}/billing-profile", H(owner_t, app, "FIN"))
    compare("profile without app", "GET", f"{P}/billing-profile", H(sys_t, None, "SYSTEM"))
    compare("profile denied", "GET", f"{P}/billing-profile", H(plain_t, "sitezump", "FIN"))
    compare("profile put denied", "PUT", f"{P}/billing-profile", H(plain_t, "sitezump", "FIN"), {"legalName": "x"})
    compare("profile put unknown app", "PUT", f"{P}/billing-profile", H(sys_t, "nope", "SYSTEM"), {"legalName": "x"})
    compare("profile put bad body", "PUT", f"{P}/billing-profile", H(sys_t, "nope", "SYSTEM"), raw=b"{")

    # ---- quote ----
    for bid in bundles + [999999]:
        compare(f"quote {bid}", "POST", f"{P}/billing/quote", H(sys_t, "sitezump", "SYSTEM"), {"bundleId": bid})
    compare("quote string id and tokens", "POST", f"{P}/billing/quote", H(owner_t, "sitezump", "FIN"), {"bundleId": "3", "tokens": 12.5})
    compare("quote null id", "POST", f"{P}/billing/quote", H(sys_t, "sitezump", "SYSTEM"), {})
    compare("quote negative id", "POST", f"{P}/billing/quote", H(sys_t, "sitezump", "SYSTEM"), {"bundleId": -1})
    compare("quote not json", "POST", f"{P}/billing/quote", H(sys_t, "sitezump", "SYSTEM"), raw=b"x")
    compare("quote no body", "POST", f"{P}/billing/quote", H(sys_t, "sitezump", "SYSTEM"), raw=b"")
    compare("quote denied", "POST", f"{P}/billing/quote", H(plain_t, "sitezump", "FIN"), {"bundleId": 1})

    # ---- purchase / order / repay: refusals only ----
    for route in ("purchase", "purchase/order"):
        compare(f"{route} unknown bundle", "POST", f"{P}/billing/{route}", H(sys_t, "sitezump", "SYSTEM"), {"bundleId": 999999})
        compare(f"{route} for an unmanaged client", "POST", f"{P}/billing/{route}", H(owner_t, "sitezump", "FIN"), {"bundleId": 1, "clientId": 1})
        compare(f"{route} denied", "POST", f"{P}/billing/{route}", H(plain_t, "sitezump", "FIN"), {"bundleId": 1})
        compare(f"{route} bad body", "POST", f"{P}/billing/{route}", H(sys_t, "sitezump", "SYSTEM"), {"bundleId": "x"})
    paid = sql("select ID from security_invoice where STATUS = 'PAID' order by ID limit 2")
    for (iid,) in paid:
        # Re-checked right before each call: a PENDING or FAILED invoice would start a Razorpay order.
        if sql(f"select STATUS from security_invoice where ID = {int(iid)}")[0][0] == "PAID":
            compare(f"repay PAID invoice {iid}", "POST", f"{P}/billing/repay", H(sys_t, "sitezump", "SYSTEM"), {"invoiceId": int(iid)})
    others = sql("select ID from security_invoice where CLIENT_ID <> 28 order by ID limit 1")
    for (iid,) in others:
        compare(f"repay another client's invoice {iid}", "POST", f"{P}/billing/repay", H(owner_t, "sitezump", "FIN"), {"invoiceId": int(iid)})
    compare("repay unknown invoice", "POST", f"{P}/billing/repay", H(sys_t, "sitezump", "SYSTEM"), {"invoiceId": 999999})
    compare("repay null invoice", "POST", f"{P}/billing/repay", H(sys_t, "sitezump", "SYSTEM"), {})
    compare("repay denied", "POST", f"{P}/billing/repay", H(plain_t, "sitezump", "FIN"), {"invoiceId": 1})

    # ---- webhook: no-ops only ----
    order = sql("select GATEWAY_ORDER_ID from security_payment where GATEWAY_ORDER_ID is not null order by ID limit 1")
    hooks = [
        ("unparseable", b"not-json", None),
        ("array", b"[1]", "x"),
        ("unknown event", json.dumps({"event": "refund.created", "payload": {}}).encode(), "x"),
        ("no entity", json.dumps({"event": "payment_link.paid", "payload": {}}).encode(), "x"),
        ("unknown link", json.dumps({"event": "payment_link.paid", "payload": {"payment_link": {"entity": {"id": "plink_nope_parity"}}}}).encode(), "x"),
        ("blank order", json.dumps({"event": "order.paid", "payload": {"order": {"entity": {"id": " "}}}}).encode(), "x"),
    ]
    if order:
        body = {"event": "order.paid", "payload": {"order": {"entity": {"id": order[0][0]}}, "payment": {"entity": {"id": "pay_parity"}}}}
        hooks.append(("known order, wrong signature", json.dumps(body).encode(), "deadbeef"))
        hooks.append(("known order, no signature", json.dumps(body).encode(), None))
    for name, raw, sig in hooks:
        h = H(None)
        if sig:
            h["X-Razorpay-Signature"] = sig
        compare(f"webhook {name}", "POST", f"{P}/billing/razorpay/webhook", h, raw=raw)
    compare("webhook no body", "POST", f"{P}/billing/razorpay/webhook", H(None), raw=b"")

    # ---- invoices ----
    for tok, app, client, who in [(sys_t, "sitezump", "SYSTEM", "SYSTEM"), (sys_t, "marketingai", "SYSTEM", "SYSTEM"),
                                  (owner_t, "sitezump", "SYSTEM", "FIN owner"), (owner_t, "sitezump", "FIN", "FIN owner"),
                                  (sys_t, "nope", "SYSTEM", "SYSTEM")]:
        compare(f"invoices {app} {client} as {who}", "GET", f"{P}/invoices?size=3&sort=id,desc", H(tok, app, client))
        compare(f"invoices/my {app} as {who}", "GET", f"{P}/invoices/my?size=3&sort=id,desc", H(tok, app, client))
    compare("invoices PAID filter", "GET", f"{P}/invoices?size=2&status=PAID&sort=id,desc", H(sys_t, "sitezump", "SYSTEM"))
    compare("invoices two statuses", "GET", f"{P}/invoices?size=2&status=PAID&status=FAILED&sort=totalAmount", H(sys_t, "sitezump", "SYSTEM"))
    compare("invoices amount filter", "GET", f"{P}/invoices?size=2&totalAmount=1178.82&sort=id", H(sys_t, "sitezump", "SYSTEM"))
    compare("invoices page 2", "GET", f"{P}/invoices?size=5&page=2&sort=id", H(sys_t, "sitezump", "SYSTEM"))
    compare("invoices unsorted", "GET", f"{P}/invoices?size=4", H(sys_t, "sitezump", "SYSTEM"))
    compare("invoices bad filter", "GET", f"{P}/invoices?id=abc", H(sys_t, "sitezump", "SYSTEM"))
    compare("invoices without client", "GET", f"{P}/invoices", H(sys_t, "sitezump", None))
    compare("invoices denied", "GET", f"{P}/invoices", H(plain_t, "sitezump", "FIN"))
    compare("invoices/my plain caller", "GET", f"{P}/invoices/my", H(plain_t, "sitezump", "FIN"))
    compare("invoices/my without app", "GET", f"{P}/invoices/my", H(sys_t, None, "SYSTEM"))
    for body in [{"size": 2, "condition": {"field": "status", "value": "PAID"}, "sort": [{"property": "id", "direction": "DESC"}]},
                 {"page": 1, "size": 3},
                 {"condition": {"operator": "OR", "conditions": [{"field": "status", "value": "FAILED"}, {"field": "bundleId", "value": 3}]}},
                 {"size": 0}]:
        compare(f"invoices query {json.dumps(body)[:60]}", "POST", f"{P}/invoices/query", H(sys_t, "sitezump", "SYSTEM"), body)
    compare("invoices query denied", "POST", f"{P}/invoices/query", H(plain_t, "sitezump", "FIN"), {})
    first = sql("select ID from security_invoice order by ID limit 1")[0][0]
    fixed = "Java's InvoiceController has no ULong binder: every id is \"Type mismatch.\""
    compare(f"invoice {first}", "GET", f"{P}/invoices/{first}", H(sys_t, "sitezump", "SYSTEM"), expected=fixed)
    compare("invoice unknown", "GET", f"{P}/invoices/999999", H(sys_t, "sitezump", "SYSTEM"), expected=fixed)
    compare("invoice abc", "GET", f"{P}/invoices/abc", H(sys_t, "sitezump", "SYSTEM"))
    compare("invoice documents unknown", "GET", f"{P}/invoices/999999/documents", H(sys_t, "sitezump", "SYSTEM"), expected=fixed)
    compare("invoice documents of another party", "GET", f"{P}/invoices/{first}/documents", H(indv_t, "sitezump", "RAJAA"), expected=fixed)

    # ---- wallets ----
    for tok, app, client, who in [(sys_t, "sitezump", "SYSTEM", "SYSTEM"), (sys_t, "sitezump", "FIN", "SYSTEM"),
                                  (sys_t, "leadzump", "FIN", "SYSTEM"), (owner_t, "sitezump", "FIN", "FIN owner"),
                                  (owner_t, "sitezump", "SYSTEM", "FIN owner"), (sys_t, "nope", "SYSTEM", "SYSTEM"),
                                  (sys_t, "sitezump", "NOPE", "SYSTEM")]:
        compare(f"wallet {app} {client} as {who}", "GET", f"{P}/wallets", H(tok, app, client))
    for tok, app, client, who in [(sys_t, "sitezump", "SYSTEM", "SYSTEM"), (owner_t, "sitezump", "FIN", "FIN owner"),
                                  (plain_t, "sitezump", "FIN", "FIN plain"), (indv_t, "sitezump", "RAJAA", "RAJAA"),
                                  (sys_t, "marketingai", "SYSTEM", "SYSTEM"), (sys_t, "nope", "SYSTEM", "SYSTEM")]:
        compare(f"wallet status {app} as {who}", "GET", f"{P}/wallets/status", H(tok, app, client))
        compare(f"wallet plan {app} as {who}", "GET", f"{P}/wallets/plan", H(tok, app, client))
        compare(f"wallet ledger {app} as {who}", "GET", f"{P}/wallets/transactions?size=3&sort=id,asc", H(tok, app, client))
    compare("wallet ledger unsorted", "GET", f"{P}/wallets/transactions?size=2", H(sys_t, "sitezump", "SYSTEM"))
    compare("wallet ledger by created", "GET", f"{P}/wallets/transactions?size=2&page=1&sort=createdAt,desc&sort=id", H(sys_t, "sitezump", "SYSTEM"))
    compare("wallet without app", "GET", f"{P}/wallets", H(sys_t, None, "SYSTEM"))
    compare("wallet without client", "GET", f"{P}/wallets", H(sys_t, "sitezump", None))
    compare("wallet denied", "GET", f"{P}/wallets", H(plain_t, "sitezump", "FIN"))
    compare("wallet status without app", "GET", f"{P}/wallets/status", H(sys_t, None, "SYSTEM"))
    lookups = [("sitezump", "SYSTEM", "FIN"), ("sitezump", "SYSTEM", "SYSTEM"), ("nope", "SYSTEM", "FIN"),
               ("sitezump", "NOPE", "FIN"), ("sitezump", "SYSTEM", "NOPE"), ("leadzump", "SYSTEM", "RAJAA")]
    for app, url_client, client in lookups:
        q = f"?appCode={app}&urlClientCode={url_client}&clientCode={client}"
        compare(f"lookup {app} {url_client} {client}", "GET", f"{P}/wallets/lookup{q}", H(sys_t, "appbuilder", "SYSTEM"))
        compare(f"lookup {app} {url_client} {client} as FIN owner", "GET", f"{P}/wallets/lookup{q}", H(owner_t, "sitezump", "FIN"))
    compare("lookup missing client", "GET", f"{P}/wallets/lookup?appCode=sitezump&urlClientCode=SYSTEM", H(sys_t, "appbuilder", "SYSTEM"))
    compare("lookup denied", "GET", f"{P}/wallets/lookup?appCode=sitezump&urlClientCode=SYSTEM&clientCode=FIN", H(plain_t, "sitezump", "FIN"))
    credits = [({"appCode": "nope", "urlClientCode": "SYSTEM", "clientCode": "FIN", "tokens": 1, "reason": "parity"}, sys_t, "unknown app"),
               ({"appCode": "sitezump", "urlClientCode": "NOPE", "clientCode": "FIN", "tokens": 1, "reason": "parity"}, sys_t, "unknown URL client"),
               ({"appCode": "sitezump", "urlClientCode": "SYSTEM", "clientCode": "NOPE", "tokens": 1, "reason": "parity"}, sys_t, "unknown client"),
               ({"appCode": "sitezump", "urlClientCode": "SYSTEM", "clientCode": "SYSTEM", "tokens": 1, "reason": "parity"}, owner_t, "by a FIN owner"),
               ({"appCode": "sitezump", "urlClientCode": "FIN", "clientCode": "SYSTEM", "tokens": 1, "reason": "parity"}, plain_t, "denied"),
               ({"tokens": "x"}, sys_t, "bad body")]
    for body, tok, name in credits:
        compare(f"credit {name}", "POST", f"{P}/wallets/credit", H(tok, "sitezump", "FIN"), body)
    compare("credit no app code", "POST", f"{P}/wallets/credit", H(sys_t, "sitezump", "SYSTEM"), {"tokens": 1})
    wid = sql("select ID from security_wallet order by ID limit 1")[0][0]
    # security-admin answers as Java ("Type mismatch." for every id) while `[billing]
    # serve_wallet_adjust` is off, as configured locally; with it on these would change balances.
    compare("adjust abc", "POST", f"{P}/wallets/abc/adjust?tokens=1&reason=parity", H(sys_t, "sitezump", "SYSTEM"))
    compare("adjust denied", "POST", f"{P}/wallets/{wid}/adjust?tokens=1&reason=parity", H(plain_t, "sitezump", "FIN"))
    compare("adjust missing tokens", "POST", f"{P}/wallets/{wid}/adjust?reason=parity", H(sys_t, "sitezump", "SYSTEM"))
    compare("adjust unknown wallet", "POST", f"{P}/wallets/999999999/adjust?tokens=1&reason=parity", H(sys_t, "sitezump", "SYSTEM"))
    compare("adjust anonymous", "POST", f"{P}/wallets/{wid}/adjust?tokens=1&reason=parity", H(None, "sitezump", "SYSTEM"))


SCRATCH_TIMES = ("id", "createdAt", "updatedAt", "appId", "billingConfigId")


def scratch_cleanup(t):
    """Deletes, through each service's API, the scratch configs a previous run may have left."""
    for base, app in ((JAVA, SCRATCH_JAVA_APP), (RUST, SCRATCH_RUST_APP)):
        for (cid,) in sql(f"select c.ID from security_app_billing_config c join security_app a on a.ID = c.APP_ID where a.APP_CODE = '{app}'"):
            call(base, "DELETE", f"{P}/billing-configs/{cid}", H(t["142"], "appbuilder", "SYSTEM"))


def writes(t):
    sys_t = t["142"]
    apps = {code: int(i) for i, code in sql(f"select ID, APP_CODE from security_app where APP_CODE in ('{SCRATCH_JAVA_APP}', '{SCRATCH_RUST_APP}') and CLIENT_ID = 1")}
    if len(apps) != 2:
        report("scratch writes", "DIFF", "the scratch apps are missing; writes not compared")
        return
    scratch_cleanup(t)
    h = H(sys_t, "appbuilder", "SYSTEM")
    gw = {"keyId": "rzp_test_parity", "keySecret": "parity-secret", "webhookSecret": "parity-webhook"}
    cfg = lambda app: {"clientId": 1, "appId": apps[app], "status": "INACTIVE", "gstPercentage": 18, "lowBalanceThreshold": "100.50",
                       "paymentGatewayConfig": gw, "sellerLegalName": "Parity Seller", "suspendAppCode": ""}
    j = call(JAVA, "POST", f"{P}/billing-configs", h, cfg(SCRATCH_JAVA_APP))
    r = call(RUST, "POST", f"{P}/billing-configs", h, cfg(SCRATCH_RUST_APP))
    judge("scratch config create", j, r, ignore=SCRATCH_TIMES)
    jv, rv = parse(j[2]), parse(r[2])
    if not (isinstance(jv, dict) and isinstance(rv, dict) and "id" in jv and "id" in rv):
        scratch_cleanup(t)
        return
    jc, rc = jv["id"], rv["id"]
    try:
        judge("scratch config duplicate", call(JAVA, "POST", f"{P}/billing-configs", h, cfg(SCRATCH_JAVA_APP)),
              call(RUST, "POST", f"{P}/billing-configs", h, cfg(SCRATCH_RUST_APP)),
              expected="a duplicate (client, app) is a 500 either way; Java's message carries jOOQ's SQL text")
        judge("scratch config read", call(JAVA, "GET", f"{P}/billing-configs/{jc}", h), call(RUST, "GET", f"{P}/billing-configs/{rc}", h), ignore=SCRATCH_TIMES)
        put = {"status": "INACTIVE", "freeApps": 2, "sellerGstin": "29PARITY", "paymentGatewayConfig": {"keyId": "rzp_test_parity2"}, "clientId": 28}
        judge("scratch config put", call(JAVA, "PUT", f"{P}/billing-configs/{jc}", h, put), call(RUST, "PUT", f"{P}/billing-configs/{rc}", h, put), ignore=SCRATCH_TIMES)
        patch = {"sellerAddress": "Somewhere", "Status": "INACTIVE", "appId": 2, "unknown": 1, "lowBalanceThreshold": 5.25}
        judge("scratch config patch", call(JAVA, "PATCH", f"{P}/billing-configs/{jc}", h, patch), call(RUST, "PATCH", f"{P}/billing-configs/{rc}", h, patch), ignore=SCRATCH_TIMES)
        judge("scratch config patch bad value", call(JAVA, "PATCH", f"{P}/billing-configs/{jc}", h, {"freeApps": "x"}),
              call(RUST, "PATCH", f"{P}/billing-configs/{rc}", h, {"freeApps": "x"}))
        bundle = lambda c: {"billingConfigId": c, "label": "Parity", "bundleType": "CUSTOM", "pricePerToken": "0.5", "minTokens": 10, "maxTokens": 100,
                            "status": "INACTIVE", "displayOrder": 3}
        jb, rb = call(JAVA, "POST", f"{P}/billing-bundles", h, bundle(jc)), call(RUST, "POST", f"{P}/billing-bundles", h, bundle(rc))
        judge("scratch bundle create", jb, rb, ignore=SCRATCH_TIMES)
        jbi, rbi = parse(jb[2]).get("id"), parse(rb[2]).get("id")
        judge("scratch bundles of config", call(JAVA, "GET", f"{P}/billing-bundles/config/{jc}", h), call(RUST, "GET", f"{P}/billing-bundles/config/{rc}", h), ignore=SCRATCH_TIMES)
        for tokens in (50, 5, 500, None, 0):
            body = {"bundleId": jbi} if tokens is None else {"bundleId": jbi, "tokens": tokens}
            rbody = dict(body, bundleId=rbi)
            judge(f"scratch quote CUSTOM {tokens}", call(JAVA, "POST", f"{P}/billing/quote", h, body), call(RUST, "POST", f"{P}/billing/quote", h, rbody), ignore=SCRATCH_TIMES + ("bundleId",))
        put = {"label": "Parity 2", "bundleType": "FIXED", "tokens": 1000, "price": 900, "currency": "USD", "status": "INACTIVE", "billingConfigId": 1}
        judge("scratch bundle put", call(JAVA, "PUT", f"{P}/billing-bundles/{jbi}", h, put), call(RUST, "PUT", f"{P}/billing-bundles/{rbi}", h, put), ignore=SCRATCH_TIMES)
        judge("scratch quote FIXED", call(JAVA, "POST", f"{P}/billing/quote", h, {"bundleId": jbi}), call(RUST, "POST", f"{P}/billing/quote", h, {"bundleId": rbi}), ignore=SCRATCH_TIMES + ("bundleId",))
        judge("scratch bundle put without label", call(JAVA, "PUT", f"{P}/billing-bundles/{jbi}", h, {"price": 10}),
              call(RUST, "PUT", f"{P}/billing-bundles/{rbi}", h, {"price": 10}), ignore=SCRATCH_TIMES)
        judge("scratch bundle patch", call(JAVA, "PATCH", f"{P}/billing-bundles/{jbi}", h, {"displayOrder": "7", "minTokens": None, "label": "P3"}),
              call(RUST, "PATCH", f"{P}/billing-bundles/{rbi}", h, {"displayOrder": "7", "minTokens": None, "label": "P3"}), ignore=SCRATCH_TIMES)
        judge("scratch serving (INACTIVE config's bundles are not served)", call(JAVA, "GET", f"{P}/billing-bundles/serving", H(None, SCRATCH_JAVA_APP, "SYSTEM")),
              call(RUST, "GET", f"{P}/billing-bundles/serving", H(None, SCRATCH_RUST_APP, "SYSTEM")), ignore=SCRATCH_TIMES)
        judge("scratch bundle delete", call(JAVA, "DELETE", f"{P}/billing-bundles/{jbi}", h), call(RUST, "DELETE", f"{P}/billing-bundles/{rbi}", h))
        judge("scratch bundle gone", call(JAVA, "GET", f"{P}/billing-bundles/{jbi}", h), call(RUST, "GET", f"{P}/billing-bundles/{rbi}", h),
              ignore=("message", "debugMessage"))
    finally:
        judge("scratch config delete", call(JAVA, "DELETE", f"{P}/billing-configs/{jc}", h), call(RUST, "DELETE", f"{P}/billing-configs/{rc}", h))
    judge("scratch config gone", call(JAVA, "GET", f"{P}/billing-configs/{jc}", h), call(RUST, "GET", f"{P}/billing-configs/{rc}", h),
          ignore=("message", "debugMessage"))


def main():
    connections_ok()
    for base in (JAVA, RUST):
        s, _, _ = call(base, "GET", "/actuator/health" if base == JAVA else "/healthz")
        if s == 0:
            sys.exit(f"{base} does not answer")
    t = {"142": mint(142, "SYSTEM", "appbuilder"), "110": mint(110, "FIN", "sitezump"), "8": mint(8, "FIN", "sitezump"),
         "11": mint(11, "RAJAA", "sitezump")}
    reads(t)
    connections_ok()
    if "--no-writes" not in sys.argv:
        writes(t)
    print(f"\nSAME {RESULTS['SAME']}  EXPECTED {RESULTS['EXPECTED']}  DIFF {RESULTS['DIFF']}")
    return 1 if RESULTS["DIFF"] else 0


if __name__ == "__main__":
    sys.exit(main())
