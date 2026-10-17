#!/usr/bin/env python3
"""Parity: Java notification against Rust notification on the local stack.

The same requests go to both (Java on --java, default :8007; Rust on --rust, default :8114) and
are compared on status, the headers that matter, and the body. Every case ends SAME, EXPECTED
(a difference listed in crates/notification/DIFFERENCES.md), or DIFF.

What is covered:
  1. every route of NotificationController, signed in and anonymous, with Spring's answers
     around them (OPTIONS, CORS preflight, unsupported methods, unmapped paths, binding errors);
  2. preferences: create, read back, update, delete, the empty-body and null cases, the userId
     checks (security answers), on an app code made up for this run and removed through the API;
  3. the SSE stream: headers, the init event and the 15 s keepalive on both sides;
  4. delivery (Rust only): a message published to Rust's SCRATCH exchange reaches an open stream
     as the `notification` event (compared with the frames Java sent on 2026-10-16), the mail goes
     to an SMTP stub in this script, and the list and count routes see the row.

Java's in-app delivery is not run live: its jOOQ code names the `notification` schema in every
statement, so a Java instance always writes the real local notification_inapp table.

Data: the scratch core definitions (a NOTIFICATION and a MAIL connection, a notification, in the
monkbars app) are created through Java core's API and deleted at the end; the one mail goes to
a SendGrid stand-in in this script, never to SendGrid; preferences are made
for a run-specific app code and deleted through the services' API. Nothing else is written.

Errors are compared by status and code (tools/error_parity.py): a coded Rust error whose code
stands for Java's text is put back into Java's shape (message, empty body, content type) before
the comparison, and the case is EXPECTED when everything else matches. A request Java answers
with its catch-all 500 and Rust with a coded 4xx is EXPECTED as N14.

Usage:
  Rust runs on a scratch schema and scratch queue, its SendGrid URL on this script's stub:
    MODLIX__DATABASE__DATABASE=RUSTTEST_notification_parity MODLIX__NOTIFICATIONS__QUEUES=rs_scratch_notif_rust \
    MODLIX__NOTIFICATIONS__EXCHANGE=rs_scratch_notif_rust_x MODLIX__NOTIFICATIONS__DECLARE=true \
    MODLIX__EMAIL__SENDGRID_URL=http://127.0.0.1:18114/v3/mail/send tools/run-local.sh notification --release
  tools/parity_notification.py --rust-exchange rs_scratch_notif_rust_x --rust-queue rs_scratch_notif_rust
  (--skip-keepalive saves the 16 s keepalive wait; --verbose prints every case)
"""

import argparse
import base64
import http.client
import json
import os
import re
import http.server
import socket
import sys
import threading
import time
import urllib.parse
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import error_parity  # noqa: E402

N14 = "N14: a request the service cannot read is a 4xx naming the problem (Java: the catch-all 500)"

BASIC = "Basic " + base64.b64encode(b"142:Pass@1234").decode()
SIGNED_IN = {"Authorization": BASIC, "clientCode": "SYSTEM", "appCode": "appbuilder"}
CORE = "http://localhost:8005"
MQ_API = "http://localhost:15672"
MQ_AUTH = "Basic " + base64.b64encode(b"guest:guest").decode()

COMPARED_HEADERS = [
    "content-type", "cache-control", "pragma", "expires", "x-content-type-options", "x-xss-protection",
    "x-frame-options", "content-security-policy", "referrer-policy", "allow", "accept-patch",
    "access-control-allow-origin", "access-control-allow-methods", "access-control-allow-headers",
    "access-control-max-age", "x-accel-buffering", "vary", "www-authenticate",
]

# The frames Java sent on 2026-10-16 for one in-app notification (ids normalised).
JAVA_SSE_FIXTURE = (
    'event:init\ndata:connected\nid:<uuid>\nretry:5000\n\n'
    'event:notification\ndata:{\ndata:  "id" : <id>,\ndata:  "userId" : 142,\ndata:  "appCode" : "monkbars",\n'
    'data:  "notificationName" : "rsNotifParity",\ndata:  "title" : "Héllo Ann",\n'
    'data:  "message" : "Line one\\nline \\"two\\" 3",\ndata:  "mimeUrl" : "api/files/x.svg",\n'
    'data:  "notificationType" : "ALERT"\ndata:}\nid:<uuid>\nretry:5000\n\n'
)
# The list item Java answered for the same row.
JAVA_LIST_ITEM_KEYS = ["id", "title", "message", "createdAt", "mimeUrl", "notificationCategory", "url"]


class Resp:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers  # lower-case name -> [values]
        self.body = body

    def text(self):
        return self.body.decode("utf-8", "replace")

    def json(self):
        try:
            return json.loads(self.body)
        except Exception:
            return None

    def h(self, name):
        v = self.headers.get(name)
        return ", ".join(v) if v else None


def call(base, method, path, body=None, headers=None, timeout=30):
    """One request; a timeout is retried once (the local Java services stall now and then)."""
    try:
        return call_once(base, method, path, body, headers, timeout)
    except TimeoutError:
        print(f"   (timeout on {base} {method} {path}, retrying once)")
        return call_once(base, method, path, body, headers, timeout)


def call_once(base, method, path, body, headers, timeout):
    u = urllib.parse.urlparse(base)
    conn = http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)
    data = None
    if body is not None:
        data = body.encode() if isinstance(body, str) else body
    hs = dict(headers or {})
    conn.request(method, path, body=data, headers=hs)
    r = conn.getresponse()
    raw = r.read() if method != "HEAD" else b""
    headers_out = {}
    for k, v in r.getheaders():
        headers_out.setdefault(k.lower(), []).append(v)
    conn.close()
    return Resp(r.status, headers_out, raw)


UNKNOWN = re.compile(r"^Please try again\. A server error - \S+ $")


def normalise(r):
    """What is compared: status, the headers that matter, and the body (error ids masked)."""
    j = r.json()
    if isinstance(j, dict) and "exceptionId" in j:
        msg = j.get("message", "")
        if UNKNOWN.match(msg):
            msg = "Please try again. A server error - <id> "
        # Security's relayed message carries its own id, without the trailing space.
        msg = re.sub(r"A server error - \d{4}-\d{2}-\d{2}-[0-9a-f]+$", "A server error - <id>", msg)
        body = ("error", msg)
    elif j is not None and r.body.strip().startswith((b"{", b"[")):
        body = ("json", json.dumps(j, sort_keys=True))
    else:
        body = ("raw", r.text())
    hs = {h: r.h(h) for h in COMPARED_HEADERS}
    if hs.get("allow"):
        # Spring builds Allow from the handler methods in reflection order, which differs per JVM run.
        hs["allow"] = ",".join(sorted(hs["allow"].split(",")))
    return {"status": r.status, "headers": hs, "body": body}


def coded_as_java(j, r):
    """Rust's answer with a coded error put back into Java's shape when its code stands for
    Java's text (error_parity.decode), and the note on the code."""
    (rs, rh, rb), note = error_parity.decode((j.status, j.h("content-type"), j.body), (r.status, r.h("content-type"), r.body))
    if not note or error_parity.is_problem(note):
        return r, note
    headers = {k: v for k, v in r.headers.items() if k not in ("content-type", "content-length")}
    if rh:
        headers["content-type"] = [rh]
    return Resp(rs, headers, rb), note


def page_order(r):
    j = r.json()
    return list(j.keys()) if isinstance(j, dict) else None


class Report:
    def __init__(self, verbose):
        self.rows = []
        self.verbose = verbose

    def add(self, name, verdict, detail=""):
        self.rows.append((name, verdict, detail))
        if self.verbose or verdict == "DIFF":
            print(f"{verdict:9} {name}" + (f"\n          {detail}" if detail else ""))

    def compare(self, name, j, r, expected=None, exact_body=False):
        r, coded = coded_as_java(j, r)
        a, b = normalise(j), normalise(r)
        diffs = []
        if error_parity.is_problem(coded):
            diffs.append(coded)
        if a["status"] != b["status"]:
            diffs.append(f"status java={a['status']} rust={b['status']}")
        for h in COMPARED_HEADERS:
            if a["headers"][h] != b["headers"][h]:
                diffs.append(f"{h}: java={a['headers'][h]!r} rust={b['headers'][h]!r}")
        if a["body"] != b["body"]:
            diffs.append(f"body java={a['body'][1][:300]!r} rust={b['body'][1][:300]!r}")
        if exact_body and j.status == 200 and j.body != r.body:
            diffs.append(f"bytes java={j.text()[:300]!r} rust={r.text()[:300]!r}")
        status_only = diffs == [f"status java={a['status']} rust={b['status']}"]
        if not diffs and coded:
            self.add(name, "EXPECTED", error_parity.detail(coded))
        elif not diffs:
            self.add(name, "SAME")
        elif status_only and coded and a["status"] == 500 and 400 <= b["status"] < 500:
            self.add(name, "EXPECTED", f"{N14}: java=500 rust={b['status']} [{coded}]")
        elif expected and not error_parity.is_problem(coded):
            self.add(name, "EXPECTED", f"{expected}: " + "; ".join(diffs))
        else:
            self.add(name, "DIFF", "; ".join(diffs))

    def summary(self):
        counts = {}
        for _, v, _ in self.rows:
            counts[v] = counts.get(v, 0) + 1
        print("\n" + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
        for n, v, d in self.rows:
            if v == "EXPECTED":
                print(f"  EXPECTED {n}: {d[:200]}")
        return counts.get("DIFF", 0)


def both(args, method, path, body=None, headers=None):
    return call(args.java, method, path, body, headers), call(args.rust, method, path, body, headers)


# ------------------------------------------------------------------------------------- routes

def routes(args, rep):
    anon = {"clientCode": "SYSTEM", "appCode": "appbuilder"}
    for m, p in [("GET", "/api/notification/new?appCode=rsparity"), ("GET", "/api/notification/notifications"),
                 ("GET", "/api/notification/subscribe?appCode=rsparity"), ("GET", "/api/notification/preference?appCode=rsparity"),
                 ("POST", "/api/notification/preference?appCode=rsparity"), ("GET", "/api/notification/nothing"),
                 ("DELETE", "/api/notification/preference")]:
        j, r = both(args, m, p, None, anon)
        rep.compare(f"anonymous {m} {p}", j, r)
    j, r = both(args, "GET", "/api/notification/new?appCode=rsparity", None, {**anon, "Authorization": "Bearer not.a.token"})
    rep.compare("malformed bearer token", j, r)

    for p in ["/api/notification/preference", "/api/notification/new", "/api/notification/subscribe",
              "/api/notification/notifications", "/api/notification/nothing"]:
        j, r = both(args, "OPTIONS", p, None, {})
        rep.compare(f"OPTIONS {p}", j, r)
    pre = {"Origin": "http://x.com", "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization,clientcode"}
    j, r = both(args, "OPTIONS", "/api/notification/subscribe", None, pre)
    rep.compare("CORS preflight", j, r)
    j, r = both(args, "GET", "/api/notification/new?appCode=rsparity", None, {**SIGNED_IN, "Origin": "http://x.com"})
    rep.compare("cross-origin GET", j, r)

    signed = [
        ("GET", "/api/notification/new?appCode=rsparity"),
        ("GET", "/api/notification/new?appCode=rsparity&type=ALERT"),
        ("GET", "/api/notification/new?appCode="),
        ("GET", "/api/notification/new"),
        ("GET", "/api/notification/notifications?appCode=rsparity"),
        ("GET", "/api/notification/notifications?appCode=rsparity&page=1&size=5"),
        ("GET", "/api/notification/notifications?appCode=rsparity&size=0&sort=title,desc"),
        ("GET", "/api/notification/notifications?appCode=rsparity&size=5000&page=x"),
        ("GET", "/api/notification/notifications?appCode=rsparity&type=INFO&category=Default&sort=createdAt&sort=title,asc,ignorecase"),
        ("GET", "/api/notification/notifications?appCode="),
        ("GET", "/api/notification/notifications"),
        ("GET", "/api/notification/preference"),
        ("GET", "/api/notification/preference?appCode=rsparity"),
        ("GET", "/api/notification/preference?appCode=rsparity&userId=abc"),
        ("GET", "/api/notification/preference?appCode=rsparity&userId=1.5"),
        ("GET", "/api/notification/preference?appCode=rsparity&userId=-5"),
        ("GET", "/api/notification/preference?appCode=rsparity&userId=999999999"),
        ("GET", "/api/notification/preference?appCode=rsparity&userId=142"),
        ("GET", "/api/notification/preference?appCode=rsparity&userId=1"),
        ("GET", "/api/notification/preference?appCode=rsparity&userId="),
        ("GET", "/api/notification/subscribe"),
        ("DELETE", "/api/notification/preference?appCode=rsparity"),
        ("PUT", "/api/notification/preference?appCode=rsparity"),
        ("POST", "/api/notification/new"),
        ("POST", "/api/notification/notifications"),
        ("GET", "/api/notification/nothing"),
        ("GET", "/api/notification/new/"),
        ("GET", "/api/notifications/new"),
    ]
    for m, p in signed:
        j, r = both(args, m, p, None, SIGNED_IN)
        rep.compare(f"{m} {p}", j, r)
        if "/notifications" in p and j.status == 200:
            jo, ro = page_order(j), page_order(r)
            if jo != ro:
                rep.add(f"key order {p}", "EXPECTED", f"N4 (Jackson's order for PageImpl differs per JVM run): java={jo} rust={ro}")
    j, r = both(args, "HEAD", "/api/notification/new?appCode=rsparity", None, SIGNED_IN)
    rep.add("HEAD /api/notification/new", "SAME" if (j.status, j.h("content-type")) == (r.status, r.h("content-type")) else "DIFF",
            f"java={j.status} {j.h('content-type')} rust={r.status} {r.h('content-type')}")
    j, r = both(args, "GET", "/api/notification/subscribe?appCode=rsparity", None, {**SIGNED_IN, "Accept": "application/json"})
    rep.compare("subscribe accepting only JSON", j, r)


# --------------------------------------------------------------------------------- preferences

def preferences(args, rep):
    app = "rsparity" + uuid.uuid4().hex[:8]
    url = f"/api/notification/preference?appCode={app}"
    json_h = {**SIGNED_IN, "Content-Type": "application/json"}
    steps = [
        ("read, none", "GET", None, SIGNED_IN),
        ("create", "POST", '{"zz":1,"a":{"y":2,"b":1.0},"n":null,"s":"x"}', json_h),
        ("read back (MySQL key order)", "GET", None, SIGNED_IN),
        ("update", "POST", '{"email":false,"inapp":{"ALERT":true}}', json_h),
        ("read updated", "GET", None, SIGNED_IN),
        ("empty map deletes", "POST", "{}", json_h),
        ("read deleted", "GET", None, SIGNED_IN),
        ("no body creates an empty row", "POST", None, SIGNED_IN),
        ("read the empty row", "GET", None, SIGNED_IN),
        ("JSON null deletes", "POST", "null", json_h),
        ("empty map creates", "POST", "{}", json_h),
        ("empty map deletes again", "POST", "{}", json_h),
        ("array body", "POST", "[1]", json_h),
        ("broken JSON", "POST", "{nope", json_h),
        ("text/plain body", "POST", "{}", {**SIGNED_IN, "Content-Type": "text/plain"}),
        ("body without a content type", "POST", "{}", SIGNED_IN),
        ("final read", "GET", None, SIGNED_IN),
    ]
    for name, m, body, h in steps:
        j, r = both(args, m, url, body, h)
        rep.compare(f"preference: {name}", j, r, exact_body=True)
    # Another user's preference: security's management check, Java's argument order.
    for uid in ["142", "1"]:
        j, r = both(args, "POST", f"{url}&userId={uid}", '{"p":1}', json_h)
        rep.compare(f"preference for userId={uid}: write", j, r, exact_body=True)
        j, r = both(args, "POST", f"{url}&userId={uid}", "{}", json_h)
        rep.compare(f"preference for userId={uid}: delete", j, r, exact_body=True)


# ------------------------------------------------------------------------------------------ SSE

class Stream:
    """An SSE client on a plain socket: http.client cannot resume a chunked read after a
    timeout, and a stream is read with timeouts to wait for events."""

    def __init__(self, base, app, headers=None):
        u = urllib.parse.urlparse(base)
        self.sock = socket.create_connection((u.hostname, u.port), timeout=1)
        hs = {**SIGNED_IN, **(headers or {}), "Host": f"{u.hostname}:{u.port}"}
        req = f"GET /api/notification/subscribe?appCode={app} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hs.items()) + "\r\n"
        self.sock.sendall(req.encode())
        self.raw = b""
        self.text = ""
        self.status = None
        self.headers = {}
        self.chunked = False
        end = time.time() + 10
        while b"\r\n\r\n" not in self.raw and time.time() < end:
            self._recv()
        head, _, self.raw = self.raw.partition(b"\r\n\r\n")
        lines = head.decode("latin-1").split("\r\n")
        self.status = int(lines[0].split()[1]) if lines and len(lines[0].split()) > 1 else None
        for l in lines[1:]:
            k, _, v = l.partition(":")
            self.headers.setdefault(k.strip().lower(), v.strip())
        self.chunked = "chunked" in self.headers.get("transfer-encoding", "").lower()

    def _recv(self):
        try:
            data = self.sock.recv(65536)
        except socket.timeout:
            return False
        if data:
            self.raw += data
        return bool(data)

    def _drain(self):
        if not self.chunked:
            self.text += self.raw.decode("utf-8", "replace")
            self.raw = b""
            return
        while True:
            i = self.raw.find(b"\r\n")
            if i < 0:
                return
            size = int(self.raw[:i].split(b";")[0] or b"0", 16)
            if len(self.raw) < i + 2 + size + 2:
                return
            self.text += self.raw[i + 2:i + 2 + size].decode("utf-8", "replace")
            self.raw = self.raw[i + 2 + size + 2:]

    def read_until(self, pattern, seconds, start=0):
        """What arrived until `pattern` matched (or the time ran out), from offset `start`."""
        end = time.time() + seconds
        self._drain()
        while not re.search(pattern, self.text[start:]) and time.time() < end:
            self._recv()
            self._drain()
        return self.text[start:]

    def close(self):
        self.sock.close()


def mask(frames):
    frames = re.sub(r"id:[0-9a-f-]{36}", "id:<uuid>", frames)
    return re.sub(r'"id" : \d+', '"id" : <id>', frames)


def sse(args, rep):
    results = {}

    def one(side, base):
        st = Stream(base, "rsparity")
        first = st.read_until(r"\n\n", 5)
        first = first[: first.index("\n\n") + 2] if "\n\n" in first else first
        keep = ""
        if not args.skip_keepalive:
            keep = st.read_until(r":keepalive\n\n", 17, len(first))
        st.close()
        results[side] = (st.status, st.headers, first, keep)

    threads = [threading.Thread(target=one, args=(s, b)) for s, b in (("java", args.java), ("rust", args.rust))]
    [t.start() for t in threads]
    [t.join() for t in threads]
    (js, jh, jf, jk), (rs, rh, rf, rk) = results["java"], results["rust"]
    diffs = []
    if js != rs:
        diffs.append(f"status {js} {rs}")
    for h in ["content-type", "cache-control", "connection", "x-accel-buffering", "x-frame-options", "content-security-policy",
              "x-content-type-options", "x-xss-protection", "pragma", "expires", "referrer-policy"]:
        if jh.get(h) != rh.get(h):
            diffs.append(f"{h}: java={jh.get(h)!r} rust={rh.get(h)!r}")
    rep.add("SSE headers", "DIFF" if diffs else "SAME", "; ".join(diffs))
    rep.add("SSE init event", "SAME" if mask(jf) == mask(rf) else "DIFF", f"java={jf!r} rust={rf!r}")
    if not args.skip_keepalive:
        ok = ":keepalive\n\n" in jk and ":keepalive\n\n" in rk
        rep.add("SSE keepalive within 16 s", "SAME" if ok else "DIFF", f"java={jk!r} rust={rk!r}")


# ------------------------------------------------------------------------------------ delivery

class SendGridStub(http.server.ThreadingHTTPServer):
    """Stands in for api.sendgrid.com: Rust runs with MODLIX__EMAIL__SENDGRID_URL pointing here."""

    daemon_threads = True

    def __init__(self, port):
        self.mails = []
        super().__init__(("127.0.0.1", port), SendGridHandler)


class SendGridHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0))
        self.server.mails.append((self.path, self.headers.get("Authorization"), json.loads(body or b"null")))
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


def core_call(method, path, body=None):
    h = {**SIGNED_IN, "X-Forwarded-Host": "appbuilder.local.modlix.com", "X-Forwarded-Port": "443", "Content-Type": "application/json"}
    return call(CORE, method, path, json.dumps(body) if body is not None else None, h)


def publish(exchange, key, body):
    req = {"properties": {"content_type": "application/json", "content_encoding": "UTF-8", "delivery_mode": 2,
                          "headers": {"__TypeId__": "com.fincity.saas.commons.mq.notifications.NotificationQueObject"}},
           "routing_key": key, "payload": body, "payload_encoding": "string"}
    r = call(MQ_API, "POST", f"/api/exchanges/%2f/{urllib.parse.quote(exchange)}/publish", json.dumps(req),
             {"Authorization": MQ_AUTH, "Content-Type": "application/json"})
    return r.json() or {}


def delivery(args, rep):
    assert args.rust_exchange.startswith("rs_scratch_") and args.rust_queue.startswith("rs_scratch_"), "scratch names only"
    sendgrid = SendGridStub(args.sendgrid_port)
    threading.Thread(target=sendgrid.serve_forever, daemon=True).start()
    tag = uuid.uuid4().hex[:6]
    names = {"mail": f"rsNP{tag}Mail", "conn": f"rsNP{tag}Conn", "notif": f"rsNP{tag}"}
    created = []
    try:
        for kind, body in [
            # SendGrid, because core refuses an SMTP host on a private address; Rust posts it to the stub.
            ("connections", {"name": names["mail"], "appCode": "monkbars", "clientCode": "SYSTEM", "connectionType": "MAIL",
                             "connectionSubType": "SENDGRID",
                             "connectionDetails": {"apiKey": "SG.parity-not-a-key", "fromAddress": "noreply@parity.local"}}),
            ("connections", {"name": names["conn"], "appCode": "monkbars", "clientCode": "SYSTEM", "connectionType": "NOTIFICATION",
                             "connectionDetails": {"inapp": True, "mail": names["mail"]}}),
            ("notifications", {"name": names["notif"], "appCode": "monkbars", "clientCode": "SYSTEM", "notificationType": "ALERT",
                               "defaultLanguage": "en", "channelTemplates": {
                                   "inapp": {"templateParts": {"en": {"title": "Héllo ${who}", "description": "Line one\nline \"two\" ${n}",
                                                                      "image": "api/files/x.svg", "url": "/page/${who}"}}},
                                   "email": {"templateParts": {"en": {"subject": "Parity ${who}", "body": "<p>Hi ${who}</p>"}}}}}),
        ]:
            r = core_call("POST", f"/api/core/{kind}", body)
            if r.status != 200 or not (r.json() or {}).get("id"):
                rep.add(f"delivery: create {kind} {body['name']}", "DIFF", f"core answered {r.status} {r.text()[:200]}")
                return
            created.append((kind, r.json()["id"]))

        stream = Stream(args.rust, "monkbars")
        init = stream.read_until(r"\n\n", 5)
        msg = {"appCode": "monkbars", "clientCode": "SYSTEM", "urlClientCode": "SYSTEM", "targetType": "User Id", "targetId": 142,
               "notificationName": names["notif"], "notificationCategory": "Parity", "connectionName": names["conn"],
               "draft": False, "payload": {"who": "Ann", "n": 3}}
        routed = publish(args.rust_exchange, args.rust_queue, json.dumps(msg)).get("routed")
        frames = stream.read_until(r"retry:5000\n\n", 20, len(init))
        stream.close()
        expected = JAVA_SSE_FIXTURE.split("\n\n", 1)[1].replace("rsNotifParity", names["notif"])
        got = mask(frames)
        rep.add("delivery: scratch queue to an open stream (vs Java's frames)", "SAME" if routed and got == expected else "DIFF",
                f"routed={routed} got={frames!r}")
        mails = list(sendgrid.mails)
        want = {"personalizations": [{"to": [{"email": "<recipient>"}]}], "from": {"email": "noreply@parity.local"},
                "subject": "Parity Ann", "content": [{"type": "text/html", "value": "<p>Hi Ann</p>"}]}
        got_mail = mails[0][2] if mails else None
        if got_mail:
            got_mail = json.loads(json.dumps(got_mail))
            got_mail["personalizations"][0]["to"][0]["email"] = "<recipient>"
        ok = len(mails) == 1 and mails[0][1] == "Bearer SG.parity-not-a-key" and got_mail == want
        rep.add("delivery: one mail per recipient (SendGrid body, to the stub)", "SAME" if ok else "DIFF", f"{mails}")

        n1 = call(args.rust, "GET", "/api/notification/new?appCode=monkbars", None, SIGNED_IN).text()
        page = call(args.rust, "GET", "/api/notification/notifications?appCode=monkbars", None, SIGNED_IN).json() or {}
        n2 = call(args.rust, "GET", "/api/notification/new?appCode=monkbars", None, SIGNED_IN).text()
        item = (page.get("content") or [{}])[0]
        ok = n1 == "1" and n2 == "0" and list(item.keys()) == JAVA_LIST_ITEM_KEYS and item.get("title") == "Héllo Ann" \
            and item.get("notificationCategory") == "Parity" and item.get("url") == "/page/Ann"
        rep.add("delivery: count, list (Java's item shape), marked read", "SAME" if ok else "DIFF", f"new={n1}->{n2} item={item}")

        # A message naming no known connection ends quietly: no event, the queue is drained.
        stream = Stream(args.rust, "monkbars")
        init = stream.read_until(r"\n\n", 5)
        publish(args.rust_exchange, args.rust_queue, json.dumps({**msg, "connectionName": "rsNPnone"}))
        publish(args.rust_exchange, args.rust_queue, "not json")
        frames = stream.read_until(r"event:notification", 3, len(init))
        stream.close()
        time.sleep(1)
        q = call(MQ_API, "GET", f"/api/queues/%2f/{args.rust_queue}", None, {"Authorization": MQ_AUTH}).json() or {}
        ok = "event:notification" not in frames and q.get("messages", 0) == 0
        rep.add("delivery: unknown connection and unreadable body are settled, nothing sent", "SAME" if ok else "DIFF",
                f"frames={frames!r} queue messages={q.get('messages')}")
    finally:
        for kind, id_ in reversed(created):
            r = core_call("DELETE", f"/api/core/{kind}/{id_}")
            if r.status != 200:
                print(f"!! could not delete core {kind}/{id_}: {r.status}")
        sendgrid.shutdown()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--java", default="http://localhost:8007")
    p.add_argument("--rust", default="http://localhost:8114")
    p.add_argument("--rust-exchange", default="rs_scratch_notif_rust_x")
    p.add_argument("--rust-queue", default="rs_scratch_notif_rust")
    p.add_argument("--sendgrid-port", type=int, default=18114, help="Rust's MODLIX__EMAIL__SENDGRID_URL port")
    p.add_argument("--skip-keepalive", action="store_true")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()
    rep = Report(args.verbose)
    routes(args, rep)
    preferences(args, rep)
    sse(args, rep)
    delivery(args, rep)
    sys.exit(1 if rep.summary() else 0)


if __name__ == "__main__":
    main()
