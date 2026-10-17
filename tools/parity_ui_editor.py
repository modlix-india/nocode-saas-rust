#!/usr/bin/env python3
"""Runs the same editing session against the Java ui service and against ui-editor and compares
the answers, the documents each write leaves behind, and the cache evictions each write sends.

Usage: parity_ui_editor.py [java_base] [rust_base] [--client-only]  (--client-only: just the component changes made for a client)
       defaults: http://localhost:8002  http://localhost:8107

Everything happens in the scratch app `shellparity` (a security app made for the ui-shell parity),
through the APIs only, signed in as user 142 under the `appbuilder` app (the editor's
authorities), on the SYSTEM client. The session runs twice: once against Java with objects named
`edpJ...`, once against Rust with `edpR...`; an application and a filler (named after the app)
are made in turn. The four URI paths the shell parity uses are read first, survive everything
but the app wipe, and are put back (through Java) after each wipe and on any failure.

Per side, in order:
- refusals both servers get the same request for (name rules, URI path validation, unknown ids,
  missing parameters, the mobile and Apple routes);
- the application: create, update, draft, discard, draft again, publish, versions;
- the filler, styles (one created unpublished and then published), themes, pages (component and
  event reads and patches), functions (step reads and patches), schemas, URI paths: create,
  update, draft save and draft read, publish, versions, delete;
- the index (slim, full, internal), publish-all with its pending list, a mobile app's life;
- transport: an export of the side's page and function, the page deleted, the export imported;
- the app wipe (`DELETE /api/ui?deleteAppCode=`).

Compared:
- each write's answer, Java's `edpJ` session against Rust's `edpR` one: status, content type,
  `X-Draft-Version`, and the body with ids, timestamps, exception ids and the side names
  normalised (key order included);
- after each write, the object read back through BOTH servers: the two reads must be identical,
  byte for byte apart from exception ids (this is also how a write on one server is seen to
  evict the other's caches);
- the messages each write publishes on Redis `evictionChannel` and `ssr:cache:invalidation`
  (those naming the scratch app): Rust must send every one Java sends; what it sends besides
  must be one of the additions DIFFERENCES.md lists for that write.

Known differences (crates/ui/DIFFERENCES.md) are reported as EXPECTED with the reason.
"""
import base64
import http.client
import json
import os
import re
import socket
import sys
import threading
import time
import urllib.parse

import error_parity  # coded Rust errors are compared by code (crates/ui/DIFFERENCES.md, Error bodies)

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
JAVA = ARGS[0] if len(ARGS) > 0 else "http://localhost:8002"
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8107"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APP = "shellparity"
BUILDER = "appbuilder"
SYSTEM = "SYSTEM"
BASIC = "Basic " + base64.b64encode(b"142:Pass@1234").decode()
HEADERS = {
    "appCode": BUILDER,
    "clientCode": SYSTEM,
    "Authorization": BASIC,
    "X-Forwarded-Host": f"{BUILDER}.local.modlix.com",
    "X-Forwarded-Port": "443",
}
SETTLE = 0.6  # seconds a write's evictions get to arrive
TARGET = "FIN"  # a client SYSTEM manages: the component changes made for a client go to its copy

# Whether the running Java ui has PageController's client-targeted component routes
# (PageClientPatchIntegrationTest, uncommitted in nocode-saas on 2026-10-15). Set in main().
JAVA_CLIENT_PATCH = None
NO_CLIENT_PATCH = ("the running Java ui predates the client-targeted component routes (PageController / "
                   "PageService.patchForClient, uncommitted): it ignores clientCode, standalone and draft and maps no "
                   "POST or DELETE on the components path")


def env(name):
    with open(os.path.join(ROOT, "config", "local.env")) as f:
        for line in f:
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip()
    raise SystemExit(f"{name} missing from config/local.env")


# ── Redis: the eviction and SSR channels ─────────────────────────────

class Bus:
    """Collects every message on the two channels (the URL is never printed)."""

    CHANNELS = ("evictionChannel", "ssr:cache:invalidation")

    def __init__(self):
        url = urllib.parse.urlsplit(env("MODLIX__REDIS__URL"))
        pw = urllib.parse.unquote(url.password or url.username or "")
        self.sock = socket.create_connection((url.hostname, url.port or 6379), timeout=10)
        self.f = self.sock.makefile("rb")
        if pw:
            self.send("AUTH", pw)
            if str(self.read()).startswith("ERR"):
                raise SystemExit("Redis refused the configured credentials")
        self.send("SUBSCRIBE", *self.CHANNELS)
        for _ in self.CHANNELS:
            self.read()
        self.sock.settimeout(None)
        self.msgs = []
        self.lock = threading.Lock()
        threading.Thread(target=self.loop, daemon=True).start()

    def send(self, *a):
        out = f"*{len(a)}\r\n" + "".join(f"${len(x.encode())}\r\n{x}\r\n" for x in a)
        self.sock.sendall(out.encode())

    def read(self):
        line = self.f.readline()
        if not line:
            raise EOFError
        t, rest = line[:1], line[1:-2]
        if t == b"*":
            return [self.read() for _ in range(int(rest))]
        if t == b"$":
            n = int(rest)
            return None if n < 0 else self.f.read(n + 2)[:-2].decode("utf-8", "replace")
        return rest.decode("utf-8", "replace")

    def loop(self):
        while True:
            try:
                m = self.read()
            except Exception:
                return
            if isinstance(m, list) and len(m) == 3 and m[0] == "message":
                with self.lock:
                    self.msgs.append((m[1], m[2]))

    def mark(self):
        with self.lock:
            return len(self.msgs)

    def since(self, i):
        with self.lock:
            return [m for m in self.msgs[i:] if APP in m[1]]


# ── HTTP ─────────────────────────────────────────────────────────────

class Resp:
    def __init__(self, status, headers, body):
        self.status, self.headers, self.body = status, headers, body

    def json(self):
        try:
            return json.loads(self.body)
        except Exception:
            return None

    def obj(self):
        j = self.json()
        return j if isinstance(j, dict) else {}

    @property
    def ct(self):
        return self.headers.get("content-type")

    def text(self):
        return self.body.decode("utf-8", "replace")


class Headers(dict):
    """Lower-case response headers, read case-insensitively."""

    def get(self, name, default=None):
        return dict.get(self, name.lower(), default)


def decoded(j, r):
    """Rust's answer as Java would have sent it when it is a coded error standing for Java's
    text (error_parity.decode), and the note."""
    jt = (j.status, {k.lower(): v for k, v in j.headers.items()}, j.body)
    rt = (r.status, {k.lower(): v for k, v in r.headers.items()}, r.body)
    (s, h, b), note = error_parity.decode(jt, rt)
    if note is None or error_parity.is_problem(note):
        return r, note
    return Resp(s, Headers(h), b), note


def call(base, method, path, body=None, headers=None, raw=None):
    u = urllib.parse.urlsplit(base)
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=60)
    h = dict(HEADERS)
    h.update(headers or {})
    data = raw
    if body is not None:
        data = json.dumps(body).encode()
        h.setdefault("Content-Type", "application/json")
    try:
        c.putrequest(method, path, skip_accept_encoding=True)
        for k, v in h.items():
            if v is not None:
                c.putheader(k, v)
        if data is not None:
            c.putheader("Content-Length", str(len(data)))
        c.endheaders(data)
        r = c.getresponse()
        return Resp(r.status, r.msg, r.read())
    finally:
        c.close()


# ── Normalising ──────────────────────────────────────────────────────

HEX = re.compile(r"\b[0-9a-f]{24}\b")
EXC = re.compile(r"\d{4}-\d{2}-\d{2}-[0-9a-f]+")
TS_KEYS = {"createdAt", "updatedAt", "timestamp", "lastModified", "expiresAt"}
RANDOM_KEYS = {"uniqueTransportCode", "androidKeystore", "androidStorePass", "androidKeyPass", "shortCode"}


def nstr(s):
    s = s.replace("edpJ", "edp*").replace("edpR", "edp*")
    # A stored transport is named `<name><uniqueTransportCode>`, the code random.
    s = re.sub(r"(edp\*t)[0-9A-Za-z]{16,24}", r"\1<code>", s)
    s = HEX.sub("<id>", s)
    return EXC.sub("<exc>", s)


def norm(v, key=None):
    if isinstance(v, dict):
        return {nstr(k): norm(x, k) for k, x in v.items()}
    if isinstance(v, list):
        return [norm(x) for x in v]
    if key in TS_KEYS and v is not None:
        return "<ts>"
    if key in RANDOM_KEYS and v is not None:
        return "<random>"
    if isinstance(v, str):
        return nstr(v)
    return v


def body_of(r, side_neutral=True):
    j = r.json()
    if j is None:
        t = r.text()
        return nstr(t) if side_neutral else EXC.sub("<exc>", t)
    if isinstance(j, dict) and "exceptionId" in j:
        j = {k: x for k, x in j.items() if k not in ("exceptionId", "stackTrace")}
        if "debugMessage" in j:
            j["debugMessage"] = "<debug>"
    return norm(j) if side_neutral else json.loads(EXC.sub("<exc>", json.dumps(j)))


def shape(r, side_neutral=True):
    return {
        "status": r.status,
        "content-type": r.ct,
        "x-draft-version": r.headers.get("x-draft-version"),
        "body": body_of(r, side_neutral),
    }


def first_diff(a, b, path="$"):
    if type(a) is not type(b):
        return f"{path}: {short(a)} vs {short(b)}"
    if isinstance(a, dict):
        if list(a.keys()) != list(b.keys()):
            if set(a.keys()) == set(b.keys()):
                return f"{path}: key order {list(a.keys())[:12]} vs {list(b.keys())[:12]}"
            return f"{path}: keys {sorted(set(a) ^ set(b))[:10]}"
        for k in a:
            d = first_diff(a[k], b[k], f"{path}.{k}")
            if d:
                return d
        return None
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: length {len(a)} vs {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            d = first_diff(x, y, f"{path}[{i}]")
            if d:
                return d
        return None
    return None if a == b else f"{path}: {short(a)} vs {short(b)}"


def short(v):
    s = json.dumps(v) if not isinstance(v, str) else v
    return s if len(s) < 160 else s[:157] + "..."


def same_but_side_ordered(a, b):
    """Equal, except that maps keyed by the side names may order their keys differently (a
    HashMap's order follows its keys' hashes, and `edpJ...` and `edpR...` hash differently)."""
    if type(a) is not type(b):
        return False
    if isinstance(a, dict):
        if set(a) != set(b):
            return False
        if list(a) != list(b) and not any("edp*" in k for k in a):
            return False
        return all(same_but_side_ordered(a[k], b[k]) for k in a)
    if isinstance(a, list):
        return len(a) == len(b) and all(same_but_side_ordered(x, y) for x, y in zip(a, b))
    return a == b


# ── Results ──────────────────────────────────────────────────────────

RESULTS = []  # (verdict, name, detail)

# Differences DIFFERENCES.md explains, by case name prefix: reason.
EXPECTED = {
    "refusal function without definition": "a null definition is Java's NullPointerException: both 500, the text is the JVM's",
    "refusal uripath without definitions": "a null pathDefinitions is Java's NullPointerException: both 500, the text is the JVM's",
}


def objects_sorted(shape_):
    body = shape_.get("body")
    if not isinstance(body, dict) or not isinstance(body.get("objects"), list):
        return shape_
    key = lambda o: json.dumps([o.get("objectType"), (o.get("data") or {}).get("name")])
    return dict(shape_, body=dict(body, objects=sorted(body["objects"], key=key)))


def record(verdict, name, detail=""):
    RESULTS.append((verdict, name, detail))
    if verdict != "SAME":
        print(f"{verdict:9} {name}" + (f"\n          {detail}" if detail else ""))


def ordered_equal(a, b):
    """Equal with every map's key order too (`==` on dicts ignores order)."""
    return json.dumps(a) == json.dumps(b)


JVM_ORDER_NOTE = ("only the key order of a page, its pageable or its sort orders differs: Jackson lists their getters in "
                  "getDeclaredMethods order, which HotSpot sorts by symbol address, so Java's order changes from one restart "
                  "to the next (crates/ui/DIFFERENCES.md)")


def jvm_orders_sorted(v, key=None):
    """`v` with the keys of the maps whose order Java picks per JVM run sorted."""
    if isinstance(v, dict):
        sort = (key == "pageable" or {"direction", "property", "ascending"} <= set(v)
                or {"pageable", "totalElements", "numberOfElements"} <= set(v))
        items = sorted(v.items()) if sort else v.items()
        return {k: jvm_orders_sorted(x, k) for k, x in items}
    if isinstance(v, list):
        return [jvm_orders_sorted(x) for x in v]
    return v


def client_case(name):
    return re.match(r"^(write |refusal |evictions )?client ", name) is not None


def compare_shapes(name, a, b, coded=None):
    if error_parity.is_problem(coded):
        return record("DIFF", name, error_parity.detail(coded, first_diff(a, b) or ""))
    if ordered_equal(a, b):
        if coded:
            return record("EXPECTED", name, error_parity.detail(coded))
        return record("SAME", name)
    d = first_diff(a, b)
    if client_case(name) and not JAVA_CLIENT_PATCH:
        return record("EXPECTED", name, NO_CLIENT_PATCH + f" ({d})")
    if same_but_side_ordered(a, b):
        return record("SAME", name)
    if ordered_equal(jvm_orders_sorted(a), jvm_orders_sorted(b)) or same_but_side_ordered(jvm_orders_sorted(a), jvm_orders_sorted(b)):
        return record("EXPECTED", name, JVM_ORDER_NOTE + f" ({d})")
    if "transport" in name and isinstance(a.get("body"), dict) and "objects" in a["body"]:
        if same_but_side_ordered(objects_sorted(a), objects_sorted(b)):
            return record("EXPECTED", name, "Java reads an export's services concurrently, so its object order is "
                                            "whichever finished first; Rust's is the service order (overridable DIFFERENCES 8)")
        d = first_diff(objects_sorted(a), objects_sorted(b))
    for prefix, why in EXPECTED.items():
        if name.startswith(prefix):
            if a["status"] == b["status"]:
                return record("EXPECTED", name, why)
    record("DIFF", name, d)


# ── Evictions ────────────────────────────────────────────────────────

OUI = re.compile(r"^cmn-(applicationOUICache|pageOUICache|styleOUICache|themeOUICache)-shellparity:\*$")
APP_CACHES = re.compile(r"^cmn-ApplicationCache_shellparity_(indexNewCache|manifestCache|cacheProperties)_shellparity(_DRAFT)?:\*$")
SSR = re.compile(r'^\{\s*"appCode"\s*:\s*"shellparity",\s*"timestamp"\s*:\s*\d+\s*\}$')

# The evictions Rust adds, per kind of write (DIFFERENCES.md, "ui-editor").
ADDED = {
    "create": "create clears the UI caches (OUI, SSR, the application's index/manifest/properties) Java's create leaves",
    "delete": "delete clears every client's cached copy (`<cache>:*`), not only the deleting client's key",
    "patch": "a component or event patch clears the page OUI caches and publishes the SSR invalidation",
    "wipe": "the app wipe clears each name's _DRAFT cache and deletes the shared entries",
    "update": "an update clears the stored app's UI caches as well as the body's",
    "draft": "a filler's draft save or discard clears its FILLER_READ cache too",
    "fork": "a filler's fork (an evictDraft) clears its FILLER_READ cache too",
}


def eviction_set(msgs):
    out = set()
    for ch, m in msgs:
        if ch == "ssr:cache:invalidation":
            out.add(("ssr", "SSR" if SSR.match(m.strip()) else nstr(m)))
        else:
            out.add(("evict", nstr(m)))
    return out


def allowed_extra(kind, msg, java):
    ch, m = msg
    if kind in ("create", "patch", "update"):
        if ch == "ssr" or OUI.match(m) or APP_CACHES.match(m):
            return True
    if kind == "create" and re.match(r"^cmn-.*shellparity.*:\*$", m):
        return True
    if kind == "delete":
        if ch == "ssr" or OUI.match(m) or APP_CACHES.match(m):
            return True
        if m.endswith(":*") and any(j[1].startswith(m[:-1]) for j in java):
            return True
        if m.endswith("_DRAFT:*") and any(j[1].startswith(m[: -len("_DRAFT:*")]) for j in java):
            return True
    if kind == "wipe" and m.endswith(":*"):
        return True
    if kind in ("draft", "fork") and m.endswith("_FILLER_READ:*"):
        return True
    return False


def compare_evictions(name, kind, java, rust):
    if client_case(name) and not JAVA_CLIENT_PATCH and eviction_set(java) != eviction_set(rust):
        return record("EXPECTED", f"evictions {name}", NO_CLIENT_PATCH)
    jset, rset = eviction_set(java), eviction_set(rust)
    missing = sorted(jset - rset)
    extra = sorted(rset - jset)
    if missing:
        return record("DIFF", f"evictions {name}", f"Rust leaves out {missing[:6]}")
    bad = [e for e in extra if not allowed_extra(kind, e, jset)]
    if bad:
        return record("DIFF", f"evictions {name}", f"Rust adds {bad[:6]}")
    if extra:
        return record("EXPECTED", f"evictions {name}", f"{ADDED.get(kind, kind)}: {len(extra)} more")
    record("SAME", f"evictions {name}")


# ── The session ──────────────────────────────────────────────────────

class Side:
    def __init__(self, tag, base, bus):
        self.tag, self.base, self.bus = tag, base, bus
        self.n = "edp" + tag
        self.writes = {}  # case -> (shape, evictions, kind)
        self.answers = {}  # case -> the write's raw answer (for the coded error check)
        self.reads = {}  # case -> shape (side-neutral)

    def write(self, case, kind, method, path, body=None, headers=None, raw=None):
        i = self.bus.mark()
        r = call(self.base, method, path, body, headers, raw)
        time.sleep(SETTLE)
        self.writes[case] = (shape(r), self.bus.since(i), kind)
        self.answers[case] = r
        return r

    def read_both(self, case, path, headers=None):
        """The same read on both servers: identical, or a DIFF. Kept for the J/R comparison."""
        j = call(JAVA, "GET", path, headers=headers)
        r = call(RUST, "GET", path, headers=headers)
        r_raw = r
        r, coded = decoded(j, r)
        a, b = shape(j, False), shape(r, False)
        if error_parity.is_problem(coded):
            record("DIFF", f"cross-read {self.tag} {case}", error_parity.detail(coded))
        elif ordered_equal(a, b) and coded:
            record("EXPECTED", f"cross-read {self.tag} {case}", error_parity.detail(coded))
        elif ordered_equal(a, b):
            record("SAME", f"cross-read {self.tag} {case}")
        elif ordered_equal(jvm_orders_sorted(a), jvm_orders_sorted(b)):
            record("EXPECTED", f"cross-read {self.tag} {case}", JVM_ORDER_NOTE + f" ({first_diff(a, b)})")
        elif re.search(r"(filler|uripath) version by id$", case) and j.status == r.status == 200 and not j.body and r.body:
            record("EXPECTED", f"cross-read {self.tag} {case}",
                   "Java's VersionService has no authority name for URIPATH / FILLER and refuses their rows; "
                   "the editor checks them with the application's authorities")
        else:
            record("DIFF", f"cross-read {self.tag} {case}", first_diff(a, b) or "headers")
        self.reads[case] = shape(r_raw)
        return j

    def query_both(self, case, path, body):
        j = call(JAVA, "POST", path, body)
        r_raw = call(RUST, "POST", path, body)
        r, coded = decoded(j, r_raw)
        a, b = shape(j, False), shape(r, False)
        same = ordered_equal(a, b) and not error_parity.is_problem(coded)
        if not same and ordered_equal(jvm_orders_sorted(a), jvm_orders_sorted(b)):
            record("EXPECTED", f"cross-read {self.tag} {case}", JVM_ORDER_NOTE + f" ({first_diff(a, b)})")
        else:
            verdict = error_parity.verdict("SAME", coded) if same else "DIFF"
            record(verdict, f"cross-read {self.tag} {case}", error_parity.detail(coded) if coded else ("" if same else (first_diff(a, b) or "headers")))
        self.reads[case] = shape(r_raw)
        return j


def oid(r):
    o = r.obj()
    return o.get("id")


def call_retrying(base, *a):
    """A request, tried again once if the server does not answer in time."""
    try:
        return call(base, *a)
    except TimeoutError:
        return call(base, *a)


def refusals(name, method, path, body=None, headers=None, raw=None):
    """One request both servers get as it is."""
    j = call_retrying(JAVA, method, path, body, headers, raw)
    r = call_retrying(RUST, method, path, body, headers, raw)
    r, coded = decoded(j, r)
    if r.headers.get("www-authenticate"):
        record("DIFF", f"refusal {name} WWW-Authenticate", "Rust sends WWW-Authenticate")
    elif j.headers.get("www-authenticate"):
        record("EXPECTED", f"refusal {name} WWW-Authenticate",
               "the running Java ui predates aca9929dd, which dropped WWW-Authenticate from 401s")
    compare_shapes(f"refusal {name}", shape(j), shape(r), coded)


KIRUN_GET = {"GET": {"uriType": "KIRUN_FUNCTION", "kiRunFxDefinition": {"name": "echo", "namespace": APP}}}


def all_refusals():
    refusals("application name mismatch", "POST", "/api/ui/applications", {"name": "other", "appCode": APP, "clientCode": SYSTEM})
    refusals("application name with digits", "POST", "/api/ui/applications", {"name": "shell1", "appCode": "shell1", "clientCode": SYSTEM})
    refusals("function without namespace", "POST", "/api/ui/functions", {"appCode": APP, "clientCode": SYSTEM, "definition": {"name": "f"}})
    refusals("function without definition", "POST", "/api/ui/functions", {"appCode": APP, "clientCode": SYSTEM})
    refusals("schema without name", "POST", "/api/ui/schemas", {"appCode": APP, "clientCode": SYSTEM, "definition": {"namespace": "EdP"}})
    refusals("uripath without path", "POST", "/api/ui/uripaths", {"appCode": APP, "clientCode": SYSTEM})
    refusals("uripath pattern mismatch", "POST", "/api/ui/uripaths",
             {"name": "/api/edpx/{id}", "appCode": APP, "clientCode": SYSTEM, "pathString": "/other/1", "pathDefinitions": KIRUN_GET})
    refusals("uripath invalid method", "POST", "/api/ui/uripaths",
             {"name": "/api/edpx", "appCode": APP, "clientCode": SYSTEM, "pathString": "/api/edpx", "pathDefinitions": {"HEAD": KIRUN_GET["GET"]}})
    refusals("uripath invalid type", "POST", "/api/ui/uripaths",
             {"name": "/api/edpx", "appCode": APP, "clientCode": SYSTEM, "pathString": "/api/edpx", "pathDefinitions": {"GET": {}}})
    refusals("uripath without definitions", "POST", "/api/ui/uripaths",
             {"name": "/api/edpx", "appCode": APP, "clientCode": SYSTEM, "pathString": "/api/edpx"})
    zero = "000000000000000000000000"
    for kind in ["applications", "pages", "styles", "themes", "functions", "schemas", "uripaths", "filler"]:
        refusals(f"{kind} read unknown", "GET", f"/api/ui/{kind}/{zero}")
        refusals(f"{kind} update unknown", "PUT", f"/api/ui/{kind}/{zero}", {"id": zero, "name": "x", "appCode": APP, "clientCode": SYSTEM})
        refusals(f"{kind} delete unknown", "DELETE", f"/api/ui/{kind}/{zero}")
        refusals(f"{kind} nomap2", "GET", f"/api/ui/{kind}/nomap2")
        refusals(f"{kind} draft read unknown", "GET", f"/api/ui/{kind}/{zero}?draft=true")
    refusals("page components unknown", "GET", f"/api/ui/pages/{zero}/components?keys=a")
    refusals("page components without keys", "GET", f"/api/ui/pages/{zero}/components")
    refusals("page component patch unknown", "PATCH", f"/api/ui/pages/{zero}/components/a", {"componentData": {}})
    refusals("page component patch bad body", "PATCH", f"/api/ui/pages/{zero}/components/a", raw=b"[]", headers={"Content-Type": "application/json"})
    refusals("client add component unknown page", "POST", f"/api/ui/pages/{zero}/components",
             {"componentKey": "x", "componentData": {}, "parentKey": "root"})
    refusals("client add component unknown page for a client", "POST", f"/api/ui/pages/{zero}/components?clientCode={TARGET}",
             {"componentKey": "x", "componentData": {}, "parentKey": "root"})
    refusals("client remove component unknown page", "DELETE", f"/api/ui/pages/{zero}/components/a")
    refusals("client patch unknown page for a client", "PATCH", f"/api/ui/pages/{zero}/components/a?clientCode={TARGET}",
             {"componentData": {}})
    refusals("client patch bad flag", "PATCH", f"/api/ui/pages/{zero}/components/a?draft=maybe", {"componentData": {}})
    refusals("page event unknown", "GET", f"/api/ui/pages/{zero}/events/onLoad")
    refusals("page event put unknown", "PUT", f"/api/ui/pages/{zero}/events/onLoad", {"definition": {}})
    refusals("function steps unknown", "GET", f"/api/ui/functions/{zero}/steps")
    refusals("function steps patch unknown", "PATCH", f"/api/ui/functions/{zero}/steps", {"steps": {}})
    refusals("versions unknown", "GET", f"/api/ui/versions/{zero}")
    refusals("versions query unknown", "POST", f"/api/ui/versions/{zero}/query", {})
    refusals("apple certificates", "GET", "/api/ui/applications/apple/certificates")
    refusals("mobile apps list", "GET", f"/api/ui/applications/{APP}/mobileApps")
    refusals("mobile apps list anonymous", "GET", f"/api/ui/applications/{APP}/mobileApps", headers={"Authorization": None})
    refusals("mobile app without details", "POST", f"/api/ui/applications/{APP}/mobileApps", {"clientCode": SYSTEM})
    refusals("mobile app status unknown", "POST", f"/api/ui/applications/mobileApps/status/{zero}", {"status": "SUCCESS"})
    refusals("mobile app delete unknown", "DELETE", f"/api/ui/applications/{APP}/mobileApps/{zero}")
    refusals("publish pending other client", "GET", f"/api/ui/publish/app/{APP}/pending?clientCode=NOSUCH")
    refusals("transport types", "GET", "/api/ui/transports/transportTypes")
    refusals("transport plain create", "POST", "/api/ui/transports", {"name": "x"})
    refusals("wipe without headers", "DELETE", "/api/ui?deleteAppCode=edpnoneapp", headers={"X-Forwarded-Host": None})
    refusals("index of an app without objects", "GET", "/api/ui/applications/edpnoneapp/index?slim=true")
    refusals("index bad slim", "GET", f"/api/ui/applications/{APP}/index?slim=maybe")
    refusals("internal index", "GET", "/api/ui/applications/internal/index/edpnoneapp?forClientCode=SYSTEM")


def crud(side, kind, plural, create_body, edit, draft_edit, extra=None):
    """Create, read, update, draft, publish, versions and (later) delete of one object."""
    n = side.n
    c = side.write(f"{kind} create", "create", "POST", f"/api/ui/{plural}", create_body)
    i = oid(c)
    if not i:
        record("DIFF", f"{kind} create {side.tag}", f"no id: {c.status} {c.text()[:200]}")
        return None
    side.read_both(f"{kind} after create", f"/api/ui/{plural}/{i}")
    body = c.obj()
    edit(body)
    u = side.write(f"{kind} update", "update", "PUT", f"/api/ui/{plural}/{i}", body)
    side.read_both(f"{kind} after update", f"/api/ui/{plural}/{i}")
    d = u.obj() or body
    draft_edit(d)
    side.write(f"{kind} draft save", "draft", "PUT", f"/api/ui/{plural}/{i}?draft=true", d)
    side.read_both(f"{kind} draft read", f"/api/ui/{plural}/{i}?draft=true")
    side.read_both(f"{kind} live read with a draft", f"/api/ui/{plural}/{i}")
    stale = dict(d)
    side.write(f"{kind} draft save stale", "draft", "PUT", f"/api/ui/{plural}/{i}?draft=true&draftVersion=0", stale)
    if extra:
        extra(i)
    side.write(f"{kind} publish", "update", "POST", f"/api/ui/{plural}/{i}/publish?message=edp-{n}")
    side.read_both(f"{kind} after publish", f"/api/ui/{plural}/{i}")
    history = side.query_both(f"{kind} versions", f"/api/ui/versions/{i}/query", {}).obj().get("content") or []
    if history:
        side.read_both(f"{kind} version by id", f"/api/ui/versions/{history[0]['id']}")
    side.write(f"{kind} draft discard none", "draft", "DELETE", f"/api/ui/{plural}/{i}/draft")
    side.write(f"{kind} fork own", "fork", "POST", f"/api/ui/{plural}/{i}/fork")
    return i


def delete(side, kind, plural, i):
    side.write(f"{kind} delete", "delete", "DELETE", f"/api/ui/{plural}/{i}")
    side.read_both(f"{kind} after delete", f"/api/ui/{plural}/{i}")


def set_key(path, value):
    """An edit that sets one nested key, making the maps on the way."""
    def f(o):
        cur = o
        for k in path[:-1]:
            if not isinstance(cur.get(k), dict):
                cur[k] = {}
            cur = cur[k]
        cur[path[-1]] = value
    return f


def client_patches(side, ids):
    """Component changes made for a client (`clientCode`), and the add and remove routes, on a page
    of their own; everything made is deleted again through the API."""
    n = side.n
    c = side.write("client page create", "create", "POST", "/api/ui/pages",
                   {"name": f"{n}cpage", "appCode": APP, "clientCode": SYSTEM, "rootComponent": "root",
                    "componentDefinition": {
                        "root": {"key": "root", "name": "root", "type": "Grid", "children": {"txt": True, "btn": True}},
                        "txt": {"key": "txt", "name": "txt", "type": "Text", "properties": {"text": {"value": "Hello"}}},
                        "btn": {"key": "btn", "name": "btn", "type": "Button", "properties": {"label": {"value": "Submit"}}}}})
    page = oid(c)
    if not page:
        record("DIFF", f"client page create {side.tag}", f"no id: {c.status} {c.text()[:200]}")
        return
    q = f"?clientCode={TARGET}"
    first = side.write("client patch for a client", "patch", "PATCH", f"/api/ui/pages/{page}/components/btn{q}",
                       {"componentData": {"properties": {"label": {"value": f"{n} for {TARGET}"}}}, "message": "m"})
    copy = oid(first) if first.status == 200 and first.obj().get("clientCode") == TARGET else None
    side.read_both("client owner page after", f"/api/ui/pages/{page}")
    side.write("client patch own copy", "patch", "PATCH", f"/api/ui/pages/{page}/components/txt{q}",
               {"componentData": {"properties": {"text": {"value": "Hi"}}}, "message": "m"})
    side.write("client add for a client", "patch", "POST", f"/api/ui/pages/{page}/components{q}",
               {"componentKey": "extra", "componentData": {"type": "Text", "name": "extra"}, "parentKey": "root", "message": "m"})
    side.write("client remove for a client", "patch", "DELETE", f"/api/ui/pages/{page}/components/txt{q}&message=m")
    side.write("client event for a client", "patch", "PUT", f"/api/ui/pages/{page}/events/onSubmit{q}",
               {"definition": {"name": "onSubmit", "steps": {}}, "message": "m"})
    side.write("client draft for a client", "draft", "PATCH", f"/api/ui/pages/{page}/components/btn{q}&draft=true",
               {"componentData": {"properties": {"label": {"value": "draft"}}}, "message": "m"})
    if copy:
        side.read_both("client copy", f"/api/ui/pages/{copy}")
        side.read_both("client copy draft", f"/api/ui/pages/{copy}?draft=true")
    # No target: the page with the id.
    side.write("client add", "patch", "POST", f"/api/ui/pages/{page}/components",
               {"componentKey": "box", "componentData": {"type": "Grid", "name": "box"}, "parentKey": "root", "message": "m"})
    side.write("client add under it", "patch", "POST", f"/api/ui/pages/{page}/components",
               {"componentKey": "inner", "componentData": {"type": "Text", "name": "inner"}, "parentKey": "box"})
    side.write("client add existing key", "patch", "POST", f"/api/ui/pages/{page}/components",
               {"componentKey": "btn", "componentData": {"type": "Text"}, "parentKey": "root"})
    side.write("client add missing parent", "patch", "POST", f"/api/ui/pages/{page}/components",
               {"componentKey": "x", "componentData": {"type": "Text"}, "parentKey": "nope"})
    side.write("client remove subtree", "patch", "DELETE", f"/api/ui/pages/{page}/components/box?message=gone")
    side.write("client remove root", "patch", "DELETE", f"/api/ui/pages/{page}/components/root")
    side.write("client remove missing", "patch", "DELETE", f"/api/ui/pages/{page}/components/nope")
    side.read_both("client page after", f"/api/ui/pages/{page}")
    # Clean up: the target's copy (its draft first), then the page.
    if copy:
        call(side.base, "DELETE", f"/api/ui/pages/{copy}/draft")
        call(side.base, "DELETE", f"/api/ui/pages/{copy}")
    call(side.base, "DELETE", f"/api/ui/pages/{page}")
    left = call(side.base, "GET", f"/api/ui/pages?appCode={APP}&clientCode={TARGET}&size=100").obj().get("content", [])
    for p in left:
        if p.get("name") == f"{n}cpage":
            call(side.base, "DELETE", f"/api/ui/pages/{p['id']}")


def session(side):
    n = side.n
    ids = {}

    # The application (the app's own name, so made and removed in turn).
    app = crud(side, "application", "applications",
               {"name": APP, "appCode": APP, "clientCode": SYSTEM, "properties": {"title": f"{n} title"}},
               set_key(["properties", "title"], f"{n} updated"),
               set_key(["properties", "title"], f"{n} draft"))
    ids["application"] = app

    # The filler (also named after the app).
    fid = crud(side, "filler", "filler",
               {"name": APP, "appCode": APP, "clientCode": SYSTEM, "values": {"k": n}},
               set_key(["values", "k"], f"{n}-2"),
               set_key(["values", "d"], f"{n}-draft"))

    ids["style"] = crud(side, "style", "styles",
                        {"name": f"{n}style", "appCode": APP, "clientCode": SYSTEM, "styleString": ".a{color:red}"},
                        set_key(["styleString"], ".a{color:blue}"),
                        set_key(["styleString"], ".a{color:green}"))
    # One made unpublished, read on the draft surface, then published.
    u = side.write("style create unpublished", "create", "POST", "/api/ui/styles?draft=true",
                   {"name": f"{n}style2", "appCode": APP, "clientCode": SYSTEM, "styleString": ".b{}"})
    ids["style2"] = oid(u)
    if ids["style2"]:
        side.read_both("style unpublished live read", f"/api/ui/styles/{ids['style2']}")
        side.read_both("style unpublished draft read", f"/api/ui/styles/{ids['style2']}?draft=true")
        side.write("style unpublished publish", "update", "POST", f"/api/ui/styles/{ids['style2']}/publish?message=first")
        side.read_both("style unpublished after publish", f"/api/ui/styles/{ids['style2']}")

    ids["theme"] = crud(side, "theme", "themes",
                        {"name": f"{n}theme", "appCode": APP, "clientCode": SYSTEM, "variables": {"t": {"primary": "#000"}}},
                        set_key(["variables", "t", "primary"], "#111"),
                        set_key(["variables", "t", "secondary"], "#222"))

    def page_extra(i):
        side.read_both("page components", f"/api/ui/pages/{i}/components?keys=root&depth=1")
        side.read_both("page components deep", f"/api/ui/pages/{i}/components?keys=root,c&depth=2")
        side.write("page component patch stale", "patch", "PATCH", f"/api/ui/pages/{i}/components/c",
                   {"componentData": {"properties": {"label": {"value": "x"}}}, "expectedComponentVersion": 99, "message": "m"})
        side.write("page component patch missing", "patch", "PATCH", f"/api/ui/pages/{i}/components/nope",
                   {"componentData": {"properties": {}}, "message": "m"})
        side.write("page component patch", "patch", "PATCH", f"/api/ui/pages/{i}/components/c",
                   {"componentData": {"properties": {"label": {"value": f"{n} label"}}, "displayOrder": 4, "type": "Ignored"},
                    "expectedComponentVersion": 0, "message": "patched"})
        side.read_both("page after component patch", f"/api/ui/pages/{i}")
        side.read_both("page draft after component patch", f"/api/ui/pages/{i}?draft=true")
        side.read_both("page event", f"/api/ui/pages/{i}/events/onLoad")
        side.read_both("page event missing", f"/api/ui/pages/{i}/events/nope")
        side.write("page event put", "patch", "PUT", f"/api/ui/pages/{i}/events/onClick",
                   {"definition": {"name": "onClick", "steps": {}}, "message": "ev"})
        side.write("page event put stale", "patch", "PUT", f"/api/ui/pages/{i}/events/onClick",
                   {"definition": {"name": "onClick"}, "expectedEventVersion": 1})
        side.read_both("page after event put", f"/api/ui/pages/{i}")

    ids["page"] = crud(side, "page", "pages",
                       {"name": f"{n}page", "appCode": APP, "clientCode": SYSTEM, "rootComponent": "root",
                        "properties": {"title": {"name": {"value": "T"}}},
                        "componentDefinition": {
                            "root": {"key": "root", "name": "root", "type": "Grid", "children": {"a": True, "c": True}},
                            "a": {"key": "a", "name": "a", "type": "Text"},
                            "c": {"key": "c", "name": "c", "type": "Button", "properties": {"label": {"value": "Go"}}}},
                        "eventFunctions": {"onLoad": {"name": "onLoad", "steps": {}}}},
                       set_key(["properties", "title", "name", "value"], "T2"),
                       set_key(["componentDefinition", "a", "properties"], {"text": {"value": "draft"}}),
                       page_extra)

    client_patches(side, ids)

    def fn_extra(i):
        side.read_both("function steps", f"/api/ui/functions/{i}/steps")
        side.read_both("function steps named", f"/api/ui/functions/{i}/steps?names=one,nope")
        side.write("function steps patch stale", "update", "PATCH", f"/api/ui/functions/{i}/steps", {"steps": {}, "expectedVersion": 99})
        side.write("function steps patch", "update", "PATCH", f"/api/ui/functions/{i}/steps",
                   {"steps": {"two": {"statementName": "two", "name": "Print", "namespace": "System"}}})
        side.read_both("function after steps patch", f"/api/ui/functions/{i}")

    fn_def = {"namespace": "EdP", "name": f"{n}fn", "steps": {"one": {"statementName": "one", "name": "Print", "namespace": "System"}}}
    ids["function"] = crud(side, "function", "functions",
                           {"name": "ignored", "appCode": APP, "clientCode": SYSTEM, "definition": fn_def},
                           set_key(["definition", "steps", "one", "comment"], "c"),
                           set_key(["definition", "steps", "one", "comment"], "draft"),
                           fn_extra)
    side.write("function rename refused", "update", "PUT", f"/api/ui/functions/{ids['function']}",
               {"id": ids["function"], "appCode": APP, "clientCode": SYSTEM, "definition": {"namespace": "EdP", "name": "other"}})

    ids["schema"] = crud(side, "schema", "schemas",
                         {"appCode": APP, "clientCode": SYSTEM, "definition": {"namespace": "EdP", "name": f"{n}sc", "type": ["OBJECT"]}},
                         set_key(["definition", "description"], "d"),
                         set_key(["definition", "description"], "draft"))

    ids["uripath"] = crud(side, "uripath", "uripaths",
                          {"name": f"/api/{n}/{{id}}", "appCode": APP, "clientCode": SYSTEM, "pathString": f"/api/{n}/1",
                           "pathDefinitions": KIRUN_GET},
                          set_key(["pathString"], f"/api/{n}/2"),
                          set_key(["pathString"], f"/api/{n}/3"))
    side.write("uripath update refused", "update", "PUT", f"/api/ui/uripaths/{ids['uripath']}",
               {"id": ids["uripath"], "name": f"/api/{n}/{{id}}", "appCode": APP, "clientCode": SYSTEM, "pathString": "/nope",
                "pathDefinitions": KIRUN_GET})

    # The index, every kind present.
    side.read_both("index slim", f"/api/ui/applications/{APP}/index?slim=true")
    side.read_both("index full", f"/api/ui/applications/{APP}/index")
    side.read_both("index internal", f"/api/ui/applications/internal/index/{APP}?forClientCode=SYSTEM")
    side.read_both("pages list", f"/api/ui/pages?appCode={APP}&clientCode=SYSTEM")
    side.read_both("styles list eager", f"/api/ui/styles?appCode={APP}&clientCode=SYSTEM&eager=true&eagerFields=styleString")

    # Publish-all, with a pending draft of the page and the theme.
    pg = call(side.base, "GET", f"/api/ui/pages/{ids['page']}").obj()
    pg.setdefault("properties", {})["note"] = "pending"
    side.write("page draft for publish-all", "draft", "PUT", f"/api/ui/pages/{ids['page']}?draft=true", pg)
    th = call(side.base, "GET", f"/api/ui/themes/{ids['theme']}").obj()
    th.setdefault("variables", {})["p"] = {"x": "1"}
    side.write("theme draft for publish-all", "draft", "PUT", f"/api/ui/themes/{ids['theme']}?draft=true", th)
    side.read_both("publish pending", f"/api/ui/publish/app/{APP}/pending?clientCode=SYSTEM")
    side.write("publish all", "update", "POST", f"/api/ui/publish/app/{APP}?clientCode=SYSTEM")
    side.read_both("page after publish all", f"/api/ui/pages/{ids['page']}")
    side.read_both("publish pending after", f"/api/ui/publish/app/{APP}/pending?clientCode=SYSTEM")

    # A mobile app (Android only: no Apple locally).
    m = side.write("mobile app create", "mobile", "POST", f"/api/ui/applications/{APP}/mobileApps",
                   {"details": {"name": f"{n} App", "android": True}})
    mid = oid(m)
    side.read_both("mobile apps list", f"/api/ui/applications/{APP}/mobileApps")
    if mid:
        body = m.obj()
        body["details"]["description"] = "second"
        side.write("mobile app update", "mobile", "POST", f"/api/ui/applications/{APP}/mobileApps", body)
        side.write("mobile app status", "mobile", "POST", f"/api/ui/applications/mobileApps/status/{mid}",
                   {"status": "FAILED", "errorMessage": "edp test"})
        side.read_both("mobile apps after status", f"/api/ui/applications/{APP}/mobileApps")
        side.write("mobile app delete", "mobile", "DELETE", f"/api/ui/applications/{APP}/mobileApps/{mid}")

    # Transport: the page and the function out, the page removed, both back in.
    req = {"appCode": APP, "clientCode": SYSTEM, "name": f"{n}t", "fileType": "JSON",
           "objectList": {"Page": [f"{n}page"], "Function": [f"EdP.{n}fn"]}}
    t = side.write("transport export", "read", "POST", "/api/ui/transports/internal/makeTransport", req)
    exported = t.body
    zipped = side.write("transport export zip", "read", "POST", "/api/ui/transports/makeTransport", dict(req, fileType="ZIP"))
    side.writes["transport export zip"] = (dict(side.writes["transport export zip"][0], body=f"<{len(zipped.body) > 100} zip>"),) + side.writes["transport export zip"][1:]
    delete(side, "page", "pages", ids["page"])
    if t.status == 200:
        side.write("transport import", "create", "POST", f"/api/ui/transports/internal/createAndApply?fileName={n}.json",
                   raw=exported, headers={"Content-Type": "application/json"})
        lst = call(side.base, "GET", f"/api/ui/pages?appCode={APP}&clientCode=SYSTEM&size=100").obj()
        back = [p for p in lst.get("content", []) if p.get("name") == f"{n}page"]
        if back:
            ids["page"] = back[0]["id"]
            side.read_both("page after transport import", f"/api/ui/pages/{ids['page']}")
        else:
            record("DIFF", f"transport import {side.tag}", "the page did not come back")
        trs = call(side.base, "GET", f"/api/ui/transports?appCode={APP}&size=100").obj().get("content", [])
        for tr in trs:
            if n in json.dumps(tr):
                call(side.base, "DELETE", f"/api/ui/transports/{tr['id']}")

    # Deletes, the application last.
    for kind, plural in [("style", "styles"), ("theme", "themes"), ("function", "functions"), ("schema", "schemas"),
                         ("uripath", "uripaths")]:
        if ids.get(kind):
            delete(side, kind, plural, ids[kind])
    if ids.get("style2"):
        side.write("style unpublished delete", "delete", "DELETE", f"/api/ui/styles/{ids['style2']}")
    if fid:
        delete(side, "filler", "filler", fid)

    # The app wipe: the page and the application are still there.
    side.write("app wipe", "wipe", "DELETE", f"/api/ui?deleteAppCode={APP}", headers={"appCode": BUILDER})
    side.read_both("pages after wipe", f"/api/ui/pages?appCode={APP}&clientCode=SYSTEM")
    side.read_both("application after wipe", f"/api/ui/applications/{app}")
    side.read_both("uripaths after wipe", f"/api/ui/uripaths?appCode={APP}&clientCode=SYSTEM")


# ── The shell's URI paths ────────────────────────────────────────────

def snapshot_uripaths():
    lst = call(JAVA, "GET", f"/api/ui/uripaths?appCode={APP}&clientCode=SYSTEM&size=100").obj().get("content", [])
    out = []
    for row in lst:
        if row.get("name", "").startswith("/api/edp"):
            continue
        full = call(JAVA, "GET", f"/api/ui/uripaths/{row['id']}")
        if full.status != 200:
            # Read through the list row (the scratch app's paths are readable through it).
            full_obj = row
        else:
            full_obj = full.obj()
        keep = {k: full_obj.get(k) for k in ("name", "appCode", "clientCode", "pathString", "pathDefinitions", "shortCode",
                                             "headers", "permission") if full_obj.get(k) is not None}
        out.append(keep)
    return out


def restore_uripaths(saved):
    have = {r.get("name") for r in call(JAVA, "GET", f"/api/ui/uripaths?appCode={APP}&clientCode=SYSTEM&size=100").obj().get("content", [])}
    for u in saved:
        if u["name"] in have:
            continue
        r = call(JAVA, "POST", "/api/ui/uripaths", u)
        if r.status != 200:
            print(f"could not restore URI path {u['name']}: {r.status} {r.text()[:200]}")


# ── Main ─────────────────────────────────────────────────────────────

def compare_sides(j, r):
    for case, (a, ev_j, kind) in j.writes.items():
        if case not in r.writes:
            record("DIFF", f"write {case}", "Rust side never ran it")
            continue
        b, ev_r, _ = r.writes[case]
        coded = None
        if case in j.answers and case in r.answers:
            r_dec, coded = decoded(j.answers[case], r.answers[case])
            if coded and not error_parity.is_problem(coded):
                b = shape(r_dec)
        compare_shapes(f"write {case}", a, b, coded)
        if kind not in ("read", "mobile"):
            compare_evictions(case, kind, ev_j, ev_r)
    for case, a in j.reads.items():
        if case in r.reads:
            b = r.reads[case]
            if case.startswith("index"):
                # The shell's URI paths are put back between the sessions, as new objects.
                a, b = without_shell_paths(a), without_shell_paths(b)
            compare_shapes(f"read {case}", a, b)


def without_shell_paths(shape_):
    body = shape_.get("body")
    if not isinstance(body, dict) or not isinstance(body.get("uripaths"), list):
        return shape_
    body = dict(body, uripaths=[u for u in body["uripaths"] if "edp*" in json.dumps(u)])
    return dict(shape_, body=body)


def main():
    for base in (JAVA, RUST):
        try:
            call(base, "GET", "/api/ui/transports/transportTypes")
        except Exception as e:
            raise SystemExit(f"{base} is not answering: {e}")
    global JAVA_CLIENT_PATCH
    probe = call(JAVA, "POST", "/api/ui/pages/000000000000000000000000/components", {"componentKey": "x", "parentKey": "root"})
    JAVA_CLIENT_PATCH = probe.status not in (404, 405)
    print(f"Java ui {'has' if JAVA_CLIENT_PATCH else 'does not have'} the client-targeted component routes")
    bus = Bus()
    saved = snapshot_uripaths()
    print(f"scratch app {APP}: {len(saved)} shell URI paths saved")
    try:
        if "--client-only" in sys.argv:
            # Only the component changes made for a client (and the add / remove routes).
            j, r = Side("J", JAVA, bus), Side("R", RUST, bus)
            client_patches(j, {})
            client_patches(r, {})
            compare_sides(j, r)
            return report()
        all_refusals()
        j = Side("J", JAVA, bus)
        session(j)
        restore_uripaths(saved)
        r = Side("R", RUST, bus)
        session(r)
        restore_uripaths(saved)
        compare_sides(j, r)
    finally:
        restore_uripaths(saved)
    report()


def report():
    same = sum(1 for v, _, _ in RESULTS if v == "SAME")
    exp = sum(1 for v, _, _ in RESULTS if v == "EXPECTED")
    diff = sum(1 for v, _, _ in RESULTS if v == "DIFF")
    print(f"\nui-editor parity: {same} same, {exp} expected, {diff} different of {len(RESULTS)}")
    sys.exit(1 if diff else 0)


if __name__ == "__main__":
    main()
