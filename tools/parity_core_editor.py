#!/usr/bin/env python3
"""Runs the same editing session against the Java core service and against core-editor and
compares the answers, the documents each write leaves behind, and the cache evictions each write
sends.

Usage: parity_core_editor.py [java_base] [rust_base]
       defaults: http://localhost:8005  http://localhost:8111

Everything happens in the scratch app `coreedparity` (a security app this script makes through
security's API when it is missing), through the APIs only, signed in as user 142 under the
`appbuilder` app, on the SYSTEM client. The app has no appData connection, so its storages are
Mongo ones and no MySQL table is made. The session runs twice: once against Java with objects
named `cedJ...`, once against Rust with `cedR...`; the filler (named after the app) is made in
turn. Each session ends with the app wipe, so nothing is left behind but version history.

Per side, in order:
- refusals both servers get the same request for (name rules, storage validation, connection
  targets, unreadable bodies, unknown ids, the schedule converter, template previews, the index,
  the run log);
- the filler, functions, schemas, storages (with relations, indexes, column definitions, a
  definition trigger, one on a schema the session then changes), connections, templates,
  notifications, event definitions (and their schedule view), event actions, workflows,
  actions: create, update, a stale update, draft save and draft read, a stale draft save,
  publish, versions, fork, delete;
- the index, publish-all with its pending list, a transport export and import, the app wipe.

Compared:
- each write's answer, Java's `cedJ` session against Rust's `cedR` one: status, content type,
  `X-Draft-Version`, and the body with ids, timestamps, table names, exception ids and the side
  names normalised (key order included);
- after each write, the object read back through BOTH servers: the two reads must be identical,
  byte for byte apart from exception ids;
- the messages each write publishes on Redis `evictionChannel` (those naming the scratch app):
  Rust must send every one Java sends; what it sends besides must be one of the additions
  crates/core/DIFFERENCES.md lists for that write.

Coded Rust errors (`code`, plain `message`, `action`...) are compared by code first
(tools/error_parity.py): when the code stands for Java's text, Rust's answer is put back into
Java's shape and compared as before, and the case reads EXPECTED (new error text, by code); a
code that does not stand for Java's text is a DIFF.

Not run here, because they write outside the scratch app: billing (`internal/billing/*` posts
charges to security for every metered app), the event raise, the cache wipe.
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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import error_parity  # noqa: E402  coded Rust errors are compared by code

ARGS = [a for a in sys.argv[1:] if not a.startswith("--")]
JAVA = ARGS[0] if len(ARGS) > 0 else "http://localhost:8005"
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8111"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

APP = "coreedparity"
BUILDER = "appbuilder"
SYSTEM = "SYSTEM"
SECURITY = "http://localhost:8001"
BASIC = "Basic " + base64.b64encode(b"142:Pass@1234").decode()
HEADERS = {
    "appCode": BUILDER,
    "clientCode": SYSTEM,
    "Authorization": BASIC,
    "X-Forwarded-Host": f"{BUILDER}.local.modlix.com",
    "X-Forwarded-Port": "443",
}
SETTLE = 0.6  # seconds a write's evictions get to arrive


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
            return [m for m in self.msgs[i:] if APP in m[1] or m[1].startswith("cmn-storageReferences")]


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


def raw_of(r):
    return (r.status, {k.lower(): v for k, v in r.headers.items()}, r.body)


def decoded(j, r):
    """Rust's answer `r` put back into Java's shape when it is a coded error whose code stands
    for Java's answer `j` (`error_parity.decode`), and the note on it."""
    (status, headers, body), note = error_parity.decode(raw_of(j), raw_of(r))
    return Resp(status, headers, body), note


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
RANDOM_KEYS = {"uniqueTransportCode", "uniqueName", "uniqueRelationId"}


def nstr(s):
    s = s.replace("cedJ", "ced*").replace("cedR", "ced*").replace("cedj", "ced*").replace("cedr", "ced*")
    # A stored transport is named `<name><uniqueTransportCode>`, the code random.
    s = re.sub(r"(ced\*t)[0-9A-Za-z]{16,24}", r"\1<code>", s)
    # A storage's table name ends in a random suffix; its caches are named after it.
    s = re.sub(r"(coreedparity_system_)[0-9a-z_-]+?(?=_(index_creation|table_creation|storage_schema))", r"\1<u>", s)
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
        if list(a) != list(b) and not any("ced*" in k for k in a):
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
    "refusal schema without definition": "a null definition is Java's NullPointerException: both 500, the text is the JVM's",
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


JVM_ORDER_NOTE = "only the key order of a page, its pageable or sort orders, or a zone differs, which Java picks per JVM run (core DIFFERENCES E13)"


def jvm_orders_sorted(v, key=None):
    """Sorts the keys of the maps whose order Java picks per JVM run: a `Page`, its `pageable` and
    its `Sort.Order`s (Jackson orders their getters as `getDeclaredMethods` lists them, which
    HotSpot sorts by symbol address) and the schedule zones (`Map.of`, whose iteration order
    follows a per-run salt). Rust writes one fixed order; Java's flips between restarts."""
    if isinstance(v, dict):
        sort = (key == "pageable" or set(v) == {"zone", "label"} or {"direction", "property", "ascending"} <= set(v)
                or {"pageable", "totalElements", "numberOfElements"} <= set(v))
        items = sorted(v.items()) if sort else v.items()
        return {k: jvm_orders_sorted(x, k) for k, x in items}
    if isinstance(v, list):
        return [jvm_orders_sorted(x) for x in v]
    return v


def compare_shapes(name, a, b, coded=None):
    if error_parity.is_problem(coded):
        return record("DIFF", name, coded)
    if coded and (ordered_equal(a, b) or same_but_side_ordered(a, b)):
        return record("EXPECTED", name, error_parity.detail(coded))
    if coded:
        name = f"{name} [{coded}]"
    if ordered_equal(a, b):
        return record("SAME", name)
    d = first_diff(a, b)
    if same_but_side_ordered(a, b):
        return record("SAME", name)
    if ordered_equal(jvm_orders_sorted(a), jvm_orders_sorted(b)) or same_but_side_ordered(jvm_orders_sorted(a), jvm_orders_sorted(b)):
        return record("EXPECTED", name, JVM_ORDER_NOTE + " (" + d + ")")
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

# The evictions Rust adds, per kind of write (core DIFFERENCES.md, "core-editor").
ADDED = {
    "delete": "delete clears every client's cached copy (`<cache>:*`), not only the deleting client's key",
    "wipe": "the app wipe clears each name's caches, live and draft, and deletes the shared entries",
    "draft": "a filler's draft save or discard clears its FILLER_READ cache too",
    "fork": "a filler's fork (an evictDraft) clears its FILLER_READ cache too",
}


def eviction_set(msgs):
    return {("evict", nstr(m)) for ch, m in msgs if ch == "evictionChannel"}


def allowed_extra(kind, msg, java):
    _, m = msg
    if kind == "delete":
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
        self.n = "ced" + tag
        self.writes = {}  # case -> (shape, evictions, kind)
        self.reads = {}  # case -> shape (side-neutral)
        self.answers = {}  # case -> the write's answer as received, for comparing coded errors

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
        r, coded = decoded(j, call(RUST, "GET", path, headers=headers))
        a, b = shape(j, False), shape(r, False)
        if error_parity.is_problem(coded):
            record("DIFF", f"cross-read {self.tag} {case}", coded)
        elif coded and ordered_equal(a, b):
            record("EXPECTED", f"cross-read {self.tag} {case}", error_parity.detail(coded))
        elif ordered_equal(a, b):
            record("SAME", f"cross-read {self.tag} {case}")
        elif ordered_equal(jvm_orders_sorted(a), jvm_orders_sorted(b)):
            record("EXPECTED", f"cross-read {self.tag} {case}", JVM_ORDER_NOTE + " (" + first_diff(a, b) + ")")
        elif re.search(r"(filler|notification|workflow) version by id$", case) and j.status == r.status == 200 and not j.body and r.body:
            record("EXPECTED", f"cross-read {self.tag} {case}",
                   "Java's VersionService has no authority name for FILLER / NOTIFICATION / WORKFLOW and refuses their rows; "
                   "the editor checks them with the application's, the notification's and the workflow's authorities")
        else:
            record("DIFF", f"cross-read {self.tag} {case}", first_diff(a, b) or "headers")
        self.reads[case] = shape(r)
        return j

    def query_both(self, case, path, body):
        j = call(JAVA, "POST", path, body)
        r, coded = decoded(j, call(RUST, "POST", path, body))
        a, b = shape(j, False), shape(r, False)
        same = ordered_equal(a, b)
        if error_parity.is_problem(coded):
            record("DIFF", f"cross-read {self.tag} {case}", coded)
        elif same and coded:
            record("EXPECTED", f"cross-read {self.tag} {case}", error_parity.detail(coded))
        elif not same and ordered_equal(jvm_orders_sorted(a), jvm_orders_sorted(b)):
            record("EXPECTED", f"cross-read {self.tag} {case}", JVM_ORDER_NOTE + " (" + first_diff(a, b) + ")")
        else:
            record("SAME" if same else "DIFF", f"cross-read {self.tag} {case}", "" if same else (first_diff(a, b) or "headers"))
        self.reads[case] = shape(r)
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
    r, coded = decoded(j, call_retrying(RUST, method, path, body, headers, raw))
    if r.headers.get("www-authenticate"):
        record("DIFF", f"refusal {name} WWW-Authenticate", "Rust sends WWW-Authenticate")
    elif j.headers.get("www-authenticate"):
        record("EXPECTED", f"refusal {name} WWW-Authenticate",
               "the running Java core predates aca9929dd, which dropped WWW-Authenticate from 401s")
    compare_shapes(f"refusal {name}", shape(j), shape(r), coded)


def ensure_app():
    """The scratch app, made through security's API when it is missing."""
    r = call(SECURITY, "GET", f"/api/security/applications/appCode/{APP}")
    if r.status == 200 and r.obj().get("appCode") == APP:
        return
    made = call(SECURITY, "POST", "/api/security/applications",
                {"appCode": APP, "appName": "Core Editor Parity (scratch)", "appType": "APP", "appAccessType": "OWN"})
    if made.status != 200:
        raise SystemExit(f"could not make the scratch app {APP}: {made.status} {made.text()[:200]}")


def all_refusals():
    zero = "000000000000000000000000"
    refusals("function without namespace", "POST", "/api/core/functions", {"appCode": APP, "clientCode": SYSTEM, "definition": {"name": "f"}})
    refusals("function without definition", "POST", "/api/core/functions", {"appCode": APP, "clientCode": SYSTEM})
    refusals("schema without name", "POST", "/api/core/schemas", {"appCode": APP, "clientCode": SYSTEM, "definition": {"namespace": "CedP"}})
    refusals("schema without definition", "POST", "/api/core/schemas", {"appCode": APP, "clientCode": SYSTEM})
    st = lambda name, schema, **kw: dict({"name": name, "appCode": APP, "clientCode": SYSTEM, "schema": schema}, **kw)
    refusals("storage unknown schema type", "POST", "/api/core/storages",
             st("cedxa", {"type": "OBJECT", "properties": {"price": {"type": "NOTATYPE"}}}))
    refusals("storage schema not an object", "POST", "/api/core/storages", st("cedxb", {"type": "STRING"}))
    refusals("storage field name with a dot", "POST", "/api/core/storages",
             st("cedxc", {"type": "OBJECT", "properties": {"a.b": {"type": "STRING"}}}))
    refusals("storage column of no field", "POST", "/api/core/storages",
             st("cedxd", OBJ, columnDefinitions={"nope": {"mysql": {"type": "INT"}}}))
    refusals("storage column without a length", "POST", "/api/core/storages",
             st("cedxe", OBJ, columnDefinitions={"title": {"mysql": {"type": "VARCHAR"}}}))
    refusals("storage relation on a schema field", "POST", "/api/core/storages",
             st("cedxf", OBJ, relations={"title": {"storageName": "x"}}))
    refusals("storage relation to nothing", "POST", "/api/core/storages",
             st("cedxg", OBJ, relations={"owner": {"storageName": "cedxnone"}}))
    refusals("storage relation unreadable", "POST", "/api/core/storages",
             st("cedxh", OBJ, relations={"owner": {"relationType": "SIDEWAYS"}}))
    refusals("storage trigger key unreadable", "POST", "/api/core/storages", st("cedxi", OBJ, triggers={"WHENEVER": ["a.b"]}))
    refusals("connection to the inside", "POST", "/api/core/connections",
             {"name": "cedxconn", "appCode": APP, "clientCode": SYSTEM, "connectionType": "REST_API",
              "connectionDetails": {"url": "http://127.0.0.1:8080/x"}})
    refusals("connection type unknown", "POST", "/api/core/connections",
             {"name": "cedxconn", "appCode": APP, "clientCode": SYSTEM, "connectionType": "NOPE"})
    refusals("workflow without trigger", "POST", "/api/core/workflows", {"name": "cedxw", "appCode": APP, "clientCode": SYSTEM})
    refusals("workflow with a step", "POST", "/api/core/workflows",
             {"name": "cedxw", "appCode": APP, "clientCode": SYSTEM, "trigger": {"eventName": "e"}, "steps": {"a": {"stepName": "a"}}})
    refusals("event action task type unknown", "POST", "/api/core/eventActions",
             {"name": "cedxea", "appCode": APP, "clientCode": SYSTEM, "tasks": {"t": {"type": "NOPE"}}})
    for kind in ["functions", "schemas", "storages", "connections", "templates", "notifications", "eventDefinitions",
                 "eventActions", "workflows", "workflow/actions", "filler"]:
        refusals(f"{kind} read unknown", "GET", f"/api/core/{kind}/{zero}")
        refusals(f"{kind} update unknown", "PUT", f"/api/core/{kind}/{zero}",
                 {"id": zero, "name": "x", "appCode": APP, "clientCode": SYSTEM, "definition": {"namespace": "A", "name": "x"}})
        refusals(f"{kind} delete unknown", "DELETE", f"/api/core/{kind}/{zero}")
        refusals(f"{kind} nomap2", "GET", f"/api/core/{kind}/nomap2")
        refusals(f"{kind} draft read unknown", "GET", f"/api/core/{kind}/{zero}?draft=true")
        refusals(f"{kind} list", "GET", f"/api/core/{kind}?appCode={APP}&clientCode=SYSTEM")
    refusals("versions unknown", "GET", f"/api/core/versions/{zero}")
    refusals("versions query unknown", "POST", f"/api/core/versions/{zero}/query", {})
    refusals("publish pending", "GET", f"/api/core/publish/app/{APP}/pending?clientCode=SYSTEM")
    refusals("transport types", "GET", "/api/core/transports/transportTypes")
    refusals("transport plain create", "POST", "/api/core/transports", {"name": "x"})
    refusals("wipe without headers", "DELETE", "/api/core?deleteAppCode=cednoneapp", headers={"X-Forwarded-Host": None})
    refusals("index without appCode", "GET", "/api/core/index")
    refusals("index of the app", "GET", f"/api/core/index?appCode={APP}")
    refusals("internal index", "GET", f"/api/core/index/internal/{APP}?forClientCode=SYSTEM")
    refusals("schedule zones", "GET", "/api/core/eventDefinitions/schedule/zones")
    refusals("schedule toCron anonymous", "POST", "/api/core/eventDefinitions/schedule/toCron", {}, headers={"Authorization": None})
    refusals("schedule toCron weekly", "POST", "/api/core/eventDefinitions/schedule/toCron?timezone=Asia/Kolkata",
             {"frequency": "weekly", "hour": 9, "minute": 30, "days": [1, 3]})
    refusals("schedule toCron hours", "POST", "/api/core/eventDefinitions/schedule/toCron?timezone=Asia/Kolkata",
             {"frequency": "hours", "every": 6, "hour": 2, "minute": 15})
    refusals("schedule toCron monthly", "POST", "/api/core/eventDefinitions/schedule/toCron?timezone=America/New_York",
             {"frequency": "monthly", "hour": 23, "minute": 0, "dayOfMonth": "L"})
    refusals("schedule toCron off", "POST", "/api/core/eventDefinitions/schedule/toCron", {})
    refusals("schedule toCron unknown frequency", "POST", "/api/core/eventDefinitions/schedule/toCron", {"frequency": "yearly"})
    refusals("schedule toCron unreadable", "POST", "/api/core/eventDefinitions/schedule/toCron", raw=b"[]",
             headers={"Content-Type": "application/json"})
    for cron in ["0 9 * * MON-FRI", "*/15 * * * *", "30 3 L * *", "61 * * * *", "@daily", "0 0 9 * * *", ""]:
        refusals(f"schedule fromCron {cron!r}", "POST", "/api/core/eventDefinitions/schedule/fromCron?timezone=Europe/London",
                 {"cron": cron, "cronZone": "UTC"})
    refusals("schedules of an event", "GET", f"/api/core/eventDefinitions/schedules?appCode={APP}&name=cedxnone")
    refusals("schedules without name", "GET", f"/api/core/eventDefinitions/schedules?appCode={APP}")
    refusals("template preview", "POST", "/api/core/templates/preview",
             {"template": {"templateParts": {"en": {"subject": "Hi ${name}", "body": "<p>${missing}x ${n}</p>"}},
                           "sampleData": {"name": "Ann", "n": 1234567}}})
    refusals("template preview language", "POST", "/api/core/templates/preview",
             {"template": {"templateParts": {"en": {"s": "E"}, "fr": {"s": "F"}}, "defaultLanguage": "fr"}, "language": "en"})
    refusals("template preview empty", "POST", "/api/core/templates/preview", {})
    refusals("template preview unreadable", "POST", "/api/core/templates/preview", {"template": 3})
    refusals("notification internal none", "GET",
             f"/api/core/notifications/internal/cedxnone?appCode={APP}&clientCode=SYSTEM&urlClientCode=SYSTEM")
    refusals("notification internal without params", "GET", "/api/core/notifications/internal/x?appCode=" + APP)
    refusals("event runs of the app", "GET", f"/api/core/eventRuns?appCode={APP}")
    refusals("anonymous storage read", "GET", f"/api/core/storages/{zero}", headers={"Authorization": None})


OBJ = {"type": "OBJECT", "properties": {"title": {"type": "STRING"}, "price": {"type": "STRING"}}}


def crud(side, kind, plural, create_body, edit, draft_edit, extra=None):
    """Create, read, update, draft, publish, versions, fork of one object; the delete is later."""
    n = side.n
    c = side.write(f"{kind} create", "create", "POST", f"/api/core/{plural}", create_body)
    i = oid(c)
    if not i:
        # Refused on both sides (the caller lacks the authority, say): the refusals are compared.
        return None
    side.read_both(f"{kind} after create", f"/api/core/{plural}/{i}")
    body = c.obj()
    edit(body)
    u = side.write(f"{kind} update", "update", "PUT", f"/api/core/{plural}/{i}", body)
    side.read_both(f"{kind} after update", f"/api/core/{plural}/{i}")
    stale = side.write(f"{kind} update stale", "update", "PUT", f"/api/core/{plural}/{i}", body)
    d = u.obj() or body
    draft_edit(d)
    side.write(f"{kind} draft save", "draft", "PUT", f"/api/core/{plural}/{i}?draft=true", d)
    side.read_both(f"{kind} draft read", f"/api/core/{plural}/{i}?draft=true")
    side.read_both(f"{kind} live read with a draft", f"/api/core/{plural}/{i}")
    side.write(f"{kind} draft save stale", "draft", "PUT", f"/api/core/{plural}/{i}?draft=true&draftVersion=0", d)
    if extra:
        extra(i)
    side.write(f"{kind} publish", "update", "POST", f"/api/core/{plural}/{i}/publish?message=ced-{n}")
    side.read_both(f"{kind} after publish", f"/api/core/{plural}/{i}")
    history = side.query_both(f"{kind} versions", f"/api/core/versions/{i}/query", {}).obj().get("content") or []
    if history:
        side.read_both(f"{kind} version by id", f"/api/core/versions/{history[0]['id']}")
    side.write(f"{kind} draft discard none", "draft", "DELETE", f"/api/core/{plural}/{i}/draft")
    side.write(f"{kind} fork own", "fork", "POST", f"/api/core/{plural}/{i}/fork")
    del stale
    return i


def delete(side, kind, plural, i):
    if not i:
        return
    side.write(f"{kind} delete", "delete", "DELETE", f"/api/core/{plural}/{i}")
    side.read_both(f"{kind} after delete", f"/api/core/{plural}/{i}")


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


def session(side):
    n = side.n
    ids = {}
    base = {"appCode": APP, "clientCode": SYSTEM}

    ids["filler"] = crud(side, "filler", "filler", dict(base, name=APP, values={"k": n}),
                         set_key(["values", "k"], f"{n}-2"), set_key(["values", "d"], f"{n}-draft"))

    fn_def = {"namespace": "CedP", "name": f"{n}fn",
              "steps": {"one": {"statementName": "one", "name": "Print", "namespace": "System"}}}
    ids["function"] = crud(side, "function", "functions", dict(base, name="ignored", definition=fn_def),
                           set_key(["definition", "steps", "one", "comment"], "c"),
                           set_key(["definition", "steps", "one", "comment"], "draft"))
    if ids["function"]:
        side.write("function rename refused", "update", "PUT", f"/api/core/functions/{ids['function']}",
                   dict(base, id=ids["function"], version=99, definition={"namespace": "CedP", "name": "other"}))

    sc_def = {"namespace": "CedP", "name": f"{n}sc", "type": "OBJECT", "properties": {"a": {"type": "STRING"}}}
    ids["schema"] = crud(side, "schema", "schemas", dict(base, definition=sc_def),
                         set_key(["definition", "description"], "d"), set_key(["definition", "description"], "draft"))

    # A storage on the schema, a storage it relates to, and one with everything a table needs.
    ids["cat"] = side.write("storage target create", "create", "POST", "/api/core/storages",
                            dict(base, name=f"{n}cat", schema={"type": "OBJECT", "properties": {"label": {"type": "STRING"}}})).obj().get("id")
    full = dict(base, name=f"{n}st", schema=OBJ,
                relations={"category": {"storageName": f"{n}cat", "relationType": "TO_ONE", "junk": 1}},
                indexes={"byTitle": {"fields": [{"fieldName": "title"}]}},
                textIndexFields=["title"],
                columnDefinitions={"price": {"mongo": {"bsonType": "DECIMAL128"}}},
                triggers={"BEFORE_UPDATE_STORAGE": ["CedP.noSuchFunction"]},
                isAudited=True, readAuth="Authorities.Logged_IN")
    ids["storage"] = crud(side, "storage", "storages", full,
                          set_key(["schema", "properties", "extra"], {"type": "STRING"}),
                          set_key(["schema", "properties", "drafted"], {"type": "STRING"}))
    ids["refstorage"] = side.write("storage on a schema create", "create", "POST", "/api/core/storages",
                                   dict(base, name=f"{n}ref", schema={"ref": f"CedP.{n}sc"})).obj().get("id")
    if ids["schema"]:
        # The schema changes: the storages standing on it are rebuilt (no table on Mongo).
        sc = call(side.base, "GET", f"/api/core/schemas/{ids['schema']}").obj()
        set_key(["definition", "properties", "b"], {"type": "STRING"})(sc)
        side.write("schema update with a storage on it", "update", "PUT", f"/api/core/schemas/{ids['schema']}", sc)

    ids["connection"] = crud(side, "connection", "connections",
                             dict(base, name=f"{n}conn", connectionType="MAIL", connectionSubType="SMTP",
                                  connectionDetails={"user": "u", "password": "p", "nested": {"apiKey": "k", "keep": 1}}),
                             set_key(["connectionDetails", "user"], "u2"), set_key(["connectionDetails", "user"], "u3"))
    if ids["connection"]:
        reader = {"x-reader": "1"}
        del reader

    ids["template"] = crud(side, "template", "templates",
                           dict(base, name=f"{n}tpl", templateType="MAIL", defaultLanguage="en",
                                templateParts={"en": {"subject": "Hi ${name}", "body": "<p>${name}</p>"}},
                                sampleData={"name": "Ann"}),
                           set_key(["toExpression"], "x@y.z"), set_key(["templateParts", "en", "subject"], "Hey ${name}"))
    ids["notification"] = crud(side, "notification", "notifications",
                               dict(base, name=f"{n}nt", channelTemplates={"email": {"templateParts": {"en": {"s": "x"}}, "junk": 1}},
                                    channelEnabled={"email": True}),
                               set_key(["channelEnabled", "email"], False), set_key(["defaultLanguage"], "en"))
    side.read_both("notification internal",
                   f"/api/core/notifications/internal/{n}nt?appCode={APP}&clientCode=SYSTEM&urlClientCode=SYSTEM")
    ids["eventDefinition"] = crud(side, "eventDefinition", "eventDefinitions",
                                  dict(base, name=f"{n}ev", schema={"type": "OBJECT"},
                                       schedule={"cron": "0 9 * * *", "perClient": "true", "enabled": False, "junk": 1}),
                                  set_key(["schedule", "timezone"], "Asia/Kolkata"), set_key(["schedule", "spread"], True))
    side.read_both("event schedules", f"/api/core/eventDefinitions/schedules?appCode={APP}&name={n}ev&timezone=UTC")
    ids["eventAction"] = crud(side, "eventAction", "eventActions",
                              dict(base, name=f"{n}ev", tasks={"t1": {"key": "t1", "order": "1", "type": "CALL_CORE_FUNCTION",
                                                                      "parameters": {"functionName": "x"}}}),
                              set_key(["tasks", "t1", "order"], 2), set_key(["tasks", "t2"], {"key": "t2", "type": "SEND_EMAIL"}))
    ids["workflow"] = crud(side, "workflow", "workflows", dict(base, name=f"{n}wf", trigger={"eventName": "e"}, startAuth="A"),
                           set_key(["startAuth"], "B"), set_key(["startAuth"], "C"))
    ids["action"] = crud(side, "action", "workflow/actions",
                         dict(base, name=f"{n}ac", functionNamespace="CedP", functionName="f", properties={"p": "1"}),
                         set_key(["properties", "p"], "2"), set_key(["properties", "q"], "3"))

    side.read_both("index", f"/api/core/index?appCode={APP}")
    side.read_both("index internal", f"/api/core/index/internal/{APP}?forClientCode=SYSTEM")
    side.read_both("storages list", f"/api/core/storages?appCode={APP}&clientCode=SYSTEM")

    # Publish-all, with pending drafts.
    if ids["function"]:
        f = call(side.base, "GET", f"/api/core/functions/{ids['function']}").obj()
        set_key(["definition", "steps", "one", "comment"], "pending")(f)
        side.write("function draft for publish-all", "draft", "PUT", f"/api/core/functions/{ids['function']}?draft=true", f)
    side.read_both("publish pending", f"/api/core/publish/app/{APP}/pending?clientCode=SYSTEM")
    side.write("publish all", "update", "POST", f"/api/core/publish/app/{APP}?clientCode=SYSTEM")
    side.read_both("publish pending after", f"/api/core/publish/app/{APP}/pending?clientCode=SYSTEM")

    # Transport: the function and the storages out, the function removed, all back in.
    req = {"appCode": APP, "clientCode": SYSTEM, "name": f"{n}t", "fileType": "JSON",
           "objectList": {"Function": [f"CedP.{n}fn"], "Storage": [f"{n}cat", f"{n}st"], "Schema": [f"CedP.{n}sc"]}}
    t = side.write("transport export", "read", "POST", "/api/core/transports/internal/makeTransport", req)
    delete(side, "function", "functions", ids["function"])
    if t.status == 200:
        side.write("transport import", "create", "POST", f"/api/core/transports/internal/createAndApply?fileName={n}.json",
                   raw=t.body, headers={"Content-Type": "application/json"})
        lst = call(side.base, "GET", f"/api/core/functions?appCode={APP}&clientCode=SYSTEM&size=100").obj()
        back = [x for x in lst.get("content", []) if x.get("name") == f"CedP.{n}fn"]
        if back:
            side.read_both("function after transport import", f"/api/core/functions/{back[0]['id']}")
        else:
            record("DIFF", f"transport import {side.tag}", "the function did not come back")
        for tr in call(side.base, "GET", f"/api/core/transports?appCode={APP}&size=100").obj().get("content", []):
            if n in json.dumps(tr):
                call(side.base, "DELETE", f"/api/core/transports/{tr['id']}")

    for kind, plural in [("action", "workflow/actions"), ("workflow", "workflows"), ("eventAction", "eventActions"),
                         ("eventDefinition", "eventDefinitions"), ("notification", "notifications"), ("template", "templates"),
                         ("connection", "connections"), ("refstorage", "storages"), ("storage", "storages"), ("cat", "storages"),
                         ("schema", "schemas"), ("filler", "filler")]:
        delete(side, kind, plural, ids.get(kind))

    # The app wipe, with something still there.
    side.write("function for the wipe", "create", "POST", "/api/core/functions",
               dict(base, definition={"namespace": "CedP", "name": f"{n}wipe"}))
    side.write("app wipe", "wipe", "DELETE", f"/api/core?deleteAppCode={APP}", headers={"appCode": BUILDER})
    side.read_both("functions after wipe", f"/api/core/functions?appCode={APP}&clientCode=SYSTEM")


def compare_sides(j, r):
    for case, (a, ev_j, kind) in j.writes.items():
        if case not in r.writes:
            record("DIFF", f"write {case}", "Rust side never ran it")
            continue
        b, ev_r, _ = r.writes[case]
        coded = None
        if case in j.answers and case in r.answers:
            answer, coded = decoded(j.answers[case], r.answers[case])
            if coded:
                b = shape(answer)
        compare_shapes(f"write {case}", a, b, coded)
        if kind not in ("read",):
            compare_evictions(case, kind, ev_j, ev_r)
    for case, a in j.reads.items():
        if case in r.reads:
            compare_shapes(f"read {case}", a, r.reads[case])


def main():
    for base in (JAVA, RUST):
        try:
            call(base, "GET", "/api/core/transports/transportTypes")
        except Exception as e:
            raise SystemExit(f"{base} is not answering: {e}")
    ensure_app()
    bus = Bus()
    all_refusals()
    j = Side("J", JAVA, bus)
    session(j)
    r = Side("R", RUST, bus)
    session(r)
    compare_sides(j, r)
    same = sum(1 for v, _, _ in RESULTS if v == "SAME")
    exp = sum(1 for v, _, _ in RESULTS if v == "EXPECTED")
    diff = sum(1 for v, _, _ in RESULTS if v == "DIFF")
    print(f"\ncore-editor parity: {same} same, {exp} expected, {diff} different of {len(RESULTS)}")
    sys.exit(1 if diff else 0)


if __name__ == "__main__":
    main()
