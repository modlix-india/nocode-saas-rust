#!/usr/bin/env python3
"""Sends the same requests to the Java ui service and to ui-engine and compares them.

Usage: parity_ui.py [java_base] [rust_base] [--quick]
       defaults: http://localhost:8002  http://localhost:8102

Cases come from the local `ui` Mongo database (read with mongosh; the URI is
MODLIX__MONGO__URI in config/local.env and is never printed): every application, a sample of
pages per app (default, shell, consent, login, not-found, protected, derived-client copies),
themes by name, styles, functions, schemas, drafts (x-draft: true), unknown pages, ETag
revalidation, and a personalization round trip for user 142. Requests carry the appCode /
clientCode headers the gateway sets. Signed-in cases use local Basic auth for user 142.

Compared: status, the headers that matter, and the body. JSON bodies are parsed and compared
as values (key order is a Java HashMap's, compared separately and only reported). ETag values
differ by design (Java draws random ids, ui-engine hashes the content), so ETags are compared
by shape, and each server's ETag is replayed to that same server to check revalidation.
"""
import base64
import concurrent.futures
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
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8102"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASIC = "Basic " + base64.b64encode(b"142:Pass@1234").decode()

COMPARED = [
    "content-type", "cache-control", "pragma", "expires", "x-content-type-options", "x-xss-protection",
    "referrer-policy", "access-control-allow-origin",
]

# Differences DIFFERENCES.md explains; matched on the case name.
EXPECTED = {
    "cross-etag": "ETag ids differ by design: a Java ETag sent to ui-engine is a miss (200), and back",
}


def mongo_uri():
    with open(os.path.join(ROOT, "config", "local.env")) as f:
        for line in f:
            if line.startswith("MODLIX__MONGO__URI="):
                return line.split("=", 1)[1].strip()
    raise SystemExit("MODLIX__MONGO__URI missing from config/local.env")


def mongo(js):
    """Runs a read-only mongosh script that prints one JSON document."""
    out = subprocess.run(["mongosh", mongo_uri(), "--quiet", "--eval", js], capture_output=True, text=True, check=True)
    return json.loads(out.stdout)


CASES_JS = r"""
const apps = db.application.find({}, {appCode: 1, clientCode: 1, baseClientCode: 1, properties: 1}).toArray();
const out = {apps: [], pages: [], themes: [], functions: [], schemas: [], drafts: [], protected: []};
for (const a of apps) {
  const p = a.properties || {};
  const themes = Object.values(p.themes || {}).filter(t => t && t.name).map(t => String(t.name));
  out.apps.push({app: a.appCode, client: a.clientCode, base: a.baseClientCode || null,
    pages: [p.defaultPage, p.shellPage, p.consentPage, p.loginPage, p.notFoundPage, p.forbiddenPage]
      .filter(x => typeof x === 'string'), themes});
}
db.page.find({}, {name: 1, appCode: 1, clientCode: 1, baseClientCode: 1, permission: 1, published: 1}).forEach(d => {
  if (typeof d.name !== 'string') return;
  out.pages.push({app: d.appCode, client: d.clientCode, name: d.name, base: d.baseClientCode || null,
    permission: d.permission || null, published: d.published === undefined ? null : d.published});
});
db.function.find({name: {$type: 'string'}}, {name: 1, appCode: 1, clientCode: 1}).forEach(d => out.functions.push({app: d.appCode, client: d.clientCode, name: d.name}));
db.schema.find({name: {$type: 'string'}}, {name: 1, appCode: 1, clientCode: 1}).forEach(d => out.schemas.push({app: d.appCode, client: d.clientCode, name: d.name}));
db.draft.find({}, {objectType: 1, objectAppCode: 1, objectName: 1, clientCode: 1}).forEach(d =>
  out.drafts.push({type: d.objectType, app: d.objectAppCode, name: d.objectName, client: d.clientCode}));
print(JSON.stringify(out));
"""


def fetch(base, path, headers=None, method="GET", body=None):
    data = None if body is None else json.dumps(body).encode()
    h = dict(headers or {})
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, headers=h, method=method, data=data)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read(), r.headers.get_all("x-frame-options") or []
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(), e.headers.get_all("x-frame-options") or []


ETAG_SHAPE = re.compile(r"^W/(d-|dlg-|dnlg-|lg-|nlg-)?[0-9A-Za-z]+$")


def etag_shape(tag):
    if tag is None:
        return None
    m = re.match(r"^W/(d-|dlg-|dnlg-|lg-|nlg-)?", tag)
    return (m.group(0) if m else "?") + ("<id>" if ETAG_SHAPE.match(tag) else "<odd>")


def normalize_error(body):
    """Exception ids and stack traces are per occurrence."""
    try:
        d = json.loads(body)
    except Exception:
        return body.decode("utf-8", "replace") if isinstance(body, bytes) else body
    if isinstance(d, dict) and "exceptionId" in d:
        d = dict(d)
        eid = d.pop("exceptionId", None)
        d.pop("stackTrace", None)
        if eid and isinstance(d.get("message"), str):
            d["message"] = d["message"].replace(eid, "<id>")
        dm = d.get("debugMessage")
        if eid and isinstance(dm, str):
            d["debugMessage"] = dm.replace(eid, "<id>")
        # A coded Rust error put back into Java's shape carries Java's message, with Java's id.
        if isinstance(d.get("message"), str):
            d["message"] = re.sub(r"\d{4}-\d{2}-\d{2}-[0-9a-f]+", "<id>", d["message"])
        # Java puts the Spring text in debugMessage for unexpected errors, and Feign's text for
        # a refusal relayed from security; ui-engine repeats the message.
        if isinstance(d.get("message"), str) and d["message"].startswith("Please try again. A server error"):
            d.pop("debugMessage", None)
        if isinstance(dm, str) and re.match(r"^\[\d{3} [^\]]*\] during \[", dm):
            d["debugMessage"] = d.get("message")
        return d
    return d


def sort_type_lists(v):
    """A schema's `type` list is a HashSet of enums in Java, iterated in per-JVM order."""
    if isinstance(v, dict):
        return {k: (sorted(x) if k == "type" and isinstance(x, list) and all(isinstance(e, str) for e in x)
                    else sort_type_lists(x)) for k, x in v.items()}
    if isinstance(v, list):
        return [sort_type_lists(x) for x in v]
    return v


def key_orders(v, path="$", out=None):
    out = [] if out is None else out
    if isinstance(v, dict):
        out.append((path, list(v.keys())))
        for k, x in v.items():
            key_orders(x, path + "." + k, out)
    elif isinstance(v, list):
        for i, x in enumerate(v):
            key_orders(x, f"{path}[{i}]", out)
    return out


def ordered_pairs(pairs):
    return dict(pairs)


class Result:
    def __init__(self, name, problems, info=None, expected=None, coded=None):
        self.name, self.problems, self.info, self.expected = name, problems, info or [], expected
        # error_parity's note: "coded CODE" when Rust's coded error stands for Java's text.
        self.coded = coded


def compare(name, path, headers=None, method="GET", body=None, expected=None, etag_check=True):
    js, jh, jb, jx = fetch(JAVA, path, headers, method, body)
    rs, rh, rb, rx = fetch(RUST, path, headers, method, body)
    (rs, rh, rb), coded = error_parity.decode((js, jh, jb), (rs, rh, rb))
    problems, info = [], []
    if js != rs:
        problems.append(f"status java={js} rust={rs}")
    for k in COMPARED:
        if jh.get(k) != rh.get(k):
            problems.append(f"{k}: java={jh.get(k)!r} rust={rh.get(k)!r}")
    if sorted(jx) != sorted(rx):
        problems.append(f"x-frame-options: java={jx} rust={rx}")
    if etag_shape(jh.get("etag")) != etag_shape(rh.get("etag")):
        problems.append(f"etag shape: java={jh.get('etag')} rust={rh.get('etag')}")
    ctype = jh.get("content-type", "")
    if jb != rb:
        if "json" in ctype or (jb[:1] in (b"{", b"[") and rb[:1] in (b"{", b"[")):
            jv, rv = normalize_error(jb), normalize_error(rb)
            if "repositoryFind" in path:
                jv, rv = sort_type_lists(jv), sort_type_lists(rv)
            if (isinstance(jv, list) and isinstance(rv, list) and "repositoryFilter" in path
                    and sorted(map(str, jv)) == sorted(map(str, rv))):
                # Java merges the app's and its dependencies' lists concurrently (flatMap).
                info.append("same names, different order")
            elif jv != rv:
                problems.append(f"json body differs ({len(jb)} vs {len(rb)} bytes): {first_diff(jv, rv)}")
            else:
                try:
                    jo = key_orders(json.loads(jb, object_pairs_hook=ordered_pairs))
                    ro = key_orders(json.loads(rb, object_pairs_hook=ordered_pairs))
                    if jo != ro:
                        info.append("same value, different key order")
                except Exception:
                    pass
        else:
            problems.append(f"body differs ({len(jb)} vs {len(rb)} bytes)")
    elif jh.get("content-length") != rh.get("content-length") and js == 200:
        problems.append(f"content-length: java={jh.get('content-length')} rust={rh.get('content-length')}")

    # Revalidation: each server's own ETag must come back 304 from it.
    if etag_check and js == 200 and rs == 200 and jh.get("etag") and rh.get("etag"):
        for base, tag, label in ((JAVA, jh["etag"], "java"), (RUST, rh["etag"], "rust")):
            h2 = dict(headers or {})
            h2["If-None-Match"] = tag
            s2, h2r, _, _ = fetch(base, path, h2, method, body)
            if s2 != 304 and label == "java":
                # A cold Java cache filled by two requests at once keeps whichever random id
                # was written last; ask again with the id it holds now.
                _, h3, _, _ = fetch(base, path, headers, method, body)
                h2["If-None-Match"] = h3.get("etag", "")
                s2, h2r, _, _ = fetch(base, path, h2, method, body)
                if s2 == 304:
                    info.append("java's id changed between requests (concurrent cache fill)")
            if s2 != 304:
                problems.append(f"{label} did not revalidate its own etag: {s2}")
            elif h2r.get("cache-control") != jh.get("cache-control"):
                problems.append(f"{label} 304 cache-control {h2r.get('cache-control')!r}")
    return Result(name, problems, info, expected, coded)


def first_diff(a, b, path="$"):
    if type(a) is not type(b):
        return f"{path}: {short(a)} vs {short(b)}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k}: missing in java, rust={short(b[k])}"
            if k not in b:
                return f"{path}.{k}: java={short(a[k])}, missing in rust"
            if a[k] != b[k]:
                return first_diff(a[k], b[k], f"{path}.{k}")
    if isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: list of {len(a)} vs {len(b)}"
        for i, (x, y) in enumerate(zip(a, b)):
            if x != y:
                return first_diff(x, y, f"{path}[{i}]")
    return f"{path}: {short(a)} vs {short(b)}"


def short(v):
    s = json.dumps(v) if not isinstance(v, str) else repr(v)
    return s if len(s) < 120 else s[:117] + "..."


def hdr(app, client, auth=False, draft=False):
    h = {"appCode": app, "clientCode": client}
    if auth:
        h["Authorization"] = BASIC
    if draft:
        h["x-draft"] = "true"
    return h


def q(s):
    return urllib.parse.quote(s, safe="")


def build_cases(data):
    cases = []
    apps = data["apps"]
    if QUICK:
        apps = apps[:25]
    app_codes = {a["app"] for a in apps}
    pages_by_app = {}
    for p in data["pages"]:
        pages_by_app.setdefault(p["app"], []).append(p)

    seen = set()

    def add(name, path, headers, **kw):
        key = (path, json.dumps(headers, sort_keys=True), kw.get("method", "GET"), json.dumps(kw.get("body")))
        if key in seen:
            return
        seen.add(key)
        cases.append((name, path, headers, kw))

    for a in apps:
        app, client = a["app"], a["client"]
        for auth in (False, True):
            who = "user142" if auth else "anon"
            add(f"application {app}/{client} {who}", "/api/ui/application", hdr(app, client, auth))
            add(f"theme {app}/{client} {who}", "/api/ui/theme", hdr(app, client, auth))
            add(f"style {app}/{client} {who}", "/api/ui/style", hdr(app, client, auth))
            for p in a["pages"][:6]:
                add(f"page {app}/{client}/{p} {who}", f"/api/ui/page/{q(p)}", hdr(app, client, auth))
        for t in a["themes"][:4]:
            add(f"theme {app}/{client}?theme={t}", f"/api/ui/theme?theme={q(t)}", hdr(app, client))
            add(f"style {app}/{client}?theme={t}", f"/api/ui/style?theme={q(t)}", hdr(app, client))
        add(f"theme {app}/{client}?theme=gone", "/api/ui/theme?theme=nosuchtheme", hdr(app, client))
        add(f"unknown page {app}/{client}", "/api/ui/page/nosuchpage_parity", hdr(app, client))
        # A sample of the app's other pages, anonymous and signed in.
        own = [p for p in pages_by_app.get(app, []) if p["client"] == client][: (3 if QUICK else 8)]
        for p in own:
            add(f"page {app}/{client}/{p['name']} anon", f"/api/ui/page/{q(p['name'])}", hdr(app, client))
            add(f"page {app}/{client}/{p['name']} user142", f"/api/ui/page/{q(p['name'])}", hdr(app, client, True))

    # Every protected, derived or never-published page, both ways.
    for p in data["pages"]:
        if p["app"] not in app_codes and QUICK:
            continue
        if p["permission"] or p["base"] or p["published"] is False:
            for auth in (False, True):
                who = "user142" if auth else "anon"
                add(f"page* {p['app']}/{p['client']}/{p['name']} {who}", f"/api/ui/page/{q(p['name'])}", hdr(p["app"], p["client"], auth))

    # Derived-client apps.
    for a in data["apps"]:
        if a["base"]:
            for auth in (False, True):
                who = "user142" if auth else "anon"
                add(f"application* {a['app']}/{a['client']} {who}", "/api/ui/application", hdr(a["app"], a["client"], auth))
                add(f"theme* {a['app']}/{a['client']} {who}", "/api/ui/theme", hdr(a["app"], a["client"], auth))

    # The draft surface.
    for d in data["drafts"]:
        app, client, name = d["app"], d["client"], d["name"]
        add(f"draft application {app}/{client}", "/api/ui/application", hdr(app, client, draft=True))
        add(f"draft theme {app}/{client}", "/api/ui/theme", hdr(app, client, draft=True))
        add(f"draft style {app}/{client}", "/api/ui/style", hdr(app, client, draft=True))
        if d["type"] == "PAGE":
            add(f"draft page {app}/{client}/{name}", f"/api/ui/page/{q(name)}", hdr(app, client, draft=True))
            add(f"draft page {app}/{client}/{name} user142", f"/api/ui/page/{q(name)}", hdr(app, client, True, True))
            add(f"live page {app}/{client}/{name}", f"/api/ui/page/{q(name)}", hdr(app, client))

    # Functions: the engine route and the repository routes.
    for f in data["functions"]:
        if QUICK and f["app"] not in app_codes:
            continue
        ns, _, nm = f["name"].rpartition(".")
        add(f"function {f['app']}/{f['client']}/{f['name']}", f"/api/ui/function/{q(ns)}/{q(nm)}", hdr(f["app"], f["client"]))
        add(f"draft function {f['app']}/{f['client']}/{f['name']}", f"/api/ui/function/{q(ns)}/{q(nm)}", hdr(f["app"], f["client"], draft=True))
        add(f"repositoryFind fn {f['name']}", f"/api/ui/functions/repositoryFind?namespace={q(ns)}&name={q(nm)}",
            hdr(f["app"], f["client"]), etag_check=False)
        add(f"repositoryFind fn {f['name']} by params",
            f"/api/ui/functions/repositoryFind?appCode={q(f['app'])}&clientCode={q(f['client'])}&namespace={q(ns)}&name={q(nm)}",
            hdr("appbuilder", "SYSTEM"), etag_check=False)
    for app in sorted({f["app"] for f in data["functions"]} | {"appbuilder"}):
        add(f"repositoryFilter fn {app}", "/api/ui/functions/repositoryFilter", hdr(app, "SYSTEM"), etag_check=False)
        add(f"repositoryFilter fn {app} ?filter=a", "/api/ui/functions/repositoryFilter?filter=a", hdr(app, "SYSTEM"), etag_check=False)
    for s in data["schemas"]:
        ns, _, nm = s["name"].rpartition(".")
        add(f"repositoryFind schema {s['name']}", f"/api/ui/schemas/repositoryFind?namespace={q(ns)}&name={q(nm)}",
            hdr(s["app"], s["client"]), etag_check=False)
    for app in sorted({s["app"] for s in data["schemas"]}):
        add(f"repositoryFilter schema {app}", "/api/ui/schemas/repositoryFilter?filter=", hdr(app, "SYSTEM"), etag_check=False)
    add("repositoryFind fn missing", "/api/ui/functions/repositoryFind?namespace=No&name=Such", hdr("appbuilder", "SYSTEM"), etag_check=False)
    add("repositoryFind fn kirun System.If", "/api/ui/functions/repositoryFind?namespace=System&name=If&includeKIRunRepos=true",
        hdr("appbuilder", "SYSTEM"), etag_check=False)
    add("repositoryFilter fn with kirun", "/api/ui/functions/repositoryFilter?includeKIRunRepos=true", hdr("appbuilder", "SYSTEM"), etag_check=False)

    # Odd requests.
    add("urlDetails", "/api/ui/urlDetails", hdr("nothing", "SYSTEM"), etag_check=False)
    add("application no appCode", "/api/ui/application", {"clientCode": "SYSTEM"}, etag_check=False)
    add("page no clientCode", "/api/ui/page/home", {"appCode": "nothing"}, etag_check=False)
    add("application unknown app", "/api/ui/application", hdr("zzznoapp", "SYSTEM"))
    add("page unknown app", "/api/ui/page/home", hdr("zzznoapp", "SYSTEM"))
    add("theme unknown app", "/api/ui/theme", hdr("zzznoapp", "SYSTEM"))
    add("style unknown app", "/api/ui/style", hdr("zzznoapp", "SYSTEM"))
    add("function missing", "/api/ui/function/No/Such", hdr("appbuilder", "SYSTEM"))
    add("bad token", "/api/ui/application", dict(hdr("nothing", "SYSTEM"), Authorization="Bearer garbage"))
    add("CORS origin", "/api/ui/application", dict(hdr("nothing", "SYSTEM"), Origin="https://example.com"))
    for tag in ("", "W/zzz", "W/nlg-zzz", "W/d-zzz", "W/lg-zzz"):
        for path in ("/api/ui/application", "/api/ui/page/home", "/api/ui/theme", "/api/ui/style"):
            add(f"If-None-Match {tag!r} {path}", path, dict(hdr("nothing", "SYSTEM"), **{"If-None-Match": tag}), etag_check=False)
    return cases


def personalization_round_trip():
    """The same sequence against each server, each on its own setting name."""
    results = []
    steps = [
        ("get anon", "GET", None, False),
        ("get (none yet)", "GET", None, True),
        ("post anon (echo)", "POST", {"a": 1, "b": {"c": [1, 2.5, "x"]}, "d.e": True}, False),
        ("post create", "POST", {"z": 1, "a": {"y": 2, "x": None}, "dotted.key": "v", "f": 1.5}, True),
        ("get after create", "GET", None, True),
        ("post update", "POST", {"z": 2, "list": [3, {"k": "v"}]}, True),
        ("get after update", "GET", None, True),
        ("delete", "DELETE", None, True),
        ("get after delete", "GET", None, True),
        ("delete again (Java NPE)", "DELETE", None, True),
        ("delete anon (Java NPE)", "DELETE", None, False),
    ]
    out = {}
    for base, label in ((JAVA, "java"), (RUST, "rust")):
        name = f"parity{label.capitalize()}Setting"
        seq = []
        for step, method, body, auth in steps:
            h = {"appCode": "appbuilder", "clientCode": "SYSTEM"}
            if auth:
                h["Authorization"] = BASIC
            seq.append(fetch(base, f"/api/ui/personalization/appbuilder/{name}", h, method, body))
        out[label] = seq
    for i, (step, *_rest) in enumerate(steps):
        js, jh, jb, _ = out["java"][i]
        rs, rh, rb, _ = out["rust"][i]
        (rs, rh, rb), coded = error_parity.decode((js, jh, jb), (rs, rh, rb))
        problems = []
        if js != rs:
            problems.append(f"status java={js} rust={rs}")
        for k in ("content-type", "cache-control"):
            if jh.get(k) != rh.get(k):
                problems.append(f"{k}: java={jh.get(k)!r} rust={rh.get(k)!r}")
        jv, rv = normalize_error(jb), normalize_error(rb)
        if jv != rv:
            problems.append(f"body: {first_diff(jv, rv)}")
        elif jb != rb:
            pass
        results.append(Result(f"personalization {step}", problems, coded=coded))
    return results


def main():
    data = mongo(CASES_JS)
    cases = build_cases(data)
    print(f"{len(cases)} cases from {len(data['apps'])} apps, {len(data['pages'])} pages, "
          f"{len(data['drafts'])} drafts, {len(data['functions'])} functions, {len(data['schemas'])} schemas")
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futs = [pool.submit(compare, n, p, h, **kw) for n, p, h, kw in cases]
        for f in futs:
            results.append(f.result())
    results.extend(personalization_round_trip())

    failures, same, expected = 0, 0, 0
    notes = {}
    for r in results:
        exp = r.expected or next((v for k, v in EXPECTED.items() if r.name.startswith(k)), None)
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
