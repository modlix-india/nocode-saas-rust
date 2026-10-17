#!/usr/bin/env python3
"""Java multi (8006) against Rust multi (8110), same requests, compared.

Usage: parity_multi.py [--writes]
  --writes also creates a scratch app through each side, updates it with a tiny JSON
  definition, and deletes it again (soft delete, then full delete). Local stack only.

Errors are compared by status and code (tools/error_parity.py): a coded Rust error whose code
stands for Java's text is put back into Java's shape, and the case is EXPECTED when everything
else then matches (crates/multi/DIFFERENCES.md, error bodies).
"""
import base64
import io
import json
import os
import sys
import urllib.error
import urllib.request
import uuid
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import error_parity  # noqa: E402

JAVA, RUST = "http://localhost:8006", "http://localhost:8110"
B = "Basic " + base64.b64encode(b"142:Pass@1234").decode()
H = {"Authorization": B, "X-Forwarded-Host": "localhost", "X-Forwarded-Port": "8080",
     "clientCode": "SYSTEM", "appCode": "appbuilder"}
HEADERS_NO_AUTH = {k: v for k, v in H.items() if k != "Authorization"}


def call(base, method, path, headers, body=None):
    data = json.dumps(body).encode() if body is not None else None
    h = dict(headers)
    if data is not None:
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def raw_call(base, method, path, headers, data):
    req = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=300) as r:
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def norm_json(b):
    try:
        v = json.loads(b)
    except ValueError:
        return b
    def strip(x):
        if isinstance(x, dict):
            return {k: strip(v) for k, v in x.items() if k not in ("exceptionId", "message", "stackTrace", "debugMessage")}
        if isinstance(x, list):
            return [strip(i) for i in x]
        return x
    return strip(v)


def zip_summary(b):
    try:
        z = zipfile.ZipFile(io.BytesIO(b))
    except zipfile.BadZipFile:
        return ("not a zip", len(b))
    out = {}
    for n in z.namelist():
        data = z.read(n)
        if n.endswith(".json"):
            out[n] = json.loads(data)
        else:
            try:
                inner = zipfile.ZipFile(io.BytesIO(data))
                out[n] = sorted(inner.namelist())
            except zipfile.BadZipFile:
                out[n] = len(data)
    return out


def compare(name, j, r, expected=None, as_zip=False):
    r, coded = error_parity.decode(j, r)
    (js, jh, jb), (rs, rh, rb) = j, r
    problems = []
    if error_parity.is_problem(coded):
        problems.append(coded)
    if js != rs:
        problems.append(f"status java={js} rust={rs}")
    if as_zip and js == 200:
        if zip_summary(jb) != zip_summary(rb):
            problems.append("zip contents differ")
        for k in ("content-type", "content-disposition"):
            if jh.get(k) != rh.get(k):
                problems.append(f"{k}: java={jh.get(k)!r} rust={rh.get(k)!r}")
    elif norm_json(jb) != norm_json(rb):
        problems.append(f"body differs: java={jb[:160]!r} rust={rb[:160]!r}")
    if not problems and coded:
        print(f"EXPECTED  {name} [{js}]: {error_parity.detail(coded)}")
        return True
    if not problems:
        print(f"SAME      {name} [{js}]")
        return True
    if expected and not error_parity.is_problem(coded):
        print(f"EXPECTED  {name}: {expected}" + (f" [{coded}]" if coded else ""))
        for p in problems:
            print(f"            {p}")
        return True
    print(f"DIFFERENT {name}")
    for p in problems:
        print(f"            {p}")
    return False


def both(method, path, headers, body=None):
    return call(JAVA, method, path, headers, body), call(RUST, method, path, headers, body)


ok = True
cases = [
    ("index leadzumptwo", "GET", "/api/multi/application/leadzumptwo/index", H, None, None),
    ("index appa", "GET", "/api/multi/application/appa/index", H, None, None),
    ("index for client", "GET", "/api/multi/application/leadzumptwo/index?clientCode=SYSTEM", H, None, None),
    ("index unknown app", "GET", "/api/multi/application/noSuchAppXyz/index", H, None, None),
    ("index types", "GET", "/api/multi/application/leadzumptwo/index?type=page,storage", H, None, None),
    ("search", "GET", "/api/multi/application/leadzumptwo/search?q=lead", H, None, None),
    ("search with type", "GET", "/api/multi/application/leadzumptwo/search?q=LEAD&type=function", H, None, None),
    ("anonymous", "GET", "/api/multi/application/leadzumptwo/index", HEADERS_NO_AUTH, None, None),
    ("missing header", "GET", "/api/multi/application/leadzumptwo/index",
     {k: v for k, v in H.items() if k != "X-Forwarded-Port"}, None, "Java 500, Rust 400"),
    ("create by appId", "POST", "/api/multi/application", H, {"appId": 843}, None),
    ("update with no definition", "POST", "/api/multi/application/update", H, {"appCode": "appa"}, None),
    ("transport needs appCode", "GET", "/api/multi/application/transport", H, None, "Java 500, Rust 400"),
    # Requests that fail before anything is written, on either side.
    ("update with an upload that is not base64", "POST", "/api/multi/application/update", H,
     {"appCode": "appa", "encodedModl": "%%%"}, "Java 500, Rust 400: the upload is the caller's input (DIFFERENCES.md)"),
    ("update from an address that answers 404", "POST", "/api/multi/application/update", H,
     {"appCode": "appa", "transportDefinitionURL": "http://localhost:8110/no-such-definition.json"},
     "Java 500, Rust 400: the address is the caller's input (DIFFERENCES.md)"),
]
for name, method, path, headers, body, expected in cases:
    ok &= compare(name, *both(method, path, headers, body), expected=expected)

for name, ctype, data in [("create without a body", None, None), ("create with a text/plain body", "text/plain", b"{}"),
                          ("create with broken JSON", "application/json", b"{nope")]:
    hs = dict(H, **({"Content-Type": ctype} if ctype else {}))
    j = raw_call(JAVA, "POST", "/api/multi/application", hs, data)
    ok &= compare(name, j, raw_call(RUST, "POST", "/api/multi/application", hs, data))

ok &= compare("transport export appa (fails in security)", *both("GET", "/api/multi/application/transport?appCode=appa", H), as_zip=True)
ok &= compare("transport export monkbars", *both("GET", "/api/multi/application/transport?appCode=monkbars", H), as_zip=True)

if "--writes" in sys.argv:
    for side, base in (("java", JAVA), ("rust", RUST)):
        # Letters only: security refuses digits and other characters in an app code.
        code = "rp" + "".join(chr(ord("a") + int(c, 16) % 26) for c in uuid.uuid4().hex[:8])
        s, _, b = call(base, "POST", "/api/multi/application", H,
                       {"appCode": code, "appName": f"Rust parity {code}", "appType": "APP"})
        app = json.loads(b) if s == 200 else {}
        print(f"{side}: create -> {s} {sorted(app.keys()) if app else b[:120]!r}")
        if s != 200:
            ok = False
            continue
        real = app.get("appCode")
        s2, _, b2 = call(base, "POST", "/api/multi/application/update", H,
                         {"appCode": real, "transportDefinition": {"security": {}, "core": {"objects": []}, "ui": {"objects": []}}})
        print(f"{side}: update -> {s2} {b2[:80]!r}")
        s3, _, b3 = call(base, "DELETE", f"/api/multi/application/{app.get('id')}", H)
        s4, _, b4 = call(base, "DELETE", f"/api/multi/application/{real}", H)
        print(f"{side}: delete soft -> {s3} {b3!r}, full -> {s4} {b4[:80]!r}")

print("\nALL SAME OR EXPECTED" if ok else "\nDIFFERENCES FOUND")
sys.exit(0 if ok else 1)
