#!/usr/bin/env python3
"""Sends the same requests to the Java files service and to files-manage and compares them.

Usage: parity_files_manage.py [java_base] [rust_base] [rust_serve_base]
       defaults: http://localhost:8003  http://localhost:8104  http://localhost:8103

Both services share one database and one bucket, so every write runs on each side in a scratch
folder of its own (client SYSTEM, static and secured `_rustparity/<run>-j` and `-r`), and the
comparison maps one folder name onto the other. Everything created is deleted at the end
(secured access keys cannot be deleted through the API and are left behind, pointing at files
that no longer exist).

Responses are compared on status, content type and body. Bodies are compared as JSON with these
normalisations: the side's folder name, ids of rows each side created, write times
(`createdDate`, `lastModifiedTime`: within two minutes), `createdAt` / `updatedAt` (equal, or
off by the Java JVM's UTC offset: Jackson writes a LocalDateTime read in the JVM's zone as if it
were UTC, so a Java service on an IST machine is 19800 s ahead), and the per-error
`exceptionId`, `stackTrace`, `debugMessage`. Cases whose difference is listed in
crates/files/DIFFERENCES.md are reported as EXPECTED.
"""
import base64
import io
import json
import random
import re
import string
import struct
import sys
import time
import urllib.error
import urllib.request
import zipfile
import zlib

import error_parity  # coded Rust errors are compared by code (crates/files/DIFFERENCES.md, Error bodies)

JAVA = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8003"
RUST = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8104"
SERVE = sys.argv[3] if len(sys.argv) > 3 else "http://localhost:8103"

AUTH = {
    "Authorization": "Basic " + base64.b64encode(b"142:Pass@1234").decode(),
    "clientCode": "SYSTEM",
    "appCode": "appbuilder",
}
RUN = "".join(random.choice(string.ascii_lowercase) for _ in range(6))
FOLDER = {"j": f"{RUN}-j", "r": f"{RUN}-r"}
BASE = {"j": JAVA, "r": RUST}
TZ_SKEWS = {0, 19800, -19800}

results = []  # (status, name, details)


# ------------------------------------------------------------------------------------------------
# HTTP


def call(base, method, path, headers=None, body=None, auth=True):
    h = dict(AUTH) if auth else {}
    h.update(headers or {})
    req = urllib.request.Request(base + path, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def multipart(fields=(), files=()):
    boundary = "----parity" + "".join(random.choice(string.digits) for _ in range(16))
    out = io.BytesIO()
    for name, value in fields:
        out.write(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n".encode())
        out.write(value.encode() + b"\r\n")
    for name, filename, ctype, data in files:
        out.write(
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
            f"Content-Type: {ctype}\r\n\r\n".encode()
        )
        out.write(data + b"\r\n")
    out.write(f"--{boundary}--\r\n".encode())
    return {"Content-Type": f"multipart/form-data; boundary={boundary}"}, out.getvalue()


def png(w, h, rgba=(200, 30, 30, 255)):
    raw = b"".join(b"\x00" + bytes(rgba) * w for _ in range(h))
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def png_size(data):
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        return None
    return struct.unpack(">II", data[16:24])


# ------------------------------------------------------------------------------------------------
# Normalisation and comparison


def sub_folder(text, side):
    """The side's folder name and run token, mapped to placeholders."""
    return text.replace(FOLDER[side], "<F>").replace(FOLDER["j" if side == "r" else "r"], "<F>")


def as_json(body):
    try:
        return json.loads(body)
    except Exception:
        return None


def normalise_pair(j, r, path=""):
    """Walks both values together; returns (j', r') with tolerated differences replaced."""
    if isinstance(j, dict) and isinstance(r, dict):
        jj, rr = {}, {}
        for k in set(j) | set(r):
            if k in ("exceptionId", "stackTrace", "debugMessage") or k in DROP:
                continue
            if k in j and k in r:
                a, b = normalise_pair(j[k], r[k], k)
                jj[k], rr[k] = a, b
            elif k in j:
                jj[k] = j[k]
            else:
                rr[k] = r[k]
        return jj, rr
    if isinstance(j, list) and isinstance(r, list) and len(j) == len(r):
        pairs = [normalise_pair(a, b, path) for a, b in zip(j, r)]
        return [p[0] for p in pairs], [p[1] for p in pairs]
    if isinstance(j, int) and isinstance(r, int) and not isinstance(j, bool):
        if path in ("id", "ownPolicyId", "managedPolicyId", "appPolicyId") and IDS_VARY:
            return "<id>", "<id>"
        if path in ("createdDate", "lastModifiedTime") and abs(j - r) < 120:
            return "<t>", "<t>"
        if path in ("createdAt", "updatedAt") and any(abs(j - r - s) < 120 for s in TZ_SKEWS):
            return "<ts>", "<ts>"
    return j, r


IDS_VARY = True
DROP = set()


def compare(name, j, r, expected=None, body="json", ids_vary=True, ignore_headers=False, drop=()):
    """j, r: (status, headers, body) from Java and Rust. `drop`: keys left out of the comparison."""
    global IDS_VARY, DROP
    IDS_VARY = ids_vary
    DROP = set(drop)
    r, coded = error_parity.decode(j, r)
    problems = []
    if error_parity.is_problem(coded):
        problems.append(coded)
    if j[0] != r[0]:
        problems.append(f"status java={j[0]} rust={r[0]}")
    jct = (j[1].get("content-type") or "").replace(" ", "").lower()
    rct = (r[1].get("content-type") or "").replace(" ", "").lower()
    if not ignore_headers and jct != rct and j[0] < 500 and r[0] < 500 and j[0] == r[0]:
        problems.append(f"content-type java={jct!r} rust={rct!r}")
    jb = sub_folder(j[2].decode("utf-8", "replace"), "j")
    rb = sub_folder(r[2].decode("utf-8", "replace"), "r")
    if body == "json":
        jv, rv = as_json(jb), as_json(rb)
        if jv is not None or rv is not None:
            a, b = normalise_pair(jv, rv)
            if a != b:
                problems.append(f"body java={json.dumps(a)[:400]} rust={json.dumps(b)[:400]}")
        elif jb != rb:
            problems.append(f"body java={jb[:200]!r} rust={rb[:200]!r}")
    elif body == "exact" and j[2] != r[2]:
        problems.append(f"bytes differ ({len(j[2])} vs {len(r[2])})")
    elif callable(body):
        msg = body(j, r)
        if msg:
            problems.append(msg)
    if not problems and coded and not expected:
        expected = error_parity.detail(coded)
        problems = [coded]
    record(name, problems, expected)


def record(name, problems, expected=None):
    if not problems:
        results.append(("SAME", name, []))
    elif expected:
        results.append(("EXPECTED", f"{name}: {expected}", problems))
    else:
        results.append(("DIFFERENT", name, problems))


def check(name, ok, detail=""):
    """A Rust-only (or cross-service) assertion."""
    results.append(("SAME" if ok else "DIFFERENT", name, [] if ok else [detail]))


def both(method, path_tpl, kind="static", headers=None, body=None, body_fn=None, auth=True):
    """The same request to each side, `{F}` in the path being the side's folder."""
    out = {}
    for side in ("j", "r"):
        p = path_tpl.replace("{F}", FOLDER[side])
        b = body_fn(side) if body_fn else body
        h = headers
        if isinstance(b, tuple):
            h, b = b
        out[side] = call(BASE[side], method, p, h, b, auth)
    return out["j"], out["r"]


def file_read(side, kind, path):
    base = JAVA if side == "j" else SERVE
    return call(base, "GET", f"/api/files/{kind}/file/SYSTEM/_rustparity/{FOLDER[side]}/{path}", auth=(kind == "secured"))


# ------------------------------------------------------------------------------------------------
# Cases


def listings():
    for name, path in [
        ("list folder", "/api/files/static/loopzump?size=3"),
        ("list filtered", "/api/files/static/loopzump/global/favicon?fileType=IMAGES&filter=32"),
        ("list sorted page 1", "/api/files/static/loopzump?size=1&page=1&sort=name,desc"),
        ("list missing folder", "/api/files/static/nonexistentfolder"),
        ("list secured root", "/api/files/secured?size=2&sort=name,desc"),
        ("list cached first page", "/api/files/static/loopzump?size=200"),
        ("list sub client folder", "/api/files/static/_withInSubClient?clientCode=SYSTEM"),
        ("exports", "/api/files/static/exports?size=3"),
        ("imports", "/api/files/static/imports?size=3"),
        ("access paths page", "/api/files/accesspath?size=3&sort=id,desc"),
        ("access paths by type", "/api/files/accesspath?resourceType=SECURED&size=2"),
        ("access path 1", "/api/files/accesspath/1"),
        ("access path missing", "/api/files/accesspath/999999999"),
        ("retention list", "/api/files/retention?appCode=leadzumptwo"),
        ("retention effective", "/api/files/retention/effective?appCode=leadzumptwo&resourceType=secured"),
        ("retention preview", "/api/files/retention/preview?appCode=leadzumptwo&resourceType=SECURED&path=whatsapp/incoming"),
        ("retention preview days", "/api/files/retention/preview?appCode=leadzumptwo&resourceType=SECURED&path=whatsapp&days=3"),
        ("retention bad type", "/api/files/retention/effective?appCode=leadzumptwo&resourceType=nope"),
    ]:
        compare(name, call(JAVA, "GET", path), call(RUST, "GET", path), ids_vary=False)

    compare("list anonymous", call(JAVA, "GET", "/api/files/static/loopzump", auth=False),
            call(RUST, "GET", "/api/files/static/loopzump", auth=False))
    compare("list unknown client", call(JAVA, "GET", "/api/files/static/x?clientCode=NOPE12"),
            call(RUST, "GET", "/api/files/static/x?clientCode=NOPE12"),
            expected="Java 500 (null client), Rust 403 forbidden_path")
    compare("list bad fileType", call(JAVA, "GET", "/api/files/static/x?fileType=NOPE"),
            call(RUST, "GET", "/api/files/static/x?fileType=NOPE"), expected="Java 500, Rust 400")
    compare("access path query", call(JAVA, "POST", "/api/files/accesspath/query", {"Content-Type": "application/json"},
                                      json.dumps({"condition": {"field": "resourceType", "value": "STATIC"}, "size": 3}).encode()),
            call(RUST, "POST", "/api/files/accesspath/query", {"Content-Type": "application/json"},
                 json.dumps({"condition": {"field": "resourceType", "value": "STATIC"}, "size": 3}).encode()), ids_vary=False)
    q = json.dumps({"condition": {"operator": "OR", "conditions": [
        {"field": "accessName", "operator": "LIKE", "value": "%Logged%"},
        {"field": "id", "operator": "IN", "value": "1,768"}]}, "sort": [{"property": "id", "direction": "ASC"}], "size": 4}).encode()
    compare("access path complex query", call(JAVA, "POST", "/api/files/accesspath/query", {"Content-Type": "application/json"}, q),
            call(RUST, "POST", "/api/files/accesspath/query", {"Content-Type": "application/json"}, q), ids_vary=False)
    compare("applyRetention limit 0", call(JAVA, "POST", "/api/files/internal/static/applyRetention?limit=0", auth=False),
            call(RUST, "POST", "/api/files/internal/static/applyRetention?limit=0", auth=False))


def access_path_crud():
    def body(side, **extra):
        b = {"accessName": f"Authorities._rustparity_{FOLDER[side]}", "path": f" _rustparity/{FOLDER[side]} ",
             "resourceType": "STATIC", "writeAccess": False, "allowSubPathAccess": True, "clientCode": "KAILA"}
        b.update(extra)
        return {"Content-Type": "application/json"}, json.dumps(b).encode()

    j, r = both("POST", "/api/files/accesspath", body_fn=lambda s: body(s))
    compare("access path create", j, r)
    ids = {"j": as_json(j[2]).get("id"), "r": as_json(r[2]).get("id")}
    j2, r2 = both("POST", "/api/files/accesspath", body_fn=lambda s: body(s, writeAccess=True))
    compare("access path create again (merge write)", j2, r2)
    check("access path merge keeps the row", as_json(r2[2]).get("id") == ids["r"] and as_json(j2[2]).get("id") == ids["j"])
    out = {s: call(BASE[s], "GET", f"/api/files/accesspath/{ids[s]}") for s in "jr"}
    compare("access path read", out["j"], out["r"])
    out = {s: call(BASE[s], "PUT", f"/api/files/accesspath/{ids[s]}", {"Content-Type": "application/json"},
                   json.dumps({"accessName": f"Authorities._rustparity_{FOLDER[s]}", "path": f"_rustparity/{FOLDER[s]}/x",
                               "resourceType": "SECURED", "writeAccess": True}).encode()) for s in "jr"}
    compare("access path put", out["j"], out["r"])
    out = {s: call(BASE[s], "PATCH", f"/api/files/accesspath/{ids[s]}", {"Content-Type": "application/json"},
                   json.dumps({"userId": 5}).encode()) for s in "jr"}
    compare("access path patch both set", out["j"], out["r"])
    out = {s: call(BASE[s], "PATCH", f"/api/files/accesspath/{ids[s]}", {"Content-Type": "application/json"},
                   json.dumps({"path": f"_rustparity/{FOLDER[s]}/patched", "allowSubPathAccess": True}).encode()) for s in "jr"}
    compare("access path patch", out["j"], out["r"])
    out = {s: call(BASE[s], "POST", "/api/files/accesspath/query", {"Content-Type": "application/json"},
                   json.dumps({"condition": {"field": "accessName", "value": f"Authorities._rustparity_{FOLDER[s]}"}}).encode())
           for s in "jr"}
    compare("access path query own", out["j"], out["r"])
    j, r = both("POST", "/api/files/accesspath", headers={"Content-Type": "application/json"},
                body=json.dumps({"path": "x", "resourceType": "STATIC"}).encode())
    compare("access path neither user nor name", j, r)
    j, r = both("POST", "/api/files/accesspath", headers={"Content-Type": "application/json"},
                body=json.dumps({"accessName": "A"}).encode())
    compare("access path no type", j, r)
    j, r = both("POST", "/api/files/internal/accesspath", auth=False, body_fn=lambda s: (
        {"Content-Type": "application/json"},
        json.dumps({"accessName": f"Authorities._rustparity_int_{FOLDER[s]}", "path": " ", "resourceType": "SECURED",
                    "clientCode": "SYSTEM", "writeAccess": True}).encode()))
    compare("internal access path create", j, r)
    for side, resp in (("j", j), ("r", r)):
        iid = (as_json(resp[2]) or {}).get("id")
        if iid:
            call(BASE[side], "DELETE", f"/api/files/accesspath/{iid}")
    out = {s: call(BASE[s], "DELETE", f"/api/files/accesspath/{ids[s]}") for s in "jr"}
    compare("access path delete", out["j"], out["r"])
    out = {s: call(BASE[s], "GET", f"/api/files/accesspath/{ids[s]}") for s in "jr"}
    out = {s: (o[0], o[1], o[2].replace(str(ids[s]).encode(), b"<id>")) for s, o in out.items()}
    compare("access path read deleted", out["j"], out["r"])


def create_keys():
    for name, q in [("createKey default", ""), ("createKey hours", "?timeSpan=2&timeUnit=HOURS"),
                    ("createKey no unit", "?timeSpan=2"), ("createKey no span", "?accessLimit=3")]:
        path = f"/api/files/secured/createKey/file/SYSTEM/_rustparity/k%20ey+x.pdf{q}"
        j, r = call(JAVA, "GET", path), call(RUST, "GET", path)
        def keys(j, r):
            pat = r"^api/files/secured/downloadFileByKey/[0-9a-z]{12,13}$"
            if j[0] == 200 and not (re.match(pat, j[2].decode()) and re.match(pat, r[2].decode())):
                return f"keys java={j[2]!r} rust={r[2]!r}"
            if j[0] != 200:
                a, b = normalise_pair(as_json(j[2]), as_json(r[2]))
                return None if a == b else f"body java={a} rust={b}"
            return None
        compare(name, j, r, body=keys)
    path = "/api/files/secured/createKey/file/SYSTEM/_rustparity/a.pdf?timeSpan=2&timeUnit=Hours"
    compare("createKey bad unit", call(JAVA, "GET", path), call(RUST, "GET", path), expected="Java 500, Rust 400")
    path = "/api/files/internal/secured/createKey?filePath=SYSTEM/_rustparity/a%20b.pdf"
    j, r = call(JAVA, "GET", path, auth=False), call(RUST, "GET", path, auth=False)
    compare("internal createKey", j, r, body=lambda j, r: None if j[2][:36] == r[2][:36] and len(r[2]) in (48, 49) else f"{j[2]!r} {r[2]!r}")


def uploads_and_folders():
    for kind in ("static", "secured"):
        j, r = both("POST", f"/api/files/{kind}/directory/_rustparity/{{F}}/sub")
        compare(f"{kind} directory create", j, r)
        j, r = both("POST", f"/api/files/{kind}/directory/_rustparity/{{F}}/sub")
        compare(f"{kind} directory exists", j, r)
        j, r = both("POST", f"/api/files/{kind}/directory/_rustparity/{{F}}/undefined")
        compare(f"{kind} directory bad name", j, r)
        hello = multipart(files=[("file", "hello.txt", "text/plain", b"hello world\n")])
        j, r = both("POST", f"/api/files/{kind}/_rustparity/{{F}}", body=hello)
        compare(f"{kind} upload", j, r)
        j, r = both("POST", f"/api/files/{kind}/_rustparity/{{F}}",
                    body=multipart([("override", "false")], [("file", "hello.txt", "text/plain", b"other bytes\n")]))
        compare(f"{kind} upload no override", j, r)
        j, r = both("POST", f"/api/files/{kind}/_rustparity/{{F}}/",
                    body=multipart([("name", "renamed")], [("file", "hello.txt", "text/plain", b"hello world\n")]))
        compare(f"{kind} upload renamed", j, r)
        j, r = both("POST", f"/api/files/{kind}/_rustparity/{{F}}/a%20b",
                    body=multipart([("name", "x y.txt")], [("file", "hello.txt", "text/plain", b"spaced\n")]))
        compare(f"{kind} upload encoded path", j, r)
        j, r = both("POST", f"/api/files/{kind}/_rustparity/{{F}}", body=multipart([("name", "x")]))
        compare(f"{kind} upload without file", j, r, expected="Java 500 (no file part), Rust 400 missing_field")
        j, r = both("GET", f"/api/files/{kind}/_rustparity/{{F}}")
        compare(f"{kind} list scratch", j, r)
        j, r = both("GET", f"/api/files/{kind}/_rustparity/{{F}}/sub?fileType=FILES")
        compare(f"{kind} list scratch files only", j, r)
        j, r = both("DELETE", f"/api/files/{kind}/_rustparity/{{F}}/renamed.txt")
        compare(f"{kind} delete file", j, r)
        j, r = both("DELETE", f"/api/files/{kind}/_rustparity/{{F}}/renamed.txt")
        compare(f"{kind} delete missing", j, r)
        j, r = both("DELETE", f"/api/files/{kind}/_rustparity/x?clientCode=NOPE12")
        compare(f"{kind} delete unknown client", j, r, expected="Java 500 (null client), Rust 403 forbidden_path")
        j, r = both("POST", f"/api/files/{kind}/_rustparity/{{F}}", body=hello, auth=False)
        compare(f"{kind} upload anonymous", j, r)

    # Overwrite: static by default, secured only when asked.
    j, r = both("POST", "/api/files/static/_rustparity/{F}",
                body=multipart(files=[("file", "hello.txt", "text/plain", b"second version\n")]))
    compare("static upload overwrites", j, r)
    for side in "jr":
        st = file_read(side, "static", "hello.txt")
        check(f"static overwrite read back ({'java' if side == 'j' else 'rust'})", st[2] == b"second version\n", repr(st[2][:40]))


def eviction_across_services():
    """A write on one service, a read through the other, a second write, a read again."""
    time.sleep(1.1)
    path = "evict.txt"
    # Java writes, Rust reads (files-serve and files-manage).
    up = lambda base, data: call(base, "POST", f"/api/files/static/_rustparity/{FOLDER['j']}",
                                 *multipart(files=[("file", path, "text/plain", data)]))
    up(JAVA, b"java v1\n")
    v1 = [call(b, "GET", f"/api/files/static/file/SYSTEM/_rustparity/{FOLDER['j']}/{path}", auth=False)[2] for b in (SERVE, RUST)]
    time.sleep(1.1)
    up(JAVA, b"java v2\n")
    time.sleep(0.5)
    v2 = [call(b, "GET", f"/api/files/static/file/SYSTEM/_rustparity/{FOLDER['j']}/{path}", auth=False)[2] for b in (SERVE, RUST)]
    check("java write -> files-serve read sees v1 then v2", v1[0] == b"java v1\n" and v2[0] == b"java v2\n", f"{v1[0]!r} {v2[0]!r}")
    check("java write -> files-manage read sees v1 then v2", v1[1] == b"java v1\n" and v2[1] == b"java v2\n", f"{v1[1]!r} {v2[1]!r}")

    # Rust writes, files-serve and Java read.
    upr = lambda data: call(RUST, "POST", f"/api/files/static/_rustparity/{FOLDER['r']}",
                            *multipart(files=[("file", path, "text/plain", data)]))
    upr(b"rust v1\n")
    url = f"/api/files/static/file/SYSTEM/_rustparity/{FOLDER['r']}/{path}"
    s1, j1 = call(SERVE, "GET", url, auth=False), call(JAVA, "GET", url, auth=False)
    time.sleep(1.1)
    upr(b"rust v2\n")
    time.sleep(0.5)
    s2, j2 = call(SERVE, "GET", url, auth=False), call(JAVA, "GET", url, auth=False)
    j2n = call(JAVA, "GET", url + "?noCache=true", auth=False)
    check("files-manage write -> files-serve read sees v1 then v2", s1[2] == b"rust v1\n" and s2[2] == b"rust v2\n", f"{s1[2]!r} {s2[2]!r}")
    check("files-manage write -> Java metadata (ETag) changes", j1[1].get("etag") != j2[1].get("etag") and j2[1].get("etag") == s2[1].get("etag"),
          f"{j1[1].get('etag')} {j2[1].get('etag')} serve={s2[1].get('etag')}")
    check("files-manage write -> Java noCache read is v2", j2n[2] == b"rust v2\n", repr(j2n[2]))
    record("files-manage write -> Java plain read bytes",
           [] if j2[2] == b"rust v2\n" else [f"java served {j2[2]!r}"],
           expected="Java keeps its own unversioned disk copy and only drops it on its own writes (DIFFERENCES.md)")


def base64_and_transforms():
    for kind in ("static", "secured"):
        for meta in ("true", "false"):
            j, r = both("GET", f"/api/files/internal/{kind}/convertToBase64?clientCode=SYSTEM&metadataRequired={meta}"
                               f"&url=api/files/{kind}/file/SYSTEM/_rustparity/{{F}}/hello.txt", auth=False)
            compare(f"{kind} internal base64 metadata={meta}", j, r)
    j, r = both("GET", "/api/files/internal/static/convertToBase64?clientCode=SYSTEM"
                       "&url=api/files/static/file/SYSTEM/_rustparity/{F}/hello.txt", auth=False)
    compare("internal base64 without metadataRequired", j, r, expected="Java 500 (unboxing null), Rust treats it as false")
    j, r = both("GET", "/api/files/internal/static/convertToBase64?clientCode=SYSTEM&metadataRequired=true"
                       "&url=api/files/static/file/SYSTEM/_rustparity/{F}", auth=False)
    compare("internal base64 of a folder", j, r)

    data = b"\x00\x01binary\xff" * 10
    form = multipart(files=[("file", "cert.p12", "application/x-pkcs12", data)])
    compare("generic convertToBase64", call(JAVA, "POST", "/api/files/generic/convertToBase64", *form),
            call(RUST, "POST", "/api/files/generic/convertToBase64", *form))
    compare("generic convertToBase64WithDetails", call(JAVA, "POST", "/api/files/generic/convertToBase64WithDetails", *form),
            call(RUST, "POST", "/api/files/generic/convertToBase64WithDetails", *form))
    empty = multipart(files=[("file", "e.bin", "application/octet-stream", b"")])
    compare("generic convertToBase64 empty", call(JAVA, "POST", "/api/files/generic/convertToBase64", *empty),
            call(RUST, "POST", "/api/files/generic/convertToBase64", *empty))

    img = png(40, 20)
    form = multipart([("width", "20"), ("rotation", "90")], [("file", "pic.png", "image/png", img)])
    j, r = call(JAVA, "POST", "/api/files/generic/resize", *form), call(RUST, "POST", "/api/files/generic/resize", *form)
    compare("generic resize png", j, r, body=lambda j, r: None if png_size(j[2]) == png_size(r[2]) else f"java {png_size(j[2])} rust {png_size(r[2])}")
    check("generic resize headers", j[1].get("content-disposition") == r[1].get("content-disposition"),
          f"{j[1].get('content-disposition')} {r[1].get('content-disposition')}")
    form = multipart([("width", "20")], [("file", "pic.gif", "image/gif", img)])
    compare("generic resize gif", call(JAVA, "POST", "/api/files/generic/resize", *form),
            call(RUST, "POST", "/api/files/generic/resize", *form), expected="Java 500 (no enum constant GIF), Rust 400")
    form = multipart([("width", "10")])
    compare("generic user image without file", call(JAVA, "POST", "/api/files/generic/user", *form),
            call(RUST, "POST", "/api/files/generic/user", *form), expected="Java 500 (missing part), Rust 400")

    for kind in ("static", "secured"):
        j, r = both("POST", f"/api/files/transform/{kind}/_rustparity/{{F}}",
                    body=multipart([("width", "20"), ("cropAreaX", "0"), ("cropAreaY", "0"), ("cropAreaWidth", "10"),
                                    ("cropAreaHeight", "5"), ("fileName", "t.png")], [("file", "pic.png", "image/png", png(40, 20))]))
        # The stored PNG's size is left out: a different encoder (pixels are not bit-identical).
        compare(f"{kind} transform upload", j, r, drop=("size",))
        a = file_read("j", kind, "t.png") if kind == "static" else call(JAVA, "GET", f"/api/files/secured/file/SYSTEM/_rustparity/{FOLDER['j']}/t.png")
        b = file_read("r", kind, "t.png") if kind == "static" else call(SERVE, "GET", f"/api/files/secured/file/SYSTEM/_rustparity/{FOLDER['r']}/t.png")
        check(f"{kind} transform stored size", png_size(a[2]) == png_size(b[2]) == (10, 5), f"java {png_size(a[2])} rust {png_size(b[2])}")
        j, r = both("POST", f"/api/files/transform/{kind}/_rustparity/{{F}}",
                    body_fn=lambda s: multipart([("path", f"api/files/{kind}/file/SYSTEM/_rustparity/{FOLDER[s]}/t.png"),
                                                 ("fileName", "t2.png"), ("rotation", "90"), ("override", "true")]))
        # The stored PNG's size is left out: a different encoder (pixels are not bit-identical).
        compare(f"{kind} transform stored file", j, r, drop=("size",))


def internal_uploads():
    j, r = both("POST", "/api/files/internal/static?clientCode=SYSTEM&fileName=raw.txt&filePath=_rustparity/{F}",
                headers={"Content-Type": "application/octet-stream"}, body=b"raw body\n", auth=False)
    compare("internal raw upload", j, r)
    j, r = both("POST", "/api/files/internal/secured?clientCode=SYSTEM&fileName=raw.txt&filePath=_rustparity/{F}&override=true",
                headers={"Content-Type": "application/octet-stream"}, body=b"raw body\n", auth=False)
    compare("internal raw upload secured", j, r)
    j, r = both("POST", "/api/files/internal/static?fileName=raw.txt", body=b"x", auth=False)
    compare("internal raw upload without client", j, r, expected="Java 500 (missing parameter), Rust 400")

    # Lifetimes: each side removes its own expired file. The cleanup takes every expired file of
    # the type, so the counts are not compared; that the file is gone is.
    for side in "rj":
        call(BASE[side], "POST", f"/api/files/internal/static?clientCode=SYSTEM&fileName=expiring.txt"
                                 f"&filePath=_rustparity/{FOLDER[side]}&expiresAfterMinutes=0", {"Content-Type": "text/plain"}, b"e", auth=False)
        time.sleep(2.2)
        n = call(BASE[side], "POST", "/api/files/internal/static/cleanupExpired?limit=50", auth=False)
        gone = call(BASE[side], "GET", f"/api/files/static/_rustparity/{FOLDER[side]}?filter=expiring")
        listed = as_json(gone[2]) or {}
        check(f"cleanupExpired removes the expired file ({'java' if side == 'j' else 'rust'})",
              n[0] == 200 and int(n[2]) >= 1 and not listed.get("content"), f"{n} {gone[2][:200]!r}")

    j, r = both("POST", "/api/files/internal/aiUploader",
                body_fn=lambda s: multipart([("clientCode", f"RP{FOLDER[s].upper()}")],
                                            [("file", "gen.png", "image/png", png(4, 4))]), auth=False)
    compare("internal aiUploader", j, r, body=lambda j, r: None if sub_folder(j[2].decode(), "j").replace(FOLDER['j'].upper(), "<F>")
            == r[2].decode().replace(FOLDER['r'].upper(), "<F>") else f"{j[2]!r} {r[2]!r}")
    j, r = both("POST", "/api/files/static/copyToClientPage?pageName=_rustparity_{F}",
                body_fn=lambda s: ({"Content-Type": "application/json"},
                                   json.dumps([f"/api/files/static/file/SYSTEM/aiGen/RP{FOLDER[s].upper()}/gen.png"]).encode()))
    compare("copyToClientPage", sub_pair(j, r)[0], sub_pair(j, r)[1])


def sub_pair(j, r):
    """Maps the aiGen client codes onto each other too."""
    jj = (j[0], j[1], j[2].replace(FOLDER["j"].upper().encode(), b"<F>"))
    rr = (r[0], r[1], r[2].replace(FOLDER["r"].upper().encode(), b"<F>"))
    return jj, rr


def zip_import_export():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("top.txt", "top\n")
        z.writestr("a/", "")
        z.writestr("a/b/deep.txt", "deep\n")
        z.writestr("a/mid.png", png(3, 3))
    zbytes = buf.getvalue()
    ids = {}
    for side in "jr":
        st, _, body = call(BASE[side], "POST", f"/api/files/static/import/_rustparity/{FOLDER[side]}/zipped",
                           *multipart(files=[("file", "bundle.zip", "application/zip", zbytes)]))
        ids[side] = (st, body)
    check("zip import accepted", ids["j"][0] == ids["r"][0] == 200, f"{ids}")
    bad = multipart(files=[("file", "bundle.tar", "application/x-tar", zbytes)])
    compare("zip import not a zip", call(JAVA, "POST", f"/api/files/static/import/_rustparity/{FOLDER['j']}/z", *bad),
            call(RUST, "POST", f"/api/files/static/import/_rustparity/{FOLDER['r']}/z", *bad))

    def job(side, kind, jid):
        page = as_json(call(BASE[side], "GET", f"/api/files/static/{kind}?size=200&sort=id,desc")[2]) or {}
        for row in page.get("content", []):
            if str(row.get("id")) == jid.decode():
                return row
        return None

    for _ in range(60):
        rows = {s: job(s, "imports", ids[s][1]) for s in "jr"}
        if all(r and r.get("status") != "PENDING" for r in rows.values()):
            break
        time.sleep(1)
    check("zip import status DONE", all(r and r.get("status") == "DONE" for r in rows.values()), f"{rows}")
    time.sleep(1.5)  # Java marks DONE before its uploads finish.
    for sub in ("zipped", "zipped/a", "zipped/a/b"):
        j, r = both("GET", f"/api/files/static/_rustparity/{{F}}/{sub}")
        compare(f"zip import tree {sub}", j, r)

    eids = {}
    for side in "jr":
        st, _, body = call(BASE[side], "GET", f"/api/files/static/export/_rustparity/{FOLDER[side]}/zipped")
        eids[side] = (st, body)
    check("zip export accepted", eids["j"][0] == eids["r"][0] == 200, f"{eids}")
    for _ in range(90):
        rows = {s: job(s, "exports", eids[s][1]) for s in "jr"}
        if all(r and r.get("status") != "PENDING" for r in rows.values()):
            break
        time.sleep(1)
    check("zip export status DONE", all(r and r.get("status") == "DONE" for r in rows.values()), f"{rows}")
    names = {}
    for side in "jr":
        row = rows[side] or {}
        url = f"/api/files/static/file/SYSTEM/{row.get('cdnUrl', '')}"
        st, h, body = call(JAVA if side == "j" else SERVE, "GET", url, auth=False)
        try:
            z = zipfile.ZipFile(io.BytesIO(body))
            names[side] = sorted((n, z.read(n)) for n in z.namelist())
        except Exception as e:
            names[side] = f"unreadable ({st}, {len(body)} bytes): {e}"
        names[side + "cd"] = h.get("content-disposition")
        EXPORTS.append(row.get("cdnUrl", ""))
    check("zip export contents", names["j"] == names["r"], f"java {names['j']} rust {names['r']}")
    for cd in ("j", "r"):
        pass


EXPORTS = []


def retention_crud():
    body = json.dumps({"appCode": "leadzumptwo", "resourceType": "SECURED", "path": "whatsapp/incoming",
                       "level": "CLIENT", "appliesTo": "SELF", "retentionDays": 7}).encode()
    hj = {"Content-Type": "application/json"}
    j = call(JAVA, "POST", "/api/files/retention", hj, body)
    r_dup = call(RUST, "POST", "/api/files/retention", hj, body)
    j_dup = call(JAVA, "POST", "/api/files/retention", hj, body)
    compare("retention create duplicate", j_dup, r_dup)
    jid = (as_json(j[2]) or {}).get("id")
    upd = json.dumps({"retentionDays": 10}).encode()
    compare("retention update", call(JAVA, "PUT", f"/api/files/retention/{jid}", hj, upd),
            call(RUST, "PUT", f"/api/files/retention/{jid}", hj, upd), ids_vary=False)
    compare("retention effective with client row", call(JAVA, "GET", "/api/files/retention/effective?appCode=leadzumptwo"),
            call(RUST, "GET", "/api/files/retention/effective?appCode=leadzumptwo"), ids_vary=False)
    d = call(RUST, "DELETE", f"/api/files/retention/{jid}")
    check("retention delete (rust deletes the java row)", d[0] == 200 and d[2].strip() == b"true", repr(d))
    compare("retention delete missing", call(JAVA, "DELETE", f"/api/files/retention/{jid}"),
            call(RUST, "DELETE", f"/api/files/retention/{jid}"))
    r = call(RUST, "POST", "/api/files/retention", hj, body)
    rid = (as_json(r[2]) or {}).get("id")
    compare("retention create", j, r)
    call(JAVA, "DELETE", f"/api/files/retention/{rid}")
    bad = json.dumps({"appCode": "leadzumptwo", "resourceType": "SECURED", "path": "not/registered", "level": "CLIENT"}).encode()
    compare("retention create unregistered prefix", call(JAVA, "POST", "/api/files/retention", hj, bad),
            call(RUST, "POST", "/api/files/retention", hj, bad))
    bad = json.dumps({"appCode": "leadzumptwo", "resourceType": "SECURED", "path": "../x", "level": "CLIENT"}).encode()
    compare("retention create bad path", call(JAVA, "POST", "/api/files/retention", hj, bad),
            call(RUST, "POST", "/api/files/retention", hj, bad))


def populate():
    """Rebuilds each side's own scratch folder rows from the bucket, then compares the tree."""
    for side in "jr":
        call(BASE[side], "GET", f"/api/files/generic/internal/fs/populate?clientCode=SYSTEM&resourceType=static"
                                f"&folderPath=_rustparity/{FOLDER[side]}/zipped", auth=False)
    time.sleep(4)
    for sub in ("zipped", "zipped/a"):
        j, r = both("GET", f"/api/files/static/_rustparity/{{F}}/{sub}")
        compare(f"populate tree {sub}", j, r)


# ------------------------------------------------------------------------------------------------
# Cleanup


def delete_tree(side, kind, path):
    """Deletes every file under `path` one by one (a folder delete leaves its objects in the
    bucket), then the folders."""
    page = as_json(call(BASE[side], "GET", f"/api/files/{kind}/{urllib.parse.quote(path)}?size=2000")[2]) or {}
    for e in page.get("content", []):
        child = f"{path}/{e['name']}"
        if e.get("directory"):
            delete_tree(side, kind, child)
        call(BASE[side], "DELETE", f"/api/files/{kind}/{urllib.parse.quote(child)}")


def cleanup():
    # The whole scratch root, this run's and anything an interrupted run left.
    for kind in ("static", "secured"):
        delete_tree("r", kind, "_rustparity")
        call(RUST, "DELETE", f"/api/files/{kind}/_rustparity")
    for side in "jr":
        delete_tree(side, "static", f"sitezump/_rustparity_{FOLDER[side]}")
        call(BASE[side], "DELETE", f"/api/files/static/sitezump/_rustparity_{FOLDER[side]}")
        delete_tree(side, "static", f"aiGen/RP{FOLDER[side].upper()}")
        call(BASE[side], "DELETE", f"/api/files/static/aiGen/RP{FOLDER[side].upper()}")
    for cdn in EXPORTS:
        if cdn:
            call(RUST, "DELETE", f"/api/files/static/{cdn}")


import urllib.parse  # noqa: E402

try:
    listings()
    access_path_crud()
    create_keys()
    uploads_and_folders()
    eviction_across_services()
    base64_and_transforms()
    internal_uploads()
    zip_import_export()
    populate()
    retention_crud()
finally:
    try:
        cleanup()
    except Exception as e:  # noqa: BLE001
        print(f"cleanup failed: {e}")

failures = 0
for status, name, problems in results:
    print(f"{status:9} {name}")
    if status != "SAME":
        for p in problems:
            print(f"            {p}")
    if status == "DIFFERENT":
        failures += 1
print(f"\n{len(results) - failures}/{len(results)} same or expected")
sys.exit(1 if failures else 0)
