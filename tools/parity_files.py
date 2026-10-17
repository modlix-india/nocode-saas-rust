#!/usr/bin/env python3
"""Sends the same requests to the Java files service and to files-serve and compares them.

Usage: parity_files.py [java_base] [rust_base]
       defaults: http://localhost:8003  http://localhost:8103

Compares status, the headers that matter, and a SHA-256 of the body. Headers whose value is a
clock reading (Date, Expires) are compared for presence only. Bodies of resized images are
expected to differ (different resampler); for those only status, ETag and type are compared.
"""
import hashlib
import sys
import urllib.error
import urllib.request

import error_parity  # coded Rust errors are compared by code (crates/files/DIFFERENCES.md, Error bodies)

JAVA = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8003"
RUST = sys.argv[2] if len(sys.argv) > 2 else "http://localhost:8103"

SMALL = "/api/files/static/file/SYSTEM/loopzump/global/favicon/loopzump-32-v1.png"
LARGE = "/api/files/static/file/SYSTEM/crumbco/home/bakes/baker-hands-story.png"

COMPARED = [
    "content-type", "content-length", "content-range", "content-disposition", "etag",
    "last-modified", "cache-control", "accept-ranges", "x-cache", "pragma",
    "x-content-type-options", "x-frame-options", "content-security-policy",
    "access-control-allow-origin",
]
PRESENCE_ONLY = ["expires"]


def fetch(base, path, headers=None, method="GET"):
    req = urllib.request.Request(base + path, headers=headers or {}, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read()


def etag_of(path):
    _, h, _ = fetch(JAVA, path)
    return h.get("etag", ""), h.get("last-modified", "")


etag, last_modified = etag_of(SMALL)

CASES = [
    # (name, path, headers, method, body_must_match, expected_difference)
    ("plain", SMALL, {}, "GET", True, None),
    ("large 1MB", LARGE, {}, "GET", True, None),
    ("HEAD", SMALL, {}, "HEAD", True, None),
    ("If-None-Match", SMALL, {"If-None-Match": etag}, "GET", True, None),
    ("If-Modified-Since", SMALL, {"If-Modified-Since": last_modified}, "GET", True, None),
    ("stale If-None-Match", SMALL, {"If-None-Match": '"nope"'}, "GET", True, None),
    ("range 0-99", SMALL, {"Range": "bytes=0-99"}, "GET", True, None),
    ("range suffix", SMALL, {"Range": "bytes=-100"}, "GET", True, None),
    ("range open", SMALL, {"Range": "bytes=1000-"}, "GET", True, None),
    ("noCache", SMALL + "?noCache=true", {}, "GET", True, None),
    ("download name", SMALL + "?download=true&name=x%20y.png", {}, "GET", True, None),
    ("quote in name", SMALL + "?name=a%22b.png", {}, "GET", True, None),
    ("resize width", SMALL + "?width=16", {}, "GET", False, None),
    ("resize cover", LARGE + "?width=120&height=120&fit=cover", {}, "GET", False, None),
    ("resize to jpeg", LARGE + "?width=200&format=jpeg", {}, "GET", False, None),
    ("CORS origin", SMALL, {"Origin": "https://example.com"}, "GET", True, None),
    ("missing file", "/api/files/static/file/SYSTEM/nope/none.png", {}, "GET", True, None),
    ("internal file", "/api/files/internal/static/file?filePath=SYSTEM/loopzump/global/favicon/loopzump-32-v1.png", {}, "GET", True, None),
    ("secured anonymous", "/api/files/secured/file/FIN/x.pdf", {}, "GET", True, None),
    ("bad key", "/api/files/secured/downloadFileByKey/nokey123", {}, "GET", True,
     "Java 500 (null row), Rust 404 invalid_key"),
    ("bad fit", SMALL + "?fit=bogus", {}, "GET", True, "Java 500, Rust 400"),
    ("inverted range", SMALL, {"Range": "bytes=5-2"}, "GET", True,
     "Java 403 (its 416 is eaten by its own filter), Rust 416"),
    ("multi range", SMALL, {"Range": "bytes=0-1,4-5"}, "GET", False,
     "Java multipart is malformed and its second part empty"),
]

failures = 0
for name, path, headers, method, body_must_match, expected in CASES:
    js, jh, jb = fetch(JAVA, path, headers, method)
    rs, rh, rb = fetch(RUST, path, headers, method)
    (rs, rh, rb), coded = error_parity.decode((js, jh, jb), (rs, rh, rb))
    if coded and not error_parity.is_problem(coded) and "content-length" in jh:
        rh["content-length"] = str(len(rb))
    problems = []
    if error_parity.is_problem(coded):
        problems.append(coded)
    if js != rs:
        problems.append(f"status java={js} rust={rs}")
    for k in COMPARED:
        if jh.get(k) != rh.get(k):
            if k == "content-length" and not body_must_match:
                continue
            if k == "content-range" and not body_must_match:
                continue
            problems.append(f"{k}: java={jh.get(k)!r} rust={rh.get(k)!r}")
    for k in PRESENCE_ONLY:
        if (k in jh) != (k in rh):
            problems.append(f"{k} present: java={k in jh} rust={k in rh}")
    if body_must_match and js < 500 and hashlib.sha256(jb).hexdigest() != hashlib.sha256(rb).hexdigest():
        problems.append(f"body differs ({len(jb)} vs {len(rb)} bytes)")
    if not body_must_match and js == 200 and rs == 200 and not rb:
        problems.append("rust body empty")

    if not problems and coded:
        print(f"EXPECTED  {name}: {error_parity.detail(coded)}")
    elif not problems:
        print(f"SAME      {name}")
    elif expected:
        print(f"EXPECTED  {name}: {expected}")
        for p in problems:
            print(f"            {p}")
    else:
        failures += 1
        print(f"DIFFERENT {name}")
        for p in problems:
            print(f"            {p}")

print(f"\n{len(CASES) - failures}/{len(CASES)} same or expected")
sys.exit(1 if failures else 0)
