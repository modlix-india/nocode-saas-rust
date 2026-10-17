#!/usr/bin/env python3
"""Captures the KIRun built-in catalog the Java ui answers `includeKIRunRepos=true` with.

Usage: capture_kirun_catalog.py [java_base]     (default http://localhost:8002)

The built-in functions and schemas live in kirun-java, not in Mongo, and the Java ui answers
`repositoryFind` for them with Gson (functions) or Jackson (schemas) of kirun-java's own
objects. ui-engine serves the same answers from crates/ui/src/kirun_catalog.json, written
here. Run it again whenever the Java services move to a new kirun-java version.

The app used must have no functions, schemas or dependencies of its own (`nothing`), so the
lists hold the built-ins only.
"""
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

JAVA = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8002"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "crates", "ui", "src", "kirun_catalog.json")
HEADERS = {"appCode": "nothing", "clientCode": "SYSTEM"}


def get(path):
    req = urllib.request.Request(JAVA + path, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def split(full):
    ns, _, name = full.rpartition(".")
    return ns, name


def main():
    catalog = {}
    for kind in ("functions", "schemas"):
        status, body = get(f"/api/ui/{kind}/repositoryFilter?includeKIRunRepos=true&filter=")
        if status != 200:
            raise SystemExit(f"{kind} filter: {status}")
        names = json.loads(body)
        bodies = {}
        for full in names:
            ns, name = split(full)
            s, b = get(f"/api/ui/{kind}/repositoryFind?includeKIRunRepos=true"
                       f"&namespace={urllib.parse.quote(ns)}&name={urllib.parse.quote(name)}")
            # A 500 is kept as a 500: Jackson cannot write some of these schemas in Java either.
            bodies[full] = {"status": s, "body": b if s == 200 else ""}
        catalog[kind] = {"names": names, "find": bodies}
    with open(OUT, "w") as f:
        json.dump(catalog, f, indent=1, sort_keys=False)
        f.write("\n")
    print(f"wrote {OUT}: {len(catalog['functions']['names'])} functions, {len(catalog['schemas']['names'])} schemas")


if __name__ == "__main__":
    main()
