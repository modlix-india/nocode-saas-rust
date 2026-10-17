#!/usr/bin/env python3
"""Storage parity: the data routes, the storage KIRun functions and the spreadsheet route of the
Java core (8005) against core-exec (8105).

Usage: parity_core_data.py [java_base] [rust_base] [-v] [--keep]

Read-only cases run on the real local storages (Mongo and MySQL apps): pages, rows by id,
filters from GET parameters, aggregates, eager relations, versions, downloads, templates,
migration status and drift, and the KIRun Read / ReadPage / Aggregate / GetVersionDetails.

Writes go ONLY into scratch storages this script creates in the `monkbars` scratch app through
the Java definitions API (`POST /api/core/storages`, `POST /api/core/functions`), on the Mongo
surface (client SYSTEM) and the MySQL one (client MONKA). Each write is made twice, once
through each service, and the two results compared with ids and times masked; reads of a row
are compared exactly through both services. Everything created is deleted through the Java
API at the end (rows with `?deleteAll=true`, then the definitions), unless --keep.

Verdicts as in parity_core_exec.py: SAME, EXPECTED <tag> (crates/core/DIFFERENCES.md), DIFF.
"""
import io
import json
import os
import re
import zipfile
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parity_core_exec as P  # noqa: E402

KEEP = "--keep" in sys.argv
ONLY = [a[len("--only="):] for a in sys.argv if a.startswith("--only=")]
PREFIX = "rpScr"
# The scratch surfaces: monkbars has no appData connection for SYSTEM (Mongo); appa runs on the
# platform MySQL (an app-level connection).
SCRATCH_APPS = [("monkbars", "SYSTEM"), ("appa", "SYSTEM")]
EX = "/api/core/function/execute/CoreServices.Storage/"


def H(app="appbuilder", client="SYSTEM", auth=P.BASIC, json_body=True, extra=None):
    return P.headers(app=app, client=client, auth=auth, extra=extra, json_body=json_body)


def q(path, **params):
    return path + ("?" + urllib.parse.urlencode(params, doseq=True) if params else "")


OID = re.compile(r"^[0-9a-f]{24}$|^[0-9A-HJKMNP-TV-Z]{26}$")
OID_IN = re.compile(r"\b[0-9a-f]{24}\b")
VOLATILE = {"createdAt", "updatedAt", "_id", "id", "objectId", "versionId", "ts", "timestamp", "date"}


def mask(v, key=None):
    """Ids and times blanked, for comparing two writes of the same thing."""
    if isinstance(v, dict):
        return {k: ("<v>" if k in VOLATILE and not isinstance(x, (dict, list)) else mask(x, k)) for k, x in v.items()}
    if isinstance(v, list):
        return [mask(x, key) for x in v]
    if isinstance(v, str) and OID.match(v):
        return "<oid>"
    if isinstance(v, str):
        return OID_IN.sub("<oid>", v)
    return v


def twice(name, method, java_path, rust_path, hdrs, java_body=None, rust_body=None, expected=None, raw=False):
    """The same write through each service (each on its own rows); results compared masked."""
    if expected is None:
        expected = D16_unknown_error_text
    for _ in range(6):
        js, jct, jb = P.fetch(P.JAVA, method, java_path, hdrs, java_body)
        rs, rct, rb = P.fetch(P.RUST, method, rust_path, hdrs, rust_body if rust_body is not None else java_body)
        jv, rv = P.parse(jb), P.parse(rb)
        if not (P.security_down(js, jv) or P.security_down(rs, rv)):
            break
        P.wait_for_security()
    else:
        P.record(name, "SKIP security-unreachable")
        return None, None
    (rs, rct, rb), coded = P.decode((js, jct, jb), (rs, rct, rb))
    rv = P.parse(rb)
    detail = f"java {js} {json.dumps(jv)[:400] if not isinstance(jv, str) else jv[:400]}\n    rust {rs} " + \
        (json.dumps(rv)[:400] if not isinstance(rv, str) else rv[:400])
    if raw and js == 200:
        same = js == rs and jb == rb
    else:
        same = js == rs and P.canon(mask(jv)) == P.canon(mask(rv))
    if same:
        P.record_coded(name, "SAME", "", coded)
    elif expected and expected(js, jv, rs, rv):
        P.record_coded(name, f"EXPECTED {expected.__name__}", detail, coded)
    else:
        P.record_coded(name, "DIFF", detail, coded)
    return (js, jv), (rs, rv)


def java(method, path, hdrs, body=None):
    for _ in range(6):
        s, _, b = P.fetch(P.JAVA, method, path, hdrs, body)
        v = P.parse(b)
        if not P.security_down(s, v):
            return s, v
        P.wait_for_security()
    return 0, None


# --- EXPECTED rules -------------------------------------------------------------------------

def D15_no_basic_challenge(js, jv, rs, rv):
    """Both 401; the running Java build still sends `WWW-Authenticate: Basic realm` (the source
    no longer does), Rust never does. Checked on headers separately."""
    return js == rs == 401


def D16_unknown_error_text(js, jv, rs, rv):
    """Both answered an unknown (500 or a framework 400) error; only the exception text, which
    is the Java class's own wording, differs."""
    return js == rs and P.is_unknown_error(jv) and P.is_unknown_error(rv)


def D2_kirun_error_text(js, jv, rs, rv):
    return P.D2_kirun_error_text(js, jv, rs, rv)


def D17_feign_debug_message(js, jv, rs, rv):
    """Another service refused (security here): same status and message; Java's debugMessage
    is Feign's exception text (method, URL, the whole body), Rust's the message."""
    return js == rs and isinstance(jv, dict) and isinstance(rv, dict) and jv.get("message") == rv.get("message") \
        and str(jv.get("debugMessage", "")).startswith("[")


# K4 (an INTEGER beyond the int range, kirun-rust following kirun-js) was resolved on 2026-10-17 in
# the kirun crate; see crates/core/DIFFERENCES.md.


# --- discovery --------------------------------------------------------------------------------

def mongo_storages():
    """SYSTEM storages with rows, on the Mongo surface."""
    script = """
    const out = [];
    db.storage.find({clientCode: 'SYSTEM'}, {name:1, appCode:1, uniqueName:1, relations:1, isVersioned:1, isAudited:1,
                                              onlyThruKIRun:1, readAuth:1, schema:1}).forEach(s => {
      if (s.name.startsWith('%s')) return;
      const conn = db.connection.findOne({appCode: s.appCode, connectionType: 'APP_DATA', isAppLevel: true});
      if (conn) return;
      const n = db.getSiblingDB('SYSTEM_' + s.appCode).getCollection(s.uniqueName || 'x').estimatedDocumentCount();
      if (n > 0) out.push({app: s.appCode, name: s.name, rows: n, relations: Object.keys(s.relations || {}),
                           versioned: !!(s.isVersioned || s.isAudited), kirun: !!s.onlyThruKIRun});
    });
    print(EJSON.stringify(out));
    """ % PREFIX
    return P.mongo_json(script)


def mysql_storages():
    """Tables with rows in the MySQL tenant schemas, by storage name."""
    env = dict(os.environ)
    env.setdefault("MYSQL_PWD", os.environ.get("MODLIX__DATABASE__PASSWORD", ""))
    sql = ("SELECT table_schema, table_name FROM information_schema.tables WHERE table_rows > 0 AND "
           "table_schema REGEXP '^[A-Z0-9]+_[a-z0-9]+$' AND table_name NOT LIKE '%\\_version' AND "
           "table_name <> 'storage_migration' ORDER BY table_schema, table_name")
    try:
        out = subprocess.run(["mysql", "-h127.0.0.1", "-uroot", "-N", "-e", sql], capture_output=True, text=True,
                             env=env, check=True).stdout
    except Exception:  # noqa: BLE001 - no MySQL client: no MySQL cases
        return []
    pairs = [l.split("\t") for l in out.strip().splitlines() if "\t" in l]
    names = P.mongo_json("print(EJSON.stringify(db.storage.find({uniqueName: {$in: %s}}, {name:1, appCode:1, uniqueName:1, "
                         "clientCode:1, relations:1}).toArray()))" % json.dumps([t for _, t in pairs]))
    by_unique = {d["uniqueName"]: d for d in names}
    out = []
    for schema, table in pairs:
        d = by_unique.get(table)
        if not d:
            continue
        client, app = schema.split("_", 1)
        if app.endswith("_draft") or d["appCode"] != app:
            continue
        out.append({"app": app, "client": client, "name": d["name"], "relations": list((d.get("relations") or {}).keys())})
    return out[:40]


# --- read-only cases -------------------------------------------------------------------------

def first_rows(app, client, name, n=3):
    s, v = java("POST", f"/api/core/data/{name}/query", H(app, client), {"size": n})
    return (v or {}).get("content", []) if s == 200 and isinstance(v, dict) else []


def read_cases(app, client, s):
    name = s["name"]
    tag = f"{app}/{client}/{name}"
    h = H(app, client)
    hg = H(app, client, json_body=False)
    base = f"/api/core/data/{name}"
    P.compare(f"query {tag}", "POST", base + "/query", h, {"size": 3})
    P.compare(f"query page 1 sorted {tag}", "POST", base + "/query", h,
              {"size": 2, "page": 1, "sort": [{"property": "_id", "direction": "DESC"}]})
    P.compare(f"query count false {tag}", "POST", base + "/query", h, {"size": 2, "count": False})
    P.compare(f"GET page {tag}", "GET", q(base, size=2, sort="_id,desc"), hg)
    P.compare(f"GET page default {tag}", "GET", base, hg)
    rows = first_rows(app, client, name)
    if rows:
        row = rows[0]
        rid = row.get("_id")
        P.compare(f"read {tag}", "GET", f"{base}/{rid}", hg)
        if s.get("relations"):
            P.compare(f"read eager {tag}", "GET", q(f"{base}/{rid}", eager="true"), hg)
            P.compare(f"query eager {tag}", "POST", base + "/query", h, {"size": 3, "eager": True})
            P.compare(f"query eagerFields {tag}", "POST", base + "/query", h,
                      {"size": 3, "eagerFields": [s["relations"][0]]})
        for k, v in row.items():
            if k != "_id" and isinstance(v, str) and 0 < len(v) < 60:
                P.compare(f"GET filter {k} {tag}", "GET", q(base, **{k: v, "size": "3"}), hg)
                P.compare(f"query filter {k} {tag}", "POST", base + "/query", h,
                          {"size": 3, "condition": {"field": k, "operator": "EQUALS", "value": v}})
                break
        P.compare(f"KIRun Read {tag}", "POST", EX + "Read", h,
                  {"storageName": name, "dataObjectId": rid, "appCode": app, "clientCode": client})
        if s.get("versioned"):
            P.compare(f"versions {tag}", "POST", f"{base}/version/{rid}/query", h, {"size": 2})
            P.compare(f"KIRun GetVersionDetails {tag}", "POST", EX + "GetVersionDetails", h,
                      {"storageName": name, "objectId": rid, "size": 2, "appCode": app, "clientCode": client})
            sv, vv = java("POST", f"{base}/version/{rid}/query", h, {"size": 1})
            if sv == 200 and isinstance(vv, dict) and vv.get("content"):
                vid = vv["content"][0].get("_id") or vv["content"][0].get("id")
                if vid:
                    P.compare(f"version by id {tag}", "GET", f"{base}/version/{vid}", hg)
    P.compare(f"read missing id {tag}", "GET", f"{base}/000000000000000000000000", hg)
    P.compare(f"aggregate count {tag}", "POST", base + "/aggregate", h,
              {"aggregations": [{"function": "COUNT", "field": "_id", "alias": "n"}]})
    P.compare(f"KIRun ReadPage {tag}", "POST", EX + "ReadPage", h,
              {"storageName": name, "size": 2, "appCode": app, "clientCode": client,
               "sort": [{"property": "_id", "direction": "DESC"}]})
    P.compare(f"KIRun Aggregate {tag}", "POST", EX + "Aggregate", h,
              {"storageName": name, "aggregations": [{"function": "COUNT", "field": "_id", "alias": "n"}],
               "appCode": app, "clientCode": client})
    P.compare(f"migrationStatus {tag}", "GET", f"{base}/migrationStatus", hg)
    P.compare(f"drift {tag}", "GET", f"{base}/drift", hg)
    for ft in ("CSV", "JSON", "TSV", "JSONL", "XLS"):
        twice(f"download {ft} {tag}", "GET", q(f"/api/core/data/download/{ft}/{name}", size="5"),
              q(f"/api/core/data/download/{ft}/{name}", size="5"), hg, raw=True)
    xlsx(f"download XLSX {tag}", q(f"/api/core/data/download/XLSX/{name}", size="5"), hg)
    xlsx(f"template XLSX {tag}", q(f"/api/core/data/template/{name}", type="XLSX"), hg)
    for ft in ("CSV", "XLS", "JSON"):
        twice(f"template {ft} {tag}", "GET", q(f"/api/core/data/template/{name}", type=ft),
              q(f"/api/core/data/template/{name}", type=ft), hg, raw=True)


def xlsx(name, path, hdrs):
    """An XLSX answer: the same zip entries with the same contents (the deflated bytes differ by
    implementation, D21)."""
    js, jct, jb = P.fetch(P.JAVA, "GET", path, hdrs)
    rs, rct, rb = P.fetch(P.RUST, "GET", path, hdrs)
    if js != 200 or rs != 200:
        (rs, rct, rb), coded = P.decode((js, jct, jb), (rs, rct, rb))
        same = js == rs and P.canon(mask(P.parse(jb))) == P.canon(mask(P.parse(rb)))
        return P.record_coded(name, "SAME" if same else "DIFF", "" if same else f"java {js} rust {rs}", coded)
    try:
        a, b = zipfile.ZipFile(io.BytesIO(jb)), zipfile.ZipFile(io.BytesIO(rb))
        same = a.namelist() == b.namelist() and all(a.read(n) == b.read(n) for n in a.namelist())
    except zipfile.BadZipFile as e:
        same = False
        print(f"# {name}: {e}")
    P.record(name, "SAME" if same else "DIFF")


def error_cases():
    hg = H("appbuilder", json_body=False)
    P.compare("data unknown storage", "GET", "/api/core/data/NoSuchStorageX/abc", hg)
    P.compare("data unknown storage query", "POST", "/api/core/data/NoSuchStorageX/query", H(), {"size": 1})
    P.compare("data anonymous", "POST", "/api/core/data/Doc/query", H(auth=None), {"size": 1}, expected=D15_no_basic_challenge)
    P.compare("spreadsheet anonymous", "POST", "/api/core/spreadsheet", H(auth=None), {"data": [[1]]},
              expected=D15_no_basic_challenge)
    P.compare("data missing appCode", "GET", "/api/core/data/Doc", P.headers(app=None), expected=D16_unknown_error_text)
    P.compare("data missing body", "POST", "/api/core/data/Doc/query", H(), None, expected=D16_unknown_error_text)
    P.compare("data bad body", "POST", "/api/core/data/Doc/query", H(), b"{bad", expected=D16_unknown_error_text)
    P.compare("data bad boolean", "GET", q("/api/core/data/Doc", eager="maybe"), hg, expected=D16_unknown_error_text)
    P.compare("delete storage not confirmed", "DELETE", "/api/core/data/Doc", hg)
    P.compare("delete rows not confirmed", "DELETE", "/api/core/data/Doc/rows", hg)
    P.compare("foreign client code", "GET", "/api/core/data/Doc", H(client="NOSUCHCLIENT", json_body=False),
              expected=D17_feign_debug_message)
    P.compare("internal read", "GET", q("/api/core/internal/data/Doc", size="2"), hg)
    P.compare("internal read anonymous", "GET", q("/api/core/internal/data/Doc", size="2"), H(auth=None, json_body=False))
    P.compare("KIRun Read unknown storage", "POST", EX + "Read", H(),
              {"storageName": "NoSuchStorageX", "dataObjectId": "x"}, expected=D2_kirun_error_text)
    P.compare("KIRun GetVersionDetails blank id", "POST", EX + "GetVersionDetails", H(),
              {"storageName": "Doc", "objectId": ""})
    for body in ({"data": [["a", "b"], [1, 2.5]], "skipHeader": True}, {"data": [{"x": 1, "y": "z"}], "type": "TSV"},
                 {"data": {"k": "v"}, "name": "one.csv", "downloadable": False}, {"data": [{"a": "1"}], "type": "JSON"},
                 {"data": [{"a": "1", "b": 2}], "type": "XLS"}, {"data": []}, {"data": [[None]]}):
        twice(f"spreadsheet {json.dumps(body)[:60]}", "POST", "/api/core/spreadsheet", "/api/core/spreadsheet", H(), body,
              raw=True, expected=D16_unknown_error_text)


# --- scratch storages ------------------------------------------------------------------------

SCHEMA = {"type": "OBJECT", "properties": {
    "name": {"type": "STRING"}, "age": {"type": "INTEGER"}, "score": {"type": "DOUBLE"}, "active": {"type": "BOOLEAN"},
    "tags": {"type": "ARRAY", "items": {"type": "STRING"}},
    "addr": {"type": "OBJECT", "properties": {"city": {"type": "STRING"}, "zip": {"type": "STRING"}}}}}


def storages():
    p = PREFIX
    rel = lambda target, kind="TO_ONE", delete="NOTHING", update="NOTHING": {  # noqa: E731
        "storageName": target, "relationType": kind, "deleteConstraint": delete, "updateConstraint": update}
    return [
        {"name": p + "Parent", "isVersioned": True, "schema": SCHEMA},
        {"name": p + "Child", "schema": {"type": "OBJECT", "properties": {"title": {"type": "STRING"}}},
         "relations": {"parent": rel(p + "Parent", delete="RESTRICT"), "many": rel(p + "Parent", "TO_MANY")}},
        {"name": p + "Owner", "schema": {"type": "OBJECT", "properties": {"name": {"type": "STRING"}}}},
        {"name": p + "Owned", "schema": {"type": "OBJECT", "properties": {"title": {"type": "STRING"}}},
         "relations": {"owner": rel(p + "Owner", delete="CASCADE")}},
        {"name": p + "Kirun", "onlyThruKIRun": True, "schema": {"type": "OBJECT", "properties": {"v": {"type": "STRING"}}}},
        {"name": p + "Auth", "readAuth": "Authorities.RustParity_Nope", "createAuth": "Authorities.RustParity_Nope",
         "schema": {"type": "OBJECT", "properties": {"v": {"type": "STRING"}}}},
        {"name": p + "Trig", "generateEvents": True,
         "triggers": {"BEFORE_CREATE": ["RustParity.noop"], "AFTER_CREATE": ["RustParity.missing"],
                      "BEFORE_UPDATE": ["RustParity.noop"], "AFTER_DELETE": ["RustParity.noop"]},
         "schema": {"type": "OBJECT", "properties": {"v": {"type": "STRING"}}}},
        {"name": p + "TrigLocked", "triggers": {"BEFORE_CREATE": ["RustParity.locked"]},
         "schema": {"type": "OBJECT", "properties": {"v": {"type": "STRING"}}}},
        {"name": p + "TrigNoDot", "triggers": {"BEFORE_CREATE": ["nodot"]},
         "schema": {"type": "OBJECT", "properties": {"v": {"type": "STRING"}}}},
    ]


FUNCTIONS = [
    {"name": "RustParity.noop", "definition": {"name": "noop", "namespace": "RustParity", "steps": {},
                                               "parameters": {"dataObject": {"parameterName": "dataObject",
                                                                             "schema": {"type": ["OBJECT", "NULL"]}}}}},
    {"name": "RustParity.locked", "executeAuth": "Authorities.RustParity_Nope",
     "definition": {"name": "locked", "namespace": "RustParity", "steps": {}}},
]

CREATED = {"storages": [], "functions": []}


def setup(app):
    hb = H("appbuilder")
    for f in FUNCTIONS:
        body = dict(f, appCode=app, clientCode="SYSTEM")
        s, v = java("POST", "/api/core/functions", hb, body)
        if s == 200:
            CREATED["functions"].append(v["id"])
        else:
            print(f"# setup: function {app} {f['name']}: {s} {v}")
    for st in storages():
        # An onlyThruKIRun storage's MySQL table could only be dropped from a builder session,
        # so the MySQL app gets none.
        if st.get("onlyThruKIRun") and app == "appa":
            continue
        body = dict(st, appCode=app, clientCode="SYSTEM")
        # MySQL's deleteStorage drops the table and leaves its `_version` table behind, so the
        # MySQL app's scratch storages keep no history.
        if app == "appa":
            body.pop("isVersioned", None)
        body["schema"] = dict(body["schema"], name=st["name"])
        s, v = java("POST", "/api/core/storages", hb, body)
        if s == 200:
            CREATED["storages"].append((v["id"], st["name"], app))
        else:
            print(f"# setup: storage {app} {st['name']}: {s} {json.dumps(v)[:300]}")


def cleanup():
    if KEEP:
        print(f"# kept: {CREATED}")
        return
    # Children before the storages they reference: on MySQL a RESTRICT or CASCADE relation is
    # a real foreign key, and the parent's table cannot be dropped under it.
    for _, name, app in reversed(CREATED["storages"]):
        h = H(app, "SYSTEM", json_body=False)
        for draft in ("", "&draft=true"):
            s, v = java("DELETE", f"/api/core/data/{name}?deleteAll=true{draft}", h)
            if s != 200:
                print(f"# cleanup: rows of {app} {name}{draft}: {s} {json.dumps(v)[:200]}")
    hb = H("appbuilder", json_body=False)
    for sid, name, _ in CREATED["storages"]:
        s, v = java("DELETE", f"/api/core/storages/{sid}", hb)
        if s != 200:
            print(f"# cleanup: storage {name}: {s} {v}")
    for fid in CREATED["functions"]:
        s, v = java("DELETE", f"/api/core/functions/{fid}", hb)
        if s != 200:
            print(f"# cleanup: function {fid}: {s} {v}")


def write_cases(SCRATCH, client):
    p = PREFIX
    h = H(SCRATCH, client)
    hg = H(SCRATCH, client, json_body=False)
    tag = f"{SCRATCH}/{client}"
    base = "/api/core/data/"
    row = {"name": "Ann", "age": 30, "score": 2.5, "active": True, "tags": ["a", "b"], "addr": {"city": "Pune", "zip": "411"}}

    twice(f"create unknown field {tag}", "POST", base + p + "Parent", base + p + "Parent", h,
          {"data": dict(row, extra=None, other="x")}, expected=D16_unknown_error_text)
    j, r = twice(f"create {tag}", "POST", base + p + "Parent", base + p + "Parent", h, {"data": row})
    if not j or j[0] != 200 or r[0] != 200:
        return
    jid, rid = j[1]["_id"], r[1]["_id"]
    for rowid, who in ((jid, "java row"), (rid, "rust row")):
        P.compare(f"read {who} {tag}", "GET", f"{base}{p}Parent/{rowid}", hg)
    twice(f"create bad type {tag}", "POST", base + p + "Parent", base + p + "Parent", h,
          {"data": {"name": "x", "age": "notanumber"}}, expected=D16_unknown_error_text)
    twice(f"create no data {tag}", "POST", base + p + "Parent", base + p + "Parent", h, {})
    twice(f"create with id {tag}", "POST", base + p + "Parent", base + p + "Parent", h,
          {"data": {"_id": jid, "name": "dup"}}, {"data": {"_id": rid, "name": "dup"}})
    twice(f"patch {tag}", "PATCH", f"{base}{p}Parent/{jid}", f"{base}{p}Parent/{rid}", h, {"data": {"age": 31, "name": None}})
    twice(f"put {tag}", "PUT", f"{base}{p}Parent/{jid}", f"{base}{p}Parent/{rid}", h,
          {"data": {"name": "Bea", "age": 40, "tags": []}, "message": "replaced"})
    twice(f"put no id {tag}", "PUT", f"{base}{p}Parent", f"{base}{p}Parent", h, {"data": {"_id": jid, "name": "Cy"}},
          {"data": {"_id": rid, "name": "Cy"}})
    twice(f"patch missing row {tag}", "PATCH", f"{base}{p}Parent/000000000000000000000000",
          f"{base}{p}Parent/000000000000000000000000", h, {"data": {"age": 1}})
    twice(f"read after updates {tag}", "GET", f"{base}{p}Parent/{jid}", f"{base}{p}Parent/{rid}", hg)
    # Versions only on Mongo: on MySQL a version read provisions a `_version` table that the
    # cleanup (Java's deleteStorage drops the row table only) would leave behind.
    if SCRATCH != "appa":
        twice(f"versions {tag}", "POST", f"{base}{p}Parent/version/{jid}/query", f"{base}{p}Parent/version/{rid}/query", h,
              {"size": 10, "sort": [{"property": "_id", "direction": "ASC"}]})
        twice(f"versions no object {tag}", "POST", q(f"{base}{p}Parent/version/{jid}/query", includeObject="false"),
              q(f"{base}{p}Parent/version/{rid}/query", includeObject="false"), h, {"size": 10})

    # KIRun writes.
    for fn, body in (("Create", {"dataObject": {"name": "K", "age": 9, "score": 3.0, "addr": {"zip": None}}}),
                     ("Create", {"dataObject": {"name": "Big", "age": 9007199254740993}}),
                     ("CreateMany", {"dataArray": [{"name": "M1"}, {"name": "M2", "age": 2}]})):
        twice(f"KIRun {fn} {json.dumps(body)[:40]} {tag}", "POST", EX + fn, EX + fn, h,
              dict(body, storageName=p + "Parent", appCode=SCRATCH, clientCode=client),
              expected=D16_unknown_error_text)
    twice(f"KIRun Update partial {tag}", "POST", EX + "Update", EX + "Update", h,
          {"storageName": p + "Parent", "dataObjectId": jid, "isPartial": True, "dataObject": {"score": 9.5},
           "appCode": SCRATCH, "clientCode": client},
          {"storageName": p + "Parent", "dataObjectId": rid, "isPartial": True, "dataObject": {"score": 9.5},
           "appCode": SCRATCH, "clientCode": client})
    twice(f"KIRun Update missing {tag}", "POST", EX + "Update", EX + "Update", h,
          {"storageName": p + "Parent", "dataObjectId": "000000000000000000000000", "dataObject": {"score": 1},
           "appCode": SCRATCH, "clientCode": client})
    twice(f"KIRun UpdateMany {tag}", "POST", EX + "UpdateMany", EX + "UpdateMany", h,
          {"storageName": p + "Parent", "isPartial": True, "dataArray": [{"_id": jid, "age": 50}], "appCode": SCRATCH,
           "clientCode": client},
          {"storageName": p + "Parent", "isPartial": True, "dataArray": [{"_id": rid, "age": 50}], "appCode": SCRATCH,
           "clientCode": client})
    twice(f"KIRun Read {tag}", "POST", EX + "Read", EX + "Read", h,
          {"storageName": p + "Parent", "dataObjectId": jid, "appCode": SCRATCH, "clientCode": client},
          {"storageName": p + "Parent", "dataObjectId": rid, "appCode": SCRATCH, "clientCode": client})
    twice(f"KIRun Read missing {tag}", "POST", EX + "Read", EX + "Read", h,
          {"storageName": p + "Parent", "dataObjectId": "000000000000000000000000", "appCode": SCRATCH, "clientCode": client})
    P.compare(f"KIRun ReadPage filtered {tag}", "POST", EX + "ReadPage", h,
              {"storageName": p + "Parent", "filter": {"field": "name", "operator": "EQUALS", "value": "M1"}, "size": 5,
               "ignoreFields": ["tags"], "appCode": SCRATCH, "clientCode": client})
    P.compare(f"query all {tag}", "POST", f"{base}{p}Parent/query", h,
              {"size": 50, "sort": [{"property": "name", "direction": "ASC"}], "fields": ["name", "age"]})

    # Relations.
    j2, r2 = twice(f"create child refs {tag}", "POST", base + p + "Child", base + p + "Child", h,
                   {"data": {"title": "c1", "parent": jid, "many": [jid]}}, {"data": {"title": "c1", "parent": rid, "many": [rid]}})
    twice(f"create child new parent {tag}", "POST", q(base + p + "Child", eager="true"), q(base + p + "Child", eager="true"),
          h, {"data": {"title": "c2", "parent": {"name": "Nested"}, "many": "a,b"}})
    twice(f"create child bad ref {tag}", "POST", base + p + "Child", base + p + "Child", h,
          {"data": {"title": "c3", "parent": "000000000000000000000000"}})
    if j2 and j2[0] == 200 and r2 and r2[0] == 200:
        jc, rc = j2[1]["_id"], r2[1]["_id"]
        twice(f"read child eager {tag}", "GET", q(f"{base}{p}Child/{jc}", eager="true"),
              q(f"{base}{p}Child/{rc}", eager="true"), hg)
        twice(f"read child eagerFields {tag}", "GET", q(f"{base}{p}Child/{jc}", eagerFields="many"),
              q(f"{base}{p}Child/{rc}", eagerFields="many"), hg)
        twice(f"delete restricted parent {tag}", "DELETE", f"{base}{p}Parent/{jid}", f"{base}{p}Parent/{rid}", hg)
        twice(f"patch child relation {tag}", "PATCH", f"{base}{p}Child/{jc}", f"{base}{p}Child/{rc}", h,
              {"data": {"many": []}})
        twice(f"delete child {tag}", "DELETE", f"{base}{p}Child/{jc}", f"{base}{p}Child/{rc}", hg)
    jo, ro = twice(f"create owner {tag}", "POST", base + p + "Owner", base + p + "Owner", h, {"data": {"name": "o"}})
    if jo and jo[0] == 200 and ro and ro[0] == 200:
        for i in range(2):
            twice(f"create owned {i} {tag}", "POST", base + p + "Owned", base + p + "Owned", h,
                  {"data": {"title": f"t{i}", "owner": jo[1]["_id"]}}, {"data": {"title": f"t{i}", "owner": ro[1]["_id"]}})
        twice(f"delete cascades {tag}", "DELETE", f"{base}{p}Owner/{jo[1]['_id']}", f"{base}{p}Owner/{ro[1]['_id']}", hg)
        twice(f"owned after cascade {tag}", "POST", f"{base}{p}Owned/query", f"{base}{p}Owned/query", h, {"size": 10})

    # Gates, triggers, onlyThruKIRun.
    twice(f"create forbidden {tag}", "POST", base + p + "Auth", base + p + "Auth", h, {"data": {"v": "x"}})
    P.compare(f"read forbidden {tag}", "POST", f"{base}{p}Auth/query", h, {"size": 1})
    P.compare(f"kirun-only public {tag}", "POST", f"{base}{p}Kirun/query", h, {"size": 1})
    P.compare(f"kirun-only builder session {tag}", "POST", f"{base}{p}Kirun/query", H("appbuilder", client), {"size": 1})
    P.compare(f"kirun-only internal {tag}", "GET", f"/api/core/internal/data/{p}Kirun", hg)
    twice(f"KIRun create kirun-only {tag}", "POST", EX + "Create", EX + "Create", h,
          {"storageName": p + "Kirun", "dataObject": {"v": "k"}, "appCode": SCRATCH, "clientCode": client})
    jt, rt = twice(f"create with triggers {tag}", "POST", base + p + "Trig", base + p + "Trig", h, {"data": {"v": "t"}})
    if jt and jt[0] == 200 and rt and rt[0] == 200:
        twice(f"update with triggers {tag}", "PATCH", f"{base}{p}Trig/{jt[1]['_id']}", f"{base}{p}Trig/{rt[1]['_id']}", h,
              {"data": {"v": "u"}})
        twice(f"delete with triggers {tag}", "DELETE", f"{base}{p}Trig/{jt[1]['_id']}", f"{base}{p}Trig/{rt[1]['_id']}", hg)
    twice(f"KIRun CreateMany with events {tag}", "POST", EX + "CreateMany", EX + "CreateMany", h,
          {"storageName": p + "Trig", "dataArray": [{"v": "e"}], "appCode": SCRATCH, "clientCode": client})
    twice(f"trigger needs authority {tag}", "POST", base + p + "TrigLocked", base + p + "TrigLocked", h, {"data": {"v": "x"}})
    twice(f"trigger without namespace {tag}", "POST", base + p + "TrigNoDot", base + p + "TrigNoDot", h, {"data": {"v": "x"}},
          expected=D16_unknown_error_text)

    # Uploads (one each; the rows are compared through a query of both services' rows).
    for ft, content in (("CSV", b"name,age,addr.city,tags[0]\nUp1,7,Goa,t\n"), ("JSON", b'[{"name":"Up2","age":8}]'),
                        ("JSONL", b'{"name":"Up3"}\n{"name":"Up4","active":true}')):
        boundary = "rustparityboundary"
        body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"up.{ft.lower()}\"\r\n"
                f"Content-Type: application/octet-stream\r\n\r\n").encode() + content + f"\r\n--{boundary}--\r\n".encode()
        hu = dict(H(SCRATCH, client, json_body=False), **{"Content-Type": f"multipart/form-data; boundary={boundary}"})
        twice(f"upload {ft} {tag}", "POST", f"{base}upload/{p}Parent", f"{base}upload/{p}Parent", hu, body)
    twice(f"upload bad json {tag}", "POST", q(f"{base}upload/{p}Parent", type="JSON"), q(f"{base}upload/{p}Parent", type="JSON"),
          dict(H(SCRATCH, client, json_body=False), **{"Content-Type": "multipart/form-data; boundary=b"}),
          b"--b\r\nContent-Disposition: form-data; name=\"file\"; filename=\"x\"\r\n\r\n{}\r\n--b--\r\n")
    P.compare(f"query after uploads {tag}", "POST", f"{base}{p}Parent/query", h,
              {"size": 100, "sort": [{"property": "name", "direction": "ASC"}],
               "condition": {"field": "name", "operator": "LIKE", "value": "Up"}}, expected=None)

    # Builder operations and the draft surface.
    P.compare(f"rows dry run {tag}", "DELETE", q(f"{base}{p}Parent/rows", dryRun="true"), hg)
    twice(f"copy to draft {tag}", "POST", f"{base}{p}Parent/copyToDraft", f"{base}{p}Parent/copyToDraft", hg)
    P.compare(f"draft read {tag}", "GET", q(f"{base}{p}Parent", draft="true", size="3", sort="name"), hg)
    P.compare(f"draft read not allowed {tag}", "GET", q(f"{base}{p}Parent", draft="true"), H("leadzump", client, json_body=False))
    twice(f"copy empty to draft {tag}", "POST", f"{base}{p}Owner/copyToDraft", f"{base}{p}Owner/copyToDraft", hg)
    # ClearDraft and CopyToDraft act on every storage of the app's draft surface, not only the
    # scratch ones, so they are left to the unit tests (storage::service tests) rather than run
    # against a shared app here.
    P.compare(f"KIRun DeleteByFilter dev mode {tag}", "POST", EX + "DeleteByFilter", h,
              {"storageName": p + "Parent", "devMode": True, "filter": {"field": "name", "operator": "EQUALS", "value": "M1"},
               "appCode": SCRATCH, "clientCode": client})

    # Deletes last.
    twice(f"KIRun Delete {tag}", "POST", EX + "Delete", EX + "Delete", h,
          {"storageName": p + "Parent", "dataObjectId": jid, "appCode": SCRATCH, "clientCode": client},
          {"storageName": p + "Parent", "dataObjectId": rid, "appCode": SCRATCH, "clientCode": client})
    twice(f"KIRun Delete again {tag}", "POST", EX + "Delete", EX + "Delete", h,
          {"storageName": p + "Parent", "dataObjectId": jid, "appCode": SCRATCH, "clientCode": client},
          {"storageName": p + "Parent", "dataObjectId": rid, "appCode": SCRATCH, "clientCode": client})
    twice(f"delete missing {tag}", "DELETE", f"{base}{p}Parent/000000000000000000000000",
          f"{base}{p}Parent/000000000000000000000000", hg)


def main():
    if "--writes" in sys.argv:
        return finish_writes()
    error_cases()
    ms = mongo_storages()
    print(f"# {len(ms)} Mongo storages with rows")
    for s in ms:
        if not s["kirun"]:
            read_cases(s["app"], "SYSTEM", s)
    my = mysql_storages()
    print(f"# {len(my)} MySQL storages with rows")
    for s in my:
        read_cases(s["app"], s["client"], s)
    try:
        for app, client in SCRATCH_APPS:
            if ONLY and app not in ONLY:
                continue
            setup(app)
            write_cases(app, client)
    finally:
        cleanup()
    summary()


def finish_writes():
    try:
        for app, client in SCRATCH_APPS:
            if ONLY and app not in ONLY:
                continue
            setup(app)
            write_cases(app, client)
    finally:
        cleanup()
    summary()


def summary():
    counts, tags = {}, {}
    for _, v, _ in P.RESULTS:
        counts[v.split(" ")[0]] = counts.get(v.split(" ")[0], 0) + 1
        if v.startswith("EXPECTED"):
            tags[v[9:]] = tags.get(v[9:], 0) + 1
    print(f"\n{len(P.RESULTS)} cases: " + ", ".join(f"{k} {n}" for k, n in sorted(counts.items())))
    if tags:
        print("EXPECTED by tag: " + ", ".join(f"{k} {n}" for k, n in sorted(tags.items())))
    sys.exit(1 if counts.get("DIFF") else 0)


if __name__ == "__main__":
    main()
