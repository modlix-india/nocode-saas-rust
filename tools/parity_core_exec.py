#!/usr/bin/env python3
"""Sends the same requests to the Java core (8005) and core-exec (8105) and compares them.

Usage: parity_core_exec.py [java_base] [rust_base] [-v]
       defaults: http://localhost:8005  http://localhost:8105

Cases:
- System (KIRun) functions by name, GET with query parameters and POST with JSON bodies;
- core's own functions (SecurityContext, Crypto, Hash, GetAppUrl);
- stored functions from the local `core` Mongo `function` collection whose steps call only
  System functions and the core functions above (read-only: nothing that touches storage,
  REST, email, events or security writes), GET and POST with arguments made from their
  parameter schemas;
- errors (unknown function, missing headers, bad numbers, execution authorization);
- functions / schemas `repositoryFind` and `repositoryFilter`.

Bodies are compared as JSON: error ids, stack traces and the id inside "Please try again"
messages are ignored, `type` arrays (Java sets) compare as sets, and `repositoryFilter` lists as
multisets. Each case is SAME, EXPECTED (a difference listed in crates/core/DIFFERENCES.md, with
its tag), or DIFF.

Coded Rust errors (`code`, plain `message`, `action`...) are compared by code first
(tools/error_parity.py): when the code stands for Java's text, Rust's answer is put back into
Java's shape and compared as before; such a case reads "EXPECTED coded" (or keeps its rule's tag
with the code noted). A code that does not stand for Java's text is a DIFF.
"""
import base64
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import error_parity  # noqa: E402  coded Rust errors are compared by code (crates/core/DIFFERENCES.md, Error bodies)

ARGS = [a for a in sys.argv[1:] if not a.startswith("-")]
VERBOSE = "-v" in sys.argv
JAVA = ARGS[0] if len(ARGS) > 0 else "http://localhost:8005"
RUST = ARGS[1] if len(ARGS) > 1 else "http://localhost:8105"

BASIC = "Basic " + base64.b64encode(b"142:Pass@1234").decode()

# Storage functions a stored function may call and still be run by this script: the reads.
STORAGE_READS = ("Read", "ReadPage", "Aggregate", "GetVersionDetails")

PURE_NAMESPACES = ("System",)
PURE_CORE = {
    "CoreServices.SecurityContext", "CoreServices.Hash", "CoreServices.Crypto",
}

# Step 3 core functions that only read, so a stored function calling them may be run on both
# services. Everything else (REST, e-mail, events, schedules, notifications, AI, WhatsApp,
# calls, PDF uploads, the security writes) sends or writes on the Java side and is never run
# from a stored function here.
SECURITY_READS = ("GetAppUrl", "GetClient", "IsBeingManagedByCode", "IsBeingManagedById", "GetAppProfiles",
                  "GetClientUsersPage", "GetClientsByIds", "GetClientsDenorm", "GetManagedClientIds", "GetOwnersEmails",
                  "GetUser", "GetUserAdminEmails", "GetUserSubOrg", "GetUsersByIds", "GetUsersForDistribution",
                  "QueryClientActivities", "QueryUsers")
FILE_READS = ("FileToBase64",)


def headers(app="appbuilder", client="SYSTEM", auth=BASIC, extra=None, json_body=False):
    h = {"clientCode": client, "appCode": app, "X-Forwarded-Host": "localhost", "X-Forwarded-Port": "8080"}
    if auth:
        h["Authorization"] = auth
    if json_body:
        h["Content-Type"] = "application/json"
    h.update(extra or {})
    return {k: v for k, v in h.items() if v is not None}


def fetch(base, method, path, hdrs, body=None):
    data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
    req = urllib.request.Request(base + path, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, r.headers.get("content-type") or "", r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("content-type") or "", e.read()
    except Exception as e:  # noqa: BLE001 - a dead service is a result too
        return 0, "", str(e).encode()


ID_RE = re.compile(r"\d{4}-\d{2}-\d{2}-[0-9a-f]+")


def parse(body):
    if not body:
        return None
    try:
        return json.loads(body)
    except ValueError:
        return body.decode(errors="replace")


SET_KEYS = ("grantedAuthorities",)


def canon(v, key=None, loose_numbers=False, sets=()):
    """A comparable form: dicts by key, `type` lists (and `sets` keys) as sets, numbers exact
    (int and float differ) unless loose."""
    if isinstance(v, dict):
        d = dict(v)
        if "exceptionId" in d and "debugMessage" in d:
            d.pop("exceptionId", None)
            d.pop("stackTrace", None)
            for k in ("message", "debugMessage"):
                if isinstance(d.get(k), str):
                    d[k] = ID_RE.sub("<id>", d[k])
        return {k: canon(x, k, loose_numbers, sets) for k, x in sorted(d.items())}
    if isinstance(v, list):
        items = [canon(x, None, loose_numbers, sets) for x in v]
        if key == "type" and all(isinstance(x, str) for x in v):
            return ("set", tuple(sorted(items)))
        if key in sets:
            return ("set", tuple(sorted(json.dumps(i, sort_keys=True) for i in items)))
        return items
    if isinstance(v, bool) or v is None or isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        return float(v) if loose_numbers else (type(v).__name__, v)
    return v


def is_unknown_error(v):
    return isinstance(v, dict) and str(v.get("message", "")).startswith("Please try again. A server error")


RESULTS = []


SECURITY_HEALTH = "http://localhost:8001/actuator/health"


def wait_for_security(limit_seconds=900):
    """Waits until security's /actuator/health answers 200 (it stalls under load at times),
    then a little longer for its pooled connections to settle."""
    deadline = time.time() + limit_seconds
    while time.time() < deadline:
        status, _, _ = fetch("", "GET", SECURITY_HEALTH, {})
        if status == 200:
            time.sleep(5)
            return
        time.sleep(10)


def security_down(status, v):
    """The local security service did not answer the caller lookup (it stalls under load at
    times); such a case says nothing about core and is retried, then skipped."""
    return status == 0 or (status == 500 and "securityContextAuthentication" in str(v))


def record(name, verdict, detail=""):
    RESULTS.append((name, verdict, detail))
    if verdict != "SAME" or VERBOSE:
        print(f"{verdict:<22} {name}" + (f"\n    {detail}" if detail else ""))


def decode(java, rust):
    """`error_parity.decode` on `(status, content type, body)` answers: Rust's coded error put
    back into Java's shape when its code stands for Java's text, and the note on it."""
    return error_parity.decode(java, rust)


def record_coded(name, verdict, detail, coded):
    """`record` once the coded check is known: a coded answer that otherwise matches is
    EXPECTED coded; a code that does not stand for Java's text is a DIFF."""
    if error_parity.is_problem(coded):
        return record(name, "DIFF coded", error_parity.detail(coded, detail))
    if coded and verdict == "SAME":
        return record(name, "EXPECTED coded", error_parity.detail(coded) if VERBOSE else coded)
    if coded:
        return record(name, verdict, error_parity.detail(coded, detail))
    return record(name, verdict, detail)


def compare(name, method, path, hdrs, body=None, kind="json", expected=None, clock=False):
    if expected is None and "/function/execute/" in path:
        expected = any_of(D30_feign_debug_message, D2_kirun_error_text)
    for attempt in range(6):
        js, jct, jb = fetch(JAVA, method, path, hdrs, body)
        rs, rct, rb = fetch(RUST, method, path, hdrs, body)
        jv, rv = parse(jb), parse(rb)
        if not (security_down(js, jv) or security_down(rs, rv)):
            break
        wait_for_security()
    else:
        return record(name, "SKIP security-unreachable")
    (rs, rct, rb), coded = decode((js, jct, jb), (rs, rct, rb))
    rv = parse(rb)
    if clock:
        jv, rv = mask_clock(jv, rv)
    def short(x):
        if isinstance(x, dict) and "stackTrace" in x:
            x = {k: v for k, v in x.items() if k not in ("stackTrace", "exceptionId")}
        return json.dumps(x)[:500] if not isinstance(x, str) else x[:500]
    detail = f"java {js} {short(jv)}\n    rust {rs} {short(rv)}"
    if js != rs:
        if expected and expected(js, jv, rs, rv):
            return record_coded(name, f"EXPECTED {expected.__name__}", detail, coded)
        return record_coded(name, "DIFF status", detail, coded)
    if js == 200 and (jct.split(";")[0] != rct.split(";")[0]):
        return record_coded(name, "DIFF content-type", f"java {jct!r} rust {rct!r}", coded)
    if kind == "list" and isinstance(jv, list) and isinstance(rv, list):
        if sorted(jv) == sorted(rv):
            return record_coded(name, "SAME", "", coded)
        if expected and expected(js, jv, rs, rv):
            return record_coded(name, f"EXPECTED {expected.__name__}", detail, coded)
        missing = sorted(set(jv) - set(rv))
        extra = sorted(set(rv) - set(jv))
        return record_coded(name, "DIFF", f"missing in rust: {missing[:20]}\n    extra in rust: {extra[:20]}", coded)
    if canon(jv) == canon(rv):
        return record_coded(name, "SAME", "", coded)
    if canon(jv, loose_numbers=True) == canon(rv, loose_numbers=True):
        return record_coded(name, "EXPECTED D1-number-repr", detail if VERBOSE else "", coded)
    if canon(jv, sets=SET_KEYS) == canon(rv, sets=SET_KEYS):
        return record_coded(name, "EXPECTED D9-granted-authority-order", detail if VERBOSE else "", coded)
    if expected and expected(js, jv, rs, rv):
        return record_coded(name, f"EXPECTED {expected.__name__}", detail, coded)
    return record_coded(name, "DIFF", detail, coded)


# --- EXPECTED rules (each one is a numbered entry in crates/core/DIFFERENCES.md) ---------------

def D2_kirun_error_text(js, jv, rs, rv):
    """Both failed inside the KIRun runtime with an unknown (500) error; only the runtime's
    error wording differs (kirun-rust follows kirun-js)."""
    return js == rs == 500 and is_unknown_error(jv) and is_unknown_error(rv)


def D30_feign_debug_message(js, jv, rs, rv):
    """Another service (security, files, message) refused a core function's call: same status
    and message; Java's debugMessage is Feign's exception text (method, URL, the downstream
    body), core-exec's is the message, or (a coded refusal from a Rust security unit, passed on
    as it came) that unit's own detail, which starts with Java's text ("Access Denied: needs
    Authorities.User_READ")."""
    if js != rs or not isinstance(jv, dict) or not isinstance(rv, dict):
        return False
    same_message = ID_RE.sub("<id>", str(jv.get("message"))) == ID_RE.sub("<id>", str(rv.get("message")))
    rust_debug, message = str(rv.get("debugMessage")), str(rv.get("message"))
    return same_message and "] during [" in str(jv.get("debugMessage", "")) and rust_debug.startswith(message)


def ER13_mysql_error_text(js, jv, rs, rv):
    """Both answer an unknown error for a statement MySQL refused; Java's debugMessage is
    jOOQ's (the SQL, then the driver's message), core-exec's is the driver's message alone."""
    return js == rs == 500 and is_unknown_error(jv) and is_unknown_error(rv) and \
        str(jv.get("debugMessage", "")).endswith(str(rv.get("debugMessage", "")))


def D4_kirun_builtins(js, jv, rs, rv):
    """KIRun's own functions and schemas: kirun-rust's set and signatures are kirun-js's."""
    if isinstance(jv, list) and isinstance(rv, list) and all(isinstance(n, str) for n in jv + rv):
        strip = lambda l: sorted(n for n in l if not n.startswith("System"))  # noqa: E731
        return strip(jv) == strip(rv)
    return js == rs == 200


def D5_java_jackson_jsonprimitive(js, jv, rs, rv):
    """Java cannot write a schema holding enums / defaultValue / examples / constant
    (Jackson on Gson's JsonPrimitive) and answers 500; core-exec answers the schema."""
    return js == 500 and rs == 200 and "JSON encoding error" in str(jv)


def D7_definition_java_cannot_read(js, jv, rs, rv):
    """Java fails to read the stored definition (Gson type errors such as `type: ["EXPRESSION"]`,
    or no `steps`); core-exec reads and runs it."""
    d = str((jv or {}).get("debugMessage", "")) if isinstance(jv, dict) else ""
    return js == 500 and ("IllegalStateException: Expected" in d or "getSteps()\" is null" in d
                          or "JsonSyntaxException" in d)


def D12_body_not_object(js, jv, rs, rv):
    """A POST body that is not a JSON object: 500 both, Gson's exception text differs."""
    return js == rs == 500 and is_unknown_error(jv) and is_unknown_error(rv)


# K1-K6 (kirun-rust following kirun-js where the Java core runs kirun-java) were resolved on
# 2026-10-17 in the kirun crate (see crates/core/DIFFERENCES.md); a case that shows one again is
# a DIFF.

ISO_INSTANT = re.compile(r"^[+-]?\d{4,}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}(Z|[+-]\d{2}:\d{2}(:\d{2})?)$")


def _instant(s):
    """Epoch milliseconds of a kirun ISO timestamp (yyyy-MM-ddTHH:mm:ss.SSS+offset)."""
    from datetime import datetime
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000
    except ValueError:
        return None


def mask_clock(a, b, tolerance_ms=5000):
    """A function that reads the clock (System.Date.GetCurrentTimestamp) answers a few
    milliseconds apart on the two services: where the two answers differ only by such a skew (two
    ISO timestamps, or two epoch seconds / milliseconds, within five seconds), both are replaced
    by the same placeholder. Values that are equal, or differ by more, are left alone."""
    if isinstance(a, dict) and isinstance(b, dict):
        keys = set(a) & set(b)
        ma, mb = dict(a), dict(b)
        for k in keys:
            ma[k], mb[k] = mask_clock(a[k], b[k], tolerance_ms)
        return ma, mb
    if isinstance(a, list) and isinstance(b, list) and len(a) == len(b):
        pairs = [mask_clock(x, y, tolerance_ms) for x, y in zip(a, b)]
        return [p[0] for p in pairs], [p[1] for p in pairs]
    if isinstance(a, str) and isinstance(b, str) and a != b and ISO_INSTANT.match(a) and ISO_INSTANT.match(b):
        ia, ib = _instant(a), _instant(b)
        if ia is not None and ib is not None and abs(ia - ib) <= tolerance_ms:
            return "<clock>", "<clock>"
    if isinstance(a, (int, float)) and isinstance(b, (int, float)) and not isinstance(a, bool) \
            and not isinstance(b, bool) and a != b:
        scale = 1 if min(abs(a), abs(b)) >= 1e12 else 1000 if min(abs(a), abs(b)) >= 1e9 else None
        if scale and abs(a - b) * scale <= tolerance_ms:
            return "<clock>", "<clock>"
    return a, b


# --- the cases ---------------------------------------------------------------------------------

def q(path, **params):
    items = []
    for k, v in params.items():
        for x in (v if isinstance(v, list) else [v]):
            items.append((k, x))
    return path + ("?" + urllib.parse.urlencode(items) if items else "")


def system_cases():
    ex = "/api/core/function/execute/"
    H, HJ = headers(), headers(json_body=True)
    compare("GET System.Math.Add", "GET", q(ex + "System.Math/Add", value=["1", "2"]), H)
    compare("GET System.Math.Add full name", "GET", q(ex + "System.Math.Add", value=["1.5", "2"]), H)
    compare("POST System.Math.Add ints", "POST", ex + "System.Math/Add", HJ, {"value": [1, 2, 3]})
    compare("POST System.Math.Add doubles", "POST", ex + "System.Math.Add", HJ, {"value": [1.5, 2.25]})
    # kirun-rust raises no event for an Add without values since 2026-10-17, as kirun-java: SAME.
    compare("POST System.Math.Add empty", "POST", ex + "System.Math/Add", HJ, {})
    compare("POST System.Math.Add bad", "POST", ex + "System.Math/Add", HJ, {"value": ["abc"]}, expected=D2_kirun_error_text)
    compare("POST System.Math.Maximum", "POST", ex + "System.Math/Maximum", HJ, {"value": [4, 9, 2]})
    compare("POST System.Math.Absolute", "POST", ex + "System.Math/Absolute", HJ, {"value": -7})
    compare("GET System.String.ToString", "GET", q(ex + "System.String/ToString", value="x"), H)
    compare("POST System.String.Concatenate", "POST", ex + "System.String/Concatenate", HJ, {"value": ["a", "<b>", "c&d"]})
    compare("POST System.String.Reverse", "POST", ex + "System.String/Reverse", HJ, {"value": "abc"})
    compare("POST System.String.Split", "POST", ex + "System.String/Split", HJ, {"string": "a,b,c", "searchString": ","})
    compare("POST System.String.Trim", "POST", ex + "System.String/Trim", HJ, {"value": "  x  "})
    compare("POST System.Array.Sort", "POST", ex + "System.Array/Sort", HJ, {"source": [3, 1, 2]})
    compare("POST System.Array.IndexOf", "POST", ex + "System.Array/IndexOf", HJ, {"source": ["a", "b"], "elementToFind": "b"})
    compare("POST System.Array.Reverse", "POST", ex + "System.Array/Reverse", HJ, {"source": [1, 2, 3]})
    compare("POST System.Object.ObjectKeys", "POST", ex + "System.Object/ObjectKeys", HJ, {"source": {"a": 1, "b": 2}})
    compare("POST System.JSON.JSONStringify", "POST", ex + "System.JSON/JSONStringify", HJ, {"source": {"a": [1, "x"]}})
    compare("POST System.If", "POST", ex + "System/If", HJ, {"condition": True})
    compare("POST System.GenerateEvent", "POST", ex + "System/GenerateEvent", HJ,
            {"eventName": "output", "results": [{"name": "x", "value": 5}]})
    compare("GET System.Math.Add anonymous", "GET", q(ex + "System.Math/Add", value=["1", "2"]), headers(auth=None))


def core_cases():
    ex = "/api/core/function/execute/"
    H, HJ = headers(), headers(json_body=True)
    anon = headers(auth=None)
    compare("HasAuthority owner", "POST", ex + "CoreServices.SecurityContext/HasAuthority", HJ, {"authority": "Authorities.ROLE_Owner"})
    compare("HasAuthority missing", "POST", ex + "CoreServices.SecurityContext/HasAuthority", HJ, {"authority": "Authorities.ROLE_Nobody"})
    compare("HasAuthority expression", "GET", q(ex + "CoreServices.SecurityContext/HasAuthority",
            authority="Authorities.ROLE_Nobody or Authorities.Logged_IN"), H)
    compare("HasAuthority blank", "POST", ex + "CoreServices.SecurityContext/HasAuthority", HJ, {"authority": ""})
    compare("HasAuthority anonymous", "POST", ex + "CoreServices.SecurityContext/HasAuthority",
            headers(auth=None, json_body=True), {"authority": "Authorities._Anonymous"})
    compare("GetAuthentication", "GET", ex + "CoreServices.SecurityContext/GetAuthentication", H)
    compare("GetAuthentication anonymous", "GET", ex + "CoreServices.SecurityContext.GetAuthentication", anon)
    compare("GetAuthentication other client header", "GET", ex + "CoreServices.SecurityContext/GetAuthentication",
            headers(app="leadzump"))
    compare("GetUser", "GET", ex + "CoreServices.SecurityContext/GetUser", H)
    compare("GetUser anonymous", "GET", ex + "CoreServices.SecurityContext/GetUser", anon)
    compare("GetAppUrl", "POST", ex + "CoreServices.Security/GetAppUrl", HJ, {"appCode": "appbuilder", "clientCode": "SYSTEM"})
    compare("GetAppUrl no client", "GET", q(ex + "CoreServices.Security/GetAppUrl", appCode="leadzump"), H)
    compare("GetAppUrl unknown app", "GET", q(ex + "CoreServices.Security.GetAppUrl", appCode="nothingHere"), H)
    for alg in ["SHA-256", "SHA-384", "SHA-512", "MD5", "MD2", "SHA-1"]:
        compare(f"HashData {alg}", "POST", ex + "CoreServices.Hash/HashData", HJ, {"data": {"a": [1, "x", None], "b": True}, "algorithm": alg})
    compare("HashData MD4", "POST", ex + "CoreServices.Hash/HashData", HJ, {"data": "abc", "algorithm": "MD4"})
    compare("HashData default", "GET", q(ex + "CoreServices.Hash/HashData", data="hello"), H)
    compare("HashData primitive level", "POST", ex + "CoreServices.Hash/HashData", HJ,
            {"data": {"k": "v", "n": 12, "d": 1.5, "l": [True, None]}, "primitiveLevel": True})
    compare("HashData null", "POST", ex + "CoreServices.Hash/HashData", HJ, {"data": None})
    compare("HashData string html", "POST", ex + "CoreServices.Hash/HashData", HJ, {"data": "<a href='x'>&"})
    compare("HashData bad algorithm", "POST", ex + "CoreServices.Hash/HashData", HJ, {"data": 1, "algorithm": "SHA-3"},
            expected=D2_kirun_error_text)
    key32 = "0123456789abcdef0123456789abcdef"
    key64 = key32 * 2
    for alg, key in [("HmacSHA256", key32), ("HmacSHA384", key64), ("HmacSHA512", key64)]:
        for enc in ["base64", "Hex"]:
            body = {"alg": alg, "secretKey": key, "data": {"x": 1, "y": "z"}, "signatureEncoder": enc}
            compare(f"Signer {alg} {enc}", "POST", ex + "CoreServices.Crypto/Signer", HJ, body)
    for cs in ["US-ASCII", "ISO-8859-1", "UTF-8", "UTF-16BE", "UTF-16LE", "UTF-16"]:
        compare(f"Signer charset {cs}", "POST", ex + "CoreServices.Crypto/Signer", HJ,
                {"alg": "HmacSHA256", "charset": cs, "secretKey": key32 + "é", "data": "héllo"})
    compare("Signer short key", "POST", ex + "CoreServices.Crypto/Signer", HJ, {"alg": "HmacSHA256", "secretKey": "short", "data": "x"})
    compare("Signer empty key", "POST", ex + "CoreServices.Crypto/Signer", HJ, {"alg": "HmacSHA256", "secretKey": "", "data": "x"})
    compare("Signer number data", "POST", ex + "CoreServices.Crypto/Signer", HJ, {"alg": "HmacSHA256", "secretKey": key32, "data": 42})
    # A signature made by Java, checked by both.
    _, _, jb = fetch(JAVA, "POST", ex + "CoreServices.Crypto/Signer", HJ,
                     {"alg": "HmacSHA256", "secretKey": key32, "data": "payload"})
    try:
        sig = json.loads(jb)[0]["result"]["result"]
    except (ValueError, KeyError, IndexError, TypeError):
        sig = ""
    for s, label in [(sig, "valid"), (sig[:-2] + "AA" if sig else "x", "invalid"), ("!!!", "malformed")]:
        compare(f"SignatureValidator {label}", "POST", ex + "CoreServices.Crypto/SignatureValidator", HJ,
                {"alg": "HmacSHA256", "secretKey": key32, "data": "payload", "signature": s})
    compare("SignatureValidator hex odd", "POST", ex + "CoreServices.Crypto/SignatureValidator", HJ,
            {"alg": "HmacSHA256", "secretKey": key32, "data": "payload", "signature": "abc", "signatureEncoder": "Hex"})


def error_cases():
    ex = "/api/core/function/execute/"
    H, HJ = headers(), headers(json_body=True)
    compare("unknown function", "GET", ex + "Nope/Nothing", H)
    compare("unknown function full name", "POST", ex + "Nope.Nothing", HJ, {})
    compare("full name without dot", "GET", ex + "NoDot", H)
    for missing in ["X-Forwarded-Host", "X-Forwarded-Port", "appCode", "clientCode"]:
        h = headers()
        h.pop(missing)
        compare(f"missing header {missing}", "GET", q(ex + "System.Math/Add", value="1"), h)
    compare("bad double in query", "GET", q(ex + "System.Math/Add", value="abc"), H)
    compare("empty double in query", "GET", q(ex + "System.Math/Add", value=""), H)
    compare("blank POST body", "POST", ex + "System.Math/Add", HJ, b"   ")
    compare("POST without a body", "POST", ex + "System.Math/Add", headers())
    compare("POST body not an object", "POST", ex + "System.Math/Add", HJ, [1, 2], expected=D12_body_not_object)
    compare("execution authorization refused", "POST", ex + "LeadZumpV2/wzHoldText",
            headers(app="leadzumptwo", json_body=True), {"reason": "x"})
    compare("bad token is anonymous", "GET", q(ex + "System.Math/Add", value="1"), headers(auth="Bearer abc.def.ghi"))
    compare("draft surface stored function", "GET", q(ex + "Test/fibonacci", n="7"), headers(extra={"x-draft": "true"}))
    compare("x-debug stored function", "GET", q(ex + "Test/fibonacci", n="12"), headers(extra={"x-debug": "parity-core"}))
    compare("remote entity-processor read", "POST", ex + "EntityProcessor.Campaign/ReadPageFilter",
            headers(app="leadzump", json_body=True), {"pageable": {"page": 0, "size": 1}})
    compare("remote entity-processor unknown", "POST", ex + "EntityProcessor.Campaign/Nope",
            headers(app="leadzump", json_body=True), {})
    compare("dependency app function", "GET", q(ex + "MarketingAI/verifyLeadgen", hubChallenge="5", hubMode="subscribe",
            hubVerifyToken="x"), headers(app="leadzump"))


def step3_cases():
    """The step 3 functions, executed directly. Only `DefinitionFunction` marks a run as a
    server function, so every function that sends, publishes or writes refuses here before
    doing anything; the REST functions name a connection that does not exist, which Java
    answers without a call ("Connection Not found")."""
    ex = "/api/core/function/execute/"
    HJ = headers(json_body=True)
    nc = "RustParityNoSuchConnection"
    cases = [
        ("Event", "CreateEvent", {"eventName": "RustParity.none", "eventData": {"a": 1}}),
        ("Event", "ScheduleEvent", {"eventName": "RustParity.none", "key": "rp-1"}),
        ("Event", "ScheduleEvent", {"eventName": "RustParity.none", "runAt": "2026-10-15T10:00:00+05"}),
        ("Event", "ScheduleEvent", {"eventName": "RustParity.none", "runAt": 1760000000000}),
        ("Event", "ScheduleEvent", {"eventName": "RustParity.none", "runAt": "not a time"}),
        ("Event", "ScheduleEvent", {"eventName": "RustParity.none", "runAt": {"a": 1}}),
        ("Event", "ScheduleEvent", {}),
        ("Event", "CancelScheduledEvent", {"key": "rp-1"}),
        ("Event", "CancelScheduledEvent", {"key": "rp-1", "clientCode": "FIN"}),
        ("Event", "SetScheduleEnabled", {"eventName": "RustParity.none", "enabled": False}),
        ("Email", "SendEmail", {"connectionName": nc, "templateName": "x", "address": ["a@x.com"]}),
        ("Notification", "SendNotification", {"connectionName": nc, "notificationName": "x", "targetId": 1}),
        ("AI", "Chat", {"connectionName": nc, "prompt": "hi"}),
        ("Message", "SendWhatsapp", {"to": "+910000000000", "text": "x"}),
        ("Message", "SendWhatsapp", {}),
        ("Message", "MakeCall", {"toNumber": "0000000000"}),
        ("Message", "LinkWhatsappNumber", {"phoneNumber": "+910000000000"}),
        ("Message", "ListWhatsappNumbers", {}),
        ("Message", "GetWhatsappPairingCode", {"sessionCode": "rp"}),
        ("Message", "RemoveWhatsappNumber", {"sessionCode": "rp"}),
        ("Message", "SetDefaultWhatsappNumber", {"sessionCode": "rp"}),
        ("File", "TemplateToPdf", {"templateName": "x"}),
        ("File", "FileToBase64", {"filePath": "/rust-parity-none.txt"}),
        ("File", "FileToBase64", {"filePath": "/rust-parity-none.txt", "fileType": "STATIC", "metadataRequired": True}),
        ("File", "FileToBase64", {}),
        ("REST", "GetRequest", {"connectionName": nc, "url": "/x"}),
        ("REST", "PostRequest", {"connectionName": nc, "url": "/x", "payload": {"a": 1}}),
        ("REST", "PutRequest", {"connectionName": nc, "url": "/x", "payload": None}),
        ("REST", "PatchRequest", {"connectionName": nc, "url": "/x", "payload": "s"}),
        ("REST", "DeleteRequest", {"connectionName": nc, "url": "/x"}),
        ("REST", "CallRequest", {"connectionName": nc, "url": "/x", "methodName": "GET", "payload": None}),
        ("REST", "GetRequest", {"connectionName": nc, "url": "/x", "timeout": "abc"}),
        ("REST", "GetRequest", {"url": "/x"}),
        ("Security", "IsBeingManagedByCode", {"managingClientCode": "SYSTEM", "clientCode": "FIN"}),
        ("Security", "IsBeingManagedById", {"managingClientId": 1, "clientId": 2}),
        ("Security", "GetClient", {"idOrCode": "SYSTEM"}),
        ("Security", "GetClient", {"idOrCode": 1}),
    ]
    sec = ["AddClientManager", "AssignProfile", "CreateUser", "DeleteClient", "DeleteUser", "GetAppProfiles",
           "GetClientUsersPage", "GetClientsByIds", "GetClientsDenorm", "GetManagedClientIds", "GetOwnersEmails", "GetUser",
           "GetUserAdminEmails", "GetUserSubOrg", "GetUsersByIds", "GetUsersForDistribution", "LogClientActivity",
           "MigrateClientManagers", "QueryClientActivities", "QueryUsers", "RemoveClientManager", "RemoveProfile",
           "ReplaceClientManager", "SetClientManagers", "SetClientStatus", "SetUserStatus", "UpdateClient", "UpdateUser"]
    sec_args = {"CreateUser": {"user": {}}, "UpdateUser": {"user": {}}, "UpdateClient": {"client": {}},
                "GetClientUsersPage": {"sort": None}, "GetOwnersEmails": {"clientCode": "SYSTEM", "appCode": "appbuilder"},
                "GetUserAdminEmails": {"clientCode": "SYSTEM", "appCode": "appbuilder"}, "LogClientActivity": {"activity": {}},
                "SetClientStatus": {"status": "ACTIVE"}, "SetUserStatus": {"status": "ACTIVE"}}
    cases += [("Security", n, sec_args.get(n, {})) for n in sec]
    for ns, name, args in cases:
        compare(f"step3 {ns}.{name} {json.dumps(args)[:60]}", "POST", ex + f"CoreServices.{ns}/{name}", HJ, args)
    # The same refusals anonymously and through GET.
    compare("step3 CreateEvent anonymous", "POST", ex + "CoreServices.Event/CreateEvent", headers(auth=None, json_body=True),
            {"eventName": "x"})
    compare("step3 ScheduleEvent GET", "GET", q(ex + "CoreServices.Event/ScheduleEvent", eventName="x", key="k"), headers())
    compare("step3 GetUser anonymous", "POST", ex + "CoreServices.Security/GetUser", headers(auth=None, json_body=True), {})


def step4_cases():
    """The run log routes (read only: a fixed window three hours back, so rows the running
    schedulers add do not move the pages) and the internal raise's refusals. A real raise
    (which would publish on the Java side) and cleanupOlderThan (which deletes) are not run."""
    base = "/api/core/eventRuns"
    H = headers(app="leadzumptwo")
    now = int(time.time())  # from / to are epoch SECONDS
    window = {"from": str(now - 3 * 3600), "to": str(now - 2 * 3600)}
    for params in [{}, {"size": "3"}, {"size": "3", "page": "1"}, {"eventName": "LZ_WA_OUTBOX", "size": "2"},
                   {"status": "FAILED", "size": "2"}, {"triggerType": "SCHEDULE", "size": "2"},
                   {"allClients": "true", "size": "2"}, {"timezone": "Asia/Kolkata", "size": "2"},
                   {"clientCode": "FIN", "size": "2"}, {"status": "NOPE"}, {"from": "abc"}]:
        compare(f"eventRuns {params}", "GET", q(base, appCode="leadzumptwo", **dict(window, **params)), H)
    # Epoch milliseconds by mistake: a date past year 9999, which MySQL refuses (ER13).
    compare("eventRuns from in milliseconds", "GET", q(base, appCode="leadzumptwo", **{"from": str(now * 1000)}), H,
            expected=ER13_mysql_error_text)
    compare("eventRuns without appCode", "GET", base, H)
    compare("eventRuns anonymous", "GET", q(base, appCode="leadzumptwo"), headers(app="leadzumptwo", auth=None))
    s, _, b = fetch(JAVA, "GET", q(base, appCode="leadzumptwo", size="1", **window), H)
    rows = (parse(b) or {}).get("content") if s == 200 else None
    if rows:
        compare("eventRuns by id", "GET", f"{base}/{rows[0]['id']}", H)
    compare("eventRuns by id missing", "GET", f"{base}/1", H)
    compare("eventRuns by id not a number", "GET", f"{base}/abc", H)
    raise_path = "/api/core/events/internal/raise"
    HJ = headers(json_body=True)
    for body in [{"eventName": "USER_CREATED", "appCode": "leadzumptwo", "clientCode": "FIN"},
                 {"eventName": "FILES_EXPIRED", "appCode": "", "clientCode": "FIN"},
                 {"eventName": "FILES_EXPIRED", "clientCode": "FIN"}, {}]:
        compare(f"events raise refused {body}", "POST", raise_path, HJ, body)
    compare("events raise without a body", "POST", raise_path, HJ)


def mongo_json(script):
    out = subprocess.run(["mongosh", "--quiet", "mongodb://localhost:27017/core", "--eval", script],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def stored_functions():
    """Published SYSTEM functions whose steps call only System functions and the core
    functions core-exec has."""
    script = """
    const ok = (ns, name) => ns.startsWith('System') || %s.includes(ns)
      || (ns === 'CoreServices.Storage' && %s.includes(name))
      || (ns === 'CoreServices.Security' && %s.includes(name))
      || (ns === 'CoreServices.File' && %s.includes(name));
    const out = [];
    db.function.find({clientCode: 'SYSTEM', published: {$ne: false}}).forEach(d => {
      const def = d.definition || {};
      const steps = Object.values(def.steps || {});
      if (!steps.every(s => ok(s.namespace || '', s.name))) return;
      if (steps.some(s => s.name === 'Wait')) return;
      out.push({app: d.appCode, name: d.name, auth: d.executeAuth || null, params: def.parameters || {},
                usesDate: steps.some(s => (s.namespace || '').startsWith('System.Date')),
                usesStorage: steps.some(s => s.namespace === 'CoreServices.Storage')});
    });
    print(EJSON.stringify(out));
    """ % (json.dumps(sorted(PURE_CORE)), json.dumps(list(STORAGE_READS)), json.dumps(list(SECURITY_READS)),
           json.dumps(list(FILE_READS)))
    return mongo_json(script)


def sample(schema, depth=0):
    if not isinstance(schema, dict) or depth > 3:
        return "abc"
    if "defaultValue" in schema:
        return schema["defaultValue"]
    if schema.get("enums"):
        return schema["enums"][0]
    t = schema.get("type")
    types = t if isinstance(t, list) else [t] if t else []
    types = [str(x).upper() for x in types]
    if "STRING" in types:
        return "abc"
    if "INTEGER" in types or "LONG" in types:
        return 3
    if "DOUBLE" in types or "FLOAT" in types:
        return 2.5
    if "BOOLEAN" in types:
        return True
    if "ARRAY" in types:
        items = schema.get("items")
        return [sample(items, depth + 1)] if isinstance(items, dict) else []
    if "OBJECT" in types:
        return {k: sample(v, depth + 1) for k, v in (schema.get("properties") or {}).items()}
    return None


def stored_cases():
    ex = "/api/core/function/execute/"
    funcs = stored_functions()
    print(f"# {len(funcs)} stored functions qualify")
    for f in funcs:
        app, full, params = f["app"], f["name"], f["params"]
        if isinstance(params, list):
            params = {(p or {}).get("parameterName", str(i)): p for i, p in enumerate(params)}
        ns, _, name = full.rpartition(".")
        args = {}
        query = {}
        for pname, p in params.items():
            v = sample((p or {}).get("schema") or {})
            if (p or {}).get("variableArgument"):
                v = [v]
            args[pname] = v
            if isinstance(v, (str, int, float)) and not isinstance(v, bool):
                query[pname] = str(v)
        hj = headers(app=app, json_body=True)
        rules = any_of(D30_feign_debug_message, D2_kirun_error_text, D7_definition_java_cannot_read)
        clock = bool(f.get("usesDate"))
        compare(f"stored POST {app} {full}", "POST", ex + f"{ns}/{name}", hj, args, expected=rules, clock=clock)
        compare(f"stored GET {app} {full}", "GET", q(ex + f"{ns}/{name}", **query), headers(app=app), expected=rules,
                clock=clock)


def any_of(*rules):
    def rule(js, jv, rs, rv):
        for r in rules:
            if r(js, jv, rs, rv):
                rule.__name__ = r.__name__
                return True
        return False
    rule.__name__ = "+".join(r.__name__ for r in rules)
    return rule


def repository_cases():
    H = headers()
    base = "/api/core/"
    for app, client, ns, name in [("appbuilder", "SYSTEM", "Test", "fibonacci"), ("appbuilder", "SYSTEM", "MyApp", "greet"),
                                  ("appbuilder", "SYSTEM", "CoreServices.Hash", "HashData"),
                                  ("appbuilder", "SYSTEM", "CoreServices.Crypto", "Signer"),
                                  ("appbuilder", "SYSTEM", "CoreServices.SecurityContext", "GetAuthentication"),
                                  ("appbuilder", "SYSTEM", "Nope", "Nope"),
                                  ("leadzumptwo", "SYSTEM", "LeadZumpV2", "lzCondValue"),
                                  ("kirunlive", "SYSTEM", "kirunlive", "dateRanges"),
                                  ("leadzump", "SYSTEM", "EntityProcessor.Campaign", "Create"),
                                  ("leadzump", "SYSTEM", "MarketingAI", "verifyLeadgen")]:
        compare(f"functions find {app} {ns}.{name}", "GET",
                q(base + "functions/repositoryFind", appCode=app, clientCode=client, namespace=ns, name=name), H,
                expected=D7_definition_java_cannot_read)
    # Every core function Java registers: core-exec must have it, with the same signature.
    _, _, body = fetch(JAVA, "GET", q(base + "functions/repositoryFilter", appCode="appbuilder", clientCode="SYSTEM",
                                      filter="CoreServices."), H)
    names = sorted(json.loads(body))
    print(f"# {len(names)} CoreServices functions in Java's repository")
    for full in names:
        ns, _, name = full.rpartition(".")
        compare(f"functions find {full}", "GET",
                q(base + "functions/repositoryFind", appCode="appbuilder", clientCode="SYSTEM", namespace=ns, name=name), H)
    compare("functions filter 'CoreServices.'", "GET", q(base + "functions/repositoryFilter", appCode="appbuilder",
            clientCode="SYSTEM", filter="CoreServices."), H, kind="list")
    compare("functions find KIRun included", "GET", q(base + "functions/repositoryFind", appCode="appbuilder",
            clientCode="SYSTEM", namespace="System.Math", name="Add", includeKIRunRepos="true"), H,
            expected=D4_kirun_builtins)
    compare("functions find KIRun not included", "GET", q(base + "functions/repositoryFind", appCode="appbuilder",
            clientCode="SYSTEM", namespace="System.Math", name="Add"), H)
    compare("functions find codes from caller", "GET", q(base + "functions/repositoryFind", namespace="Test", name="fibonacci"), H)
    for app, flt in [("appbuilder", ""), ("appbuilder", "hash"), ("appbuilder", "Test"), ("leadzump", "lead"),
                     ("leadzumptwo", "wz"), ("loopzump", "")]:
        compare(f"functions filter {app} '{flt}'", "GET",
                q(base + "functions/repositoryFilter", appCode=app, clientCode="SYSTEM", filter=flt), H,
                kind="list")
    compare("functions filter KIRun included", "GET", q(base + "functions/repositoryFilter", appCode="appbuilder",
            clientCode="SYSTEM", filter="math", includeKIRunRepos="true"), H, kind="list", expected=D4_kirun_builtins)
    for app, ns, name in [("appbuilder", "Test", "UserRecord"), ("appbuilder", "Security.Context", "ContextAuthentication"),
                          ("appbuilder", "Security.Context", "ContextUser"), ("markauto", "Model", "Conditions"),
                          ("markauto", "Model", "FilterCondition"), ("markauto", "EnumModel", "UserTypes"),
                          ("appbuilder", "Nope", "Nope"), ("leadzump", "EntityProcessor.DTO", "Owner"),
                          ("docs", "docs", "MenuItem"), ("docs", "docs", "Details")]:
        compare(f"schemas find {app} {ns}.{name}", "GET",
                q(base + "schemas/repositoryFind", appCode=app, clientCode="SYSTEM", namespace=ns, name=name), H,
                expected=D5_java_jackson_jsonprimitive)
    for ns, name in [("System", "any"), ("System.Date", "Timestamp"), ("System", "Schema")]:
        compare(f"schemas find KIRun {ns}.{name}", "GET", q(base + "schemas/repositoryFind", appCode="appbuilder",
                clientCode="SYSTEM", namespace=ns, name=name, includeKIRunRepos="true"), H,
                expected=D5_java_jackson_jsonprimitive)
    compare("schemas filter KIRun included", "GET", q(base + "schemas/repositoryFilter", appCode="appbuilder",
            clientCode="SYSTEM", filter="a", includeKIRunRepos="true"), H, kind="list")
    compare("functions filter anonymous, codes from caller", "GET", q(base + "functions/repositoryFilter", filter="Test"),
            headers(auth=None), kind="list")
    for app, flt in [("appbuilder", None), ("appbuilder", "user"), ("markauto", "Enum"), ("leadzump", "DTO"), ("docs", "")]:
        params = {"appCode": app, "clientCode": "SYSTEM"}
        if flt is not None:
            params["filter"] = flt
        compare(f"schemas filter {app} {flt!r}", "GET", q(base + "schemas/repositoryFilter", **params), H, kind="list")


def main():
    system_cases()
    core_cases()
    error_cases()
    repository_cases()
    step3_cases()
    step4_cases()
    stored_cases()
    counts = {}
    for _, v, _ in RESULTS:
        key = v.split(" ")[0]
        counts[key] = counts.get(key, 0) + 1
    tags = {}
    for _, v, _ in RESULTS:
        if v.startswith("EXPECTED"):
            tags[v[9:]] = tags.get(v[9:], 0) + 1
    print(f"\n{len(RESULTS)} cases: " + ", ".join(f"{k} {n}" for k, n in sorted(counts.items())))
    if tags:
        print("EXPECTED by tag: " + ", ".join(f"{k} {n}" for k, n in sorted(tags.items())))
    sys.exit(1 if counts.get("DIFF") else 0)


if __name__ == "__main__":
    main()
