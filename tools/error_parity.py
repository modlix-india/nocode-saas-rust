"""Comparing error answers by status and code, for the parity scripts.

The Rust units answer errors with the coded body (crates/platform/src/error.rs): `code`,
`message` in plain words, `action`, `params`, `locale`, and Java's own text in `debugMessage`.
Java answers with its bundle text (or an empty 401, or a `text/plain` "Access Denied"). The new
texts are expected to differ; what must hold is that the code stands for what Java said.

`decode(java, rust)` checks exactly that, from the catalogues (`crates/*/messages/en.toml`: each
code's `java` bundle keys and `java_text` templates) and the Java bundles the Rust crates carry.
When the code fits, Rust's answer is rewritten into Java's shape (Java's message, Java's empty or
plain-text body and content type) so the script's own comparison then checks everything else
(status, headers, `debugMessage`, the rest of the body) exactly as before. The script reports a
case that then compares equal as EXPECTED ("new text, by code"). When the code does not fit,
the answer is left alone and the note says why, so the case is a DIFF.

Responses are `(status, headers, body)` with headers either a dict (lower-case names) or the
content type alone.
"""
import json
import os
import re
import tomllib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CATALOGUES = [
    "crates/platform/messages/en.toml",
    "crates/security/messages/en.toml",
    "crates/gateway/messages/en.toml",
    # Phase 2 (each read once it exists): CORE core, appdata and connections; DEF the definition
    # library both ui and core use (overridable); UI; FILES; MULTI; NOTIF notification.
    "crates/core/messages/en.toml",
    "crates/overridable/messages/en.toml",
    "crates/ui/messages/en.toml",
    "crates/files/messages/en.toml",
    "crates/multi/messages/en.toml",
    "crates/notification/messages/en.toml",
]

# The Java bundles each namespace's `java` keys refer to, first match wins: the copy a Rust crate
# carries (`"key" => r#"text"#,` lines) or Java's own `messages_en.properties`.
JAVA = "../nocode-saas"
BUNDLES = {
    "SEC": ["crates/security/src/messages.rs"],
    "CORE": [f"{JAVA}/core/src/main/resources/messages_en.properties"],
    "DEF": [f"{JAVA}/core/src/main/resources/messages_en.properties", f"{JAVA}/ui/src/main/resources/messages_en.properties"],
    "UI": [f"{JAVA}/ui/src/main/resources/messages_en.properties"],
    "FILES": [f"{JAVA}/files/src/main/resources/messages_en.properties"],
    "MULTI": [f"{JAVA}/multi/src/main/resources/messages_en.properties"],
    "NOTIF": [f"{JAVA}/notification/src/main/resources/messages_en.properties"],
}

EXPECTED_NOTE = "new error text, compared by code (crates/security/DIFFERENCES.md, Error bodies)"


def _walk(prefix, table, out):
    for k, v in table.items():
        code = f"{prefix}.{k}" if prefix else k
        if not isinstance(v, dict):
            continue
        if "text" in v or "action" in v:
            out[code] = v
        else:
            _walk(code, v, out)


def load_catalogue():
    out = {}
    for rel in CATALOGUES:
        path = os.path.join(ROOT, rel)
        if os.path.exists(path):
            with open(path, "rb") as f:
                _walk("", tomllib.load(f), out)
    return out


def load_bundle(rel):
    path = os.path.normpath(os.path.join(ROOT, rel))
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if rel.endswith(".properties"):
        return load_properties(text)
    return dict(re.findall(r'^\s+"([a-z_]+)" => r#"(.*?)"#,', text, re.M))


def load_properties(text):
    """`key=value` lines of a Java bundle (`#` / `!` comments, `\\` line continuations). As
    `java.util.Properties` reads them, a value keeps its trailing spaces (ui's
    `forbidden_permission` ends in one, and so does the message Java sends)."""
    out = {}
    lines = iter(text.splitlines())
    for line in lines:
        line = line.lstrip()
        if not line.strip() or line[0] in "#!":
            continue
        while line.endswith("\\"):
            line = line[:-1] + next(lines, "").lstrip()
        m = re.match(r"([^=:\s]+)\s*[=:]\s*(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).encode("latin-1", "backslashreplace").decode("unicode_escape") if "\\u" in m.group(2) else m.group(2)
    return out


def load_bundles(rels):
    out = {}
    for rel in reversed(rels):
        out.update(load_bundle(rel))
    return out


CATALOGUE = load_catalogue()
BUNDLE = {ns: load_bundles(rels) for ns, rels in BUNDLES.items()}
UNKNOWN = "Internal Server Error (Unknown)"


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def java_templates(code):
    """What Java says where Rust answers `code`: its bundle keys' templates and literal texts."""
    entry = CATALOGUE.get(code, {})
    ns = code.split(".")[0]
    bundle = BUNDLE.get(ns, {})
    out = [bundle.get(k, UNKNOWN) for k in as_list(entry.get("java"))]
    out += as_list(entry.get("java_text"))
    return out


def template_matches(template, text):
    pattern = "".join("(.*)" if c == "$" else re.escape(c) for c in template)
    return re.fullmatch(pattern, text, re.S) is not None


def _json(raw):
    try:
        return json.loads(raw) if raw else None
    except (ValueError, TypeError):
        return None


def _ctype(headers):
    if isinstance(headers, dict):
        return headers.get("content-type")
    return headers


def _with_ctype(headers, ctype):
    if isinstance(headers, dict):
        h = dict(headers)
        if ctype is None:
            h.pop("content-type", None)
        else:
            h["content-type"] = ctype
        h.pop("content-length", None)
        return h
    return ctype


def java_side(headers, body):
    """Java's message, its debugMessage, and the kind of body it sent (json, text, empty)."""
    if not body:
        return "", None, "empty"
    v = _json(body)
    if isinstance(v, dict):
        return v.get("message") or "", v.get("debugMessage"), "json"
    return body.decode(errors="replace"), None, "text"


def shape_problems(v):
    problems = []
    msg = v.get("message")
    if not isinstance(msg, str) or not msg.strip():
        problems.append("empty message")
    elif "{" in msg or "}" in msg:
        problems.append(f"unfilled placeholder in {msg!r}")
    if v.get("stackTrace") != "":
        problems.append("stackTrace is not empty")
    if not isinstance(v.get("locale"), str):
        problems.append("no locale")
    if not isinstance(v.get("params"), dict):
        problems.append("no params")
    if "action" in v and not (isinstance(v["action"], str) and v["action"].strip()):
        problems.append("empty action")
    return problems


def rust_debug_as_java(debug):
    """`[key] text` is Java's text under its key."""
    if isinstance(debug, str) and debug.startswith("["):
        end = debug.find("] ")
        if end > 0:
            return debug[end + 2:]
    return debug


def decode(java, rust):
    """(rust rewritten into Java's shape, note). The note is None for an answer that is not a
    coded error, "coded CODE" when the code stands for Java's text, and names the problem
    otherwise (see `is_problem`)."""
    _, jh, jb = java
    rs, rh, rb = rust
    rv = _json(rb)
    if not (isinstance(rv, dict) and isinstance(rv.get("code"), str) and "exceptionId" in rv):
        return rust, None
    code = rv["code"]
    jtext, _, jkind = java_side(jh, jb)
    problems = shape_problems(rv)
    if code not in CATALOGUE:
        problems.append("the code is not in any catalogue")
    elif not any(template_matches(t, jtext) for t in java_templates(code)):
        problems.append(f"it does not stand for Java's {jtext[:120]!r}")
    if problems:
        return rust, f"coded {code}: " + "; ".join(problems)
    if jkind == "empty":
        return (rs, _with_ctype(rh, _ctype(jh)), b""), f"coded {code}"
    if jkind == "text":
        return (rs, _with_ctype(rh, _ctype(jh)), jb), f"coded {code}"
    out = {
        "exceptionId": rv["exceptionId"],
        "message": jtext,
        "stackTrace": rv.get("stackTrace", ""),
        "debugMessage": rust_debug_as_java(rv.get("debugMessage")),
    }
    jv = _json(jb)
    ordered = {k: out[k] for k in jv if k in out} if isinstance(jv, dict) else out
    for k, v in out.items():
        ordered.setdefault(k, v)
    return (rs, _with_ctype(rh, _ctype(jh)), json.dumps(ordered, separators=(",", ":")).encode()), f"coded {code}"


def is_problem(note):
    return bool(note) and ":" in note


def verdict(verdict_without_codes, note):
    """The script's verdict once the coded check is known: a coded answer that otherwise
    matches is EXPECTED; a code that does not fit is a DIFF."""
    if is_problem(note):
        return "DIFF"
    if note and verdict_without_codes == "SAME":
        return "EXPECTED"
    return verdict_without_codes


def detail(note, detail_without_codes=""):
    if is_problem(note):
        return "; ".join(x for x in [note, detail_without_codes] if x)
    if note and not detail_without_codes:
        return f"{EXPECTED_NOTE}: {note[len('coded '):]}"
    if note:
        return f"{detail_without_codes} [{note}]"
    return detail_without_codes


if __name__ == "__main__":
    # A self-check of the rules on fixed answers.
    sec = '{"exceptionId":"x","message":"Permission/Role User READ is required to use this operation","stackTrace":"","debugMessage":"Permission/Role User READ is required to use this operation"}'
    rust = json.dumps({"exceptionId": "y", "message": "You can't do this.", "stackTrace": "", "debugMessage":
                       "[forbidden_permission] Permission/Role User READ is required to use this operation",
                       "code": "SEC.FORBIDDEN_PERMISSION", "params": {}, "locale": "en"}).encode()
    r, note = decode((403, {"content-type": "application/json"}, sec.encode()), (403, {"content-type": "application/json"}, rust))
    assert note == "coded SEC.FORBIDDEN_PERMISSION", note
    assert json.loads(r[2])["message"] == json.loads(sec)["message"]
    assert json.loads(r[2])["debugMessage"] == json.loads(sec)["debugMessage"]
    r, note = decode((401, {}, b""), (401, {"content-type": "application/json"}, json.dumps(
        {"exceptionId": "y", "message": "Please sign in to continue.", "stackTrace": "", "debugMessage": "x",
         "code": "COMMON.SIGN_IN_REQUIRED", "params": {}, "locale": "en"}).encode()))
    assert (r[2], r[1], note) == (b"", {}, "coded COMMON.SIGN_IN_REQUIRED"), (r, note)
    r, note = decode((403, "text/plain", b"Access Denied"), (403, "application/json", json.dumps(
        {"exceptionId": "y", "message": "No.", "stackTrace": "", "debugMessage": "x",
         "code": "COMMON.PERMISSION_REQUIRED", "params": {}, "locale": "en"}).encode()))
    assert (r[1], r[2]) == ("text/plain", b"Access Denied"), r
    _, note = decode((404, {}, b'{"message":"Client with id 5 not found"}'), (404, {}, json.dumps(
        {"exceptionId": "y", "message": "No.", "stackTrace": "", "debugMessage": "x",
         "code": "SEC.USER_CREDENTIALS_MISMATCHED", "params": {}, "locale": "en"}).encode()))
    assert is_problem(note) and verdict("SAME", note) == "DIFF", note
    assert verdict("SAME", "coded X") == "EXPECTED" and verdict("SAME", None) == "SAME"
    assert template_matches("Please try again. A server error - $", "Please try again. A server error - 2026-10-17-ab")
    assert java_templates("SEC.REQUEST_EXISITING")[0] == "Certificate request is in progress and cannot create a new one"
    assert load_properties("a=x \n  b = y\\\n   z\n# c=no\n") == {"a": "x ", "b": "yz"}
    assert UNKNOWN in java_templates("SEC.SOCIAL_LOGIN_FAILED")
    print(f"ok: {len(CATALOGUE)} codes, {sum(len(b) for b in BUNDLE.values())} Java keys")
