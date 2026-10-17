#!/usr/bin/env python3
"""Writes the error message review sheet from the catalogues.

Usage: error_catalogue.py [output] [--approve-all]
       default output: ~/.claude/plans/rust-migration-2026-10-12/ERROR_CATALOGUE.md
       --approve-all records every row as it reads now as reviewed today (after Kiran marks all OK)

One row per code (COMMON, SEC, GW...): when it happens, today's Java text, the new text, the
action, who sees it. Then the permission labels (authority -> plain words) and the entity labels.
The catalogues (`crates/*/messages/en.toml`) are the source; edit them, then run this again.

The Review column shows what Kiran approved (`tools/error_messages_approved.json`: per code the
date and a digest of the text and action as approved): "OK <date>" while the wording is the
approved one, "changed since OK <date>" once it differs, empty for a row not reviewed yet.
"""
import datetime
import hashlib
import json
import os
import sys

import error_parity

DEFAULT_OUT = os.path.expanduser("~/.claude/plans/rust-migration-2026-10-12/ERROR_CATALOGUE.md")
APPROVED = os.path.join(os.path.dirname(os.path.abspath(__file__)), "error_messages_approved.json")


def load_approved():
    if not os.path.exists(APPROVED):
        return {}
    with open(APPROVED) as f:
        return json.load(f)


def digest(entry):
    words = json.dumps([entry.get("text"), entry.get("action")], ensure_ascii=False)
    return hashlib.sha1(words.encode()).hexdigest()[:12]


def review(code, approved):
    a = approved.get(code)
    if not a:
        return ""
    if a["digest"] == digest(error_parity.CATALOGUE[code]):
        return f"OK {a['date']}"
    return f"changed since OK {a['date']}"

NAMESPACES = [
    ("COMMON", "Shared by every unit (platform)", "crates/platform/messages/en.toml"),
    ("SEC", "Security (security-auth, security-internal, security-admin)", "crates/security/messages/en.toml"),
    ("GW", "Gateway (gateway-rust)", "crates/gateway/messages/en.toml"),
    ("CORE", "Core (core-exec, core-editor, core-events, core-scheduler; storage, connections)", "crates/core/messages/en.toml"),
    ("DEF", "Definitions (pages, functions, schemas... in ui and core: the overridable library)", "crates/overridable/messages/en.toml"),
    ("UI", "UI (ui-engine, ui-shell, ui-editor)", "crates/ui/messages/en.toml"),
    ("FILES", "Files (files-serve, files-manage)", "crates/files/messages/en.toml"),
    ("MULTI", "Multi (app transport and templates)", "crates/multi/messages/en.toml"),
    ("NOTIF", "Notification", "crates/notification/messages/en.toml"),
]


def cell(v):
    if v is None or v == "":
        return ""
    if isinstance(v, list):
        v = " / ".join(str(x) for x in v)
    return str(v).replace("|", "\\|").replace("\n", " ")


def java_texts(code, entry):
    ns = code.split(".")[0]
    bundle = error_parity.BUNDLE.get(ns, {})
    out = []
    for key in error_parity.as_list(entry.get("java")):
        if key in bundle:
            out.append(f"`{key}`: {bundle[key]}")
        else:
            out.append(f"`{key}` (not in the bundle): {error_parity.UNKNOWN}")
    for t in error_parity.as_list(entry.get("java_text")):
        out.append("(empty body)" if t == "" else t)
    return "<br>".join(cell(x) for x in out)


# Sample values for the examples the sheet shows under each template.
SAMPLES = {
    "app": "LeadZump", "client": "Fincity", "permission": "the Edit pages permission", "what": "client address",
    "id": "7", "field": "email", "expected": "a whole number", "user": "asha@example.com", "identity": "email",
    "method": "PUT", "minutes": "15", "left": "2", "reason": "password", "min": "8", "max": "64", "length": "4",
    "name": "Sales", "role": "Viewer", "other": "Editor", "host": "crm.example.com", "subdomain": "acme",
    "suffix": ".example.org", "domains": "a.example.com", "detail": "DNS record not found", "params": "tokens",
    "target": "billing", "errorId": "2026-10-17-1f2e3d", "again": "code", "profile": "Sales Lead", "package": "Basic",
    "value": "abc", "type": "a number",
    "service": "core", "header": "X-Forwarded-Port", "status": "404",
}


def render(template, values):
    """The template grammar of platform::messages::template, for the examples."""
    if template is None:
        return ""

    def parse(i, depth, pipe_ends):
        nodes, text = [], []
        while i < len(template):
            c = template[i]
            i += 1
            if c == "\\" and i < len(template):
                text.append(template[i])
                i += 1
            elif c == "{":
                j = template.index("}", i)
                name, _, default = template[i:j].partition("|")
                nodes += ["".join(text), ("var", name.strip(), default if "|" in template[i:j] else None)]
                text, i = [], j + 1
            elif c == "[":
                nodes.append("".join(text))
                text = []
                body, i, end = parse(i, depth + 1, True)
                other = []
                if end == "|":
                    other, i, _ = parse(i, depth + 1, False)
                nodes.append(("opt", body, other))
            elif c == "]" and depth:
                nodes.append("".join(text))
                return nodes, i, "]"
            elif c == "|" and pipe_ends:
                nodes.append("".join(text))
                return nodes, i, "|"
            else:
                text.append(c)
        nodes.append("".join(text))
        return nodes, i, None

    def out(nodes):
        r = []
        for n in nodes:
            if isinstance(n, str):
                r.append(n)
            elif n[0] == "var":
                v = values.get(n[1])
                r.append(v if v else (n[2] or ""))
            else:
                complete = all(values.get(x[1]) for x in n[1] if isinstance(x, tuple) and x[0] == "var")
                r.append(out(n[1] if complete else n[2]))
        return "".join(r)

    return " ".join(out(parse(0, 0, False)[0]).split())


def examples(e):
    if not e.get("params") and "{" not in (e.get("text") or "") + (e.get("action") or ""):
        return ""
    names = [p.split(":")[0] for p in e.get("params", [])]
    full = {n: SAMPLES.get(n, n) for n in names}
    full["errorId"] = SAMPLES["errorId"]
    bare = {"errorId": SAMPLES["errorId"]}
    a = render(e.get("text"), full)
    b = render(e.get("text"), bare)
    return f"<br>*Reads:* {cell(a)}" + (f"<br>*Without values:* {cell(b)}" if b != a else "")


def mirror_of(code):
    """The DEF code a code only repeats: not raised by the Rust units, for the same Java keys, in
    the same words (the keys ui and core share answer with DEF.*). Such rows are left off the
    sheet (Kiran, 2026-10-17: fewer rows)."""
    e = error_parity.CATALOGUE[code]
    # The sections Kiran approved as a whole (2026-10-17) stay as he read them.
    if code.split(".")[0] in ("DEF", "COMMON", "SEC", "GW") or not str(e.get("when", "")).startswith("Not raised by the Rust units"):
        return None
    keys = set(error_parity.as_list(e.get("java")))
    for other, d in error_parity.CATALOGUE.items():
        if other.startswith("DEF.") and keys and keys <= set(error_parity.as_list(d.get("java"))) \
                and (d.get("text"), d.get("action")) == (e.get("text"), e.get("action")):
            return other
    return None


def code_rows(ns, approved):
    rows = []
    for code in sorted(c for c in error_parity.CATALOGUE if c.startswith(ns + ".")):
        if mirror_of(code):
            continue
        e = error_parity.CATALOGUE[code]
        rows.append(
            f"| `{code}` | {e.get('status', '')} | {cell(e.get('when'))} | {java_texts(code, e)} | {cell(e.get('text'))}{examples(e)} "
            f"| {cell(e.get('action'))} | {cell(e.get('audience'))} | {review(code, approved)} |"
        )
    return rows


def label_rows(prefix, approved):
    rows = []
    for code in sorted(c for c in error_parity.CATALOGUE if c.startswith(prefix + ".")):
        name = code[len(prefix) + 1:]
        rows.append(f"| `{name}` | {cell(error_parity.CATALOGUE[code].get('text'))} | {review(code, approved)} |")
    return rows


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    out = args[0] if args else DEFAULT_OUT
    approved = load_approved()
    if "--approve-all" in sys.argv:
        today = datetime.date.today().isoformat()
        for code, e in error_parity.CATALOGUE.items():
            if review(code, approved) != f"OK {approved.get(code, {}).get('date')}":
                approved[code] = {"date": today, "digest": digest(e)}
        with open(APPROVED, "w") as f:
            json.dump(dict(sorted(approved.items())), f, indent=1)
            f.write("\n")
    counts = {ns: sum(1 for c in error_parity.CATALOGUE if c.startswith(ns + ".")) for ns, _, _ in NAMESPACES}
    counts = {ns: n for ns, n in counts.items() if n}
    mirrors = {ns: sum(1 for c in error_parity.CATALOGUE if c.startswith(ns + ".") and mirror_of(c)) for ns in counts}
    lines = [
        "# Error messages: review sheet",
        "",
        f"Generated by `tools/error_catalogue.py` on {datetime.date.today().isoformat()} from the catalogues; do not edit",
        "this file, edit the catalogue named in each section and run the tool again. Codes: "
        + ", ".join(f"{ns} {n}" for ns, n in counts.items()) + ".",
        "",
        "How to review: mark a row OK in the last column, or write the wording you want there.",
        "Placeholders: `{app}` a value, `{app|this app}` a value or the default, `[ ... ]` shown only",
        "when its values are known, `[ ... | otherwise ]` the alternative, `{errorId}` the error id.",
        "`message` carries the text, `action` the next step, `debugMessage` Java's text (for support).",
        "Codes marked \"Not raised by the Rust units\" map Java bundle keys no Rust path raises.",
        "",
    ]
    for ns, title, src in NAMESPACES:
        if ns not in counts:
            continue
        lines += [
            f"## {title} (`{ns}.*`, {counts[ns]} codes)",
            "",
            f"Source: `{src}`."
            + (f" Not listed: {mirrors[ns]} codes that only repeat a DEF code's words for the same Java key"
               " and are not raised." if mirrors.get(ns) else ""),
            "",
            "| Code | Status | When it happens | Java today | New text | Action | Who sees it | Review |",
            "|---|---|---|---|---|---|---|---|",
        ]
        lines += code_rows(ns, approved)
        lines.append("")
    lines += [
        "## Permission labels (`PERMISSION.*`)",
        "",
        "How an authority reads in a message: `Authorities.Page_UPDATE` is \"Edit pages\", and inside a",
        "sentence \"the Edit pages permission\" (`_ONE`); roles read \"the Owner role\" (`_ROLE`), profiles",
        "\"the X profile\" (`_PROFILE`). An authority without a row reads by pattern: `_READ` \"View {name}\",",
        "`_CREATE`, `_UPDATE`, `_DELETE`. An app-scoped authority (`Authorities.CRM.Lead_READ`) uses",
        "`CRM.Lead_READ`, then `Lead_READ`. Source: `crates/platform/messages/en.toml`.",
        "",
        "| Authority (after `Authorities.`) | Label | Review |",
        "|---|---|---|",
    ]
    lines += label_rows("PERMISSION", approved)
    lines += [
        "",
        "## Entity labels (`ENTITY.*`)",
        "",
        "Java class names as words in messages (`ClientUrl` reads \"client address\"); a class without",
        "a row reads as its words (`ClientPasswordPolicy`: \"client password policy\").",
        "",
        "| Class | Label | Review |",
        "|---|---|---|",
    ]
    lines += label_rows("ENTITY", approved)
    lines.append("")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write("\n".join(lines))
    pending = sum(1 for c in error_parity.CATALOGUE if not review(c, approved).startswith("OK") and not mirror_of(c))
    print(f"wrote {out}: " + ", ".join(f"{ns} {n}" for ns, n in counts.items()) + f"; {pending} rows to review")


if __name__ == "__main__":
    main()
