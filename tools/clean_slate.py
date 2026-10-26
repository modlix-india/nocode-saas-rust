#!/usr/bin/env python3
"""Clean slate: wipe dead test clients and empty apps through multi's purge routes.

Three steps, each its own command, so nothing deletes before its backup exists:

  plan    Reads the survey lists (<env>-clients.tsv, <env>-apps.tsv from the clean-slate report),
          re-checks every candidate against the live databases (read only) and writes the ordered
          plan: apps first, then clients, deepest in the client hierarchy first. A client that
          signed in within 90 days or is under 30 days old, or an app whose definitions changed
          within 30 days, drops out.
  backup  Dumps everything the plan removes: the whole security schema, the core rows keyed by
          the plan's client codes, every tenant MySQL schema and Mongo database the plan drops,
          and the ui/core definitions of the plan's clients and apps.
  purge   DELETE /api/multi/purge/{application|client}/{code}, a dry run unless --go. One JSON
          line per call goes to <plan dir>/purge-<env>-<time>.jsonl. --go refuses to start without
          a backup of the same plan.

Databases are reached with the environment variables MYSQL_HOST, MYSQL_USER, MYSQL_PWD and
MONGO_URI (read only in plan; dumps in backup). The API token comes from MODLIX_PURGE_TOKEN, or
on local from tools/platform_common.py's sign-in. Nothing secret is printed.

  clean_slate.py plan   --env dev --report ~/.claude/plans/clean-slate-2026-10-26 --out DIR
  clean_slate.py backup --env dev --plan DIR/plan-dev.json
  clean_slate.py purge  --env dev --plan DIR/plan-dev.json --base-url https://appbuilder.dev.modlix.com [--go]
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import datetime as dt
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import platform_common as pc  # noqa: E402

CLIENT_TIERS = ("A-empty",)
APP_TIERS = ("A-empty", "B-barely")
# Never purged, whatever a list says.
PROTECTED_CLIENTS = {"SYSTEM", "FIN", "FIN2"}
SYSTEM_DBS = {"admin", "config", "local", "ui", "core", "test", "information_schema", "mysql", "performance_schema", "sys"}


def die(msg: str) -> None:
    print(f"clean_slate: {msg}", file=sys.stderr)
    sys.exit(1)


def say(msg: str) -> None:
    print(msg, flush=True)


# ---------------------------------------------------------------- databases (read only here)

def db_env() -> dict[str, str]:
    need = ["MYSQL_HOST", "MYSQL_USER", "MYSQL_PWD", "MONGO_URI"]
    missing = [k for k in need if not os.environ.get(k)]
    if missing:
        die(f"set {', '.join(missing)} (see the module doc)")
    return {k: os.environ[k] for k in need}


def mysql(sql: str) -> list[list[str]]:
    e = db_env()
    out = subprocess.run(["mysql", "-h", e["MYSQL_HOST"], "-u", e["MYSQL_USER"], "--batch", "--skip-column-names", "-e", sql],
                         capture_output=True, text=True, env={**os.environ, "MYSQL_PWD": e["MYSQL_PWD"]})
    if out.returncode != 0:
        die(f"mysql: {out.stderr.strip().splitlines()[-1] if out.stderr.strip() else out.returncode}")
    return [line.split("\t") for line in out.stdout.splitlines() if line]


def mongo_eval(js: str) -> str:
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(js)
        path = f.name
    try:
        out = subprocess.run(["mongosh", db_env()["MONGO_URI"], "--quiet", "--file", path], capture_output=True, text=True)
    finally:
        os.unlink(path)
    if out.returncode != 0:
        die(f"mongosh: {out.stderr.strip()[-300:]}")
    return out.stdout


def code_ok(code: str) -> bool:
    """Letters, digits and `_`: the only codes that go into SQL and URLs here."""
    return bool(code) and code.replace("_", "").isalnum() and code.isascii()


def quoted(values: list[str]) -> str:
    for v in values:
        if not code_ok(v):
            die(f"refusing an odd code in SQL: {v!r}")
    return ",".join(f"'{v}'" for v in values)


def split_tenant(name: str) -> tuple[str, str] | None:
    """`<CLIENT>_<app>[_draft]` -> (client, app incl. any _draft); None for anything else."""
    if name in SYSTEM_DBS or "_" not in name:
        return None
    c, _, a = name.partition("_")
    return (c, a) if c and a else None


def tenant_names() -> tuple[list[str], list[str]]:
    my = [r[0] for r in mysql("SELECT SCHEMA_NAME FROM information_schema.SCHEMATA")]
    mg = mongo_eval("print(db.adminCommand({listDatabases:1,nameOnly:true}).databases.map(d=>d.name).join('\\n'))").split()
    return [n for n in my if split_tenant(n)], [n for n in mg if split_tenant(n)]


# ---------------------------------------------------------------- plan

def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open() as f:
        return list(csv.DictReader(f, delimiter="\t", quoting=csv.QUOTE_NONE))


def cmd_plan(a: argparse.Namespace) -> None:
    report = Path(a.report).expanduser()
    clients = [r for r in read_tsv(report / f"{a.env}-clients.tsv") if r["tier"] in CLIENT_TIERS and r["code"] not in PROTECTED_CLIENTS]
    apps = [r for r in read_tsv(report / f"{a.env}-apps.tsv") if r["tier"] in APP_TIERS]
    # A row without a usable code (empty, or `M,` on dev) cannot be named in three URLs; it is
    # left for a person to look at.
    blank = [c["id"] for c in clients if not code_ok(c["code"])] + [p["app"] for p in apps if not code_ok(p["app"])]
    clients = [c for c in clients if code_ok(c["code"])]
    apps = [p for p in apps if code_ok(p["app"])]
    say(f"{a.env}: survey lists {len(clients)} clients, {len(apps)} apps")

    # Clients: still there, still idle, still old enough; with their depth in the hierarchy. The
    # recently active clients come from one pass over the last 90 days (CREATED_AT is indexed).
    active = {r[0] for r in mysql(
        "SELECT DISTINCT u.CLIENT_ID FROM security.security_sox_log s JOIN security.security_user u ON u.ID = s.OBJECT_ID "
        "WHERE s.CREATED_AT > NOW() - INTERVAL 90 DAY AND s.OBJECT_NAME = 'USER' AND s.ACTION_NAME = 'LOGIN' "
        "UNION SELECT DISTINCT u.CLIENT_ID FROM security.security_user_token t JOIN security.security_user u ON u.ID = t.USER_ID "
        "WHERE GREATEST(t.CREATED_AT, COALESCE(t.LAST_USED_AT, t.CREATED_AT)) > NOW() - INTERVAL 90 DAY")}
    codes = [c["code"] for c in clients if code_ok(c["code"])]
    live = {}
    for i in range(0, len(codes), 500):
        part = codes[i:i + 500]
        rows = mysql(
            "SELECT c.CODE, c.ID, c.CREATED_AT > NOW() - INTERVAL 30 DAY, "
            "(h.MANAGE_CLIENT_LEVEL_0 IS NOT NULL) + (h.MANAGE_CLIENT_LEVEL_1 IS NOT NULL) + (h.MANAGE_CLIENT_LEVEL_2 IS NOT NULL) + (h.MANAGE_CLIENT_LEVEL_3 IS NOT NULL) "
            f"FROM security.security_client c LEFT JOIN security.security_client_hierarchy h ON h.CLIENT_ID = c.ID WHERE c.CODE IN ({quoted(part)})")
        for code, cid, new, depth in rows:
            live[code] = dict(id=int(cid), new=new == "1", active=cid in active, depth=int(depth))
    keep_c = []
    plan_c = []
    for c in clients:
        x = live.get(c["code"])
        if x is None:
            keep_c.append((c["code"], "gone already"))
        elif x["new"]:
            keep_c.append((c["code"], "created within 30 days"))
        elif x["active"]:
            keep_c.append((c["code"], "signed in within 90 days"))
        else:
            plan_c.append(dict(code=c["code"], id=x["id"], depth=x["depth"]))
    plan_c.sort(key=lambda c: (-c["depth"], c["code"]))

    # Apps: still there, untouched in ui/core for 30 days.
    app_codes = [p["app"] for p in apps]
    in_security = {r[0] for r in mysql(f"SELECT APP_CODE FROM security.security_app WHERE APP_CODE IN ({quoted(app_codes)})")} if app_codes else set()
    js = ("const codes=" + json.dumps(app_codes) + ";const since=new Date(Date.now()-30*864e5);const hot=new Set();"
          "for(const d of ['ui','core']){const x=db.getSiblingDB(d);for(const c of x.getCollectionNames()){"
          "x.getCollection(c).distinct('appCode',{appCode:{$in:codes},updatedAt:{$gt:since}}).forEach(a=>hot.add(a));}}"
          "print(JSON.stringify([...hot]));")
    hot = set(json.loads(mongo_eval(js).strip().splitlines()[-1])) if app_codes else set()
    keep_a, plan_a = [], []
    for p in apps:
        if p["app"] not in in_security:
            keep_a.append((p["app"], "gone already"))
        elif p["app"] in hot:
            keep_a.append((p["app"], "changed within 30 days"))
        else:
            plan_a.append(dict(code=p["app"], owner=p["owner"], tier=p["tier"]))

    out = Path(a.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    plan = dict(env=a.env, made=dt.datetime.now().isoformat(timespec="seconds"), apps=plan_a, clients=plan_c,
                dropped=dict(apps=keep_a, clients=keep_c, odd_codes=blank))
    path = out / f"plan-{a.env}.json"
    path.write_text(json.dumps(plan, indent=1))
    say(f"{a.env}: plan {len(plan_a)} apps, {len(plan_c)} clients; dropped on re-check {len(keep_a)} apps, {len(keep_c)} clients")
    say(f"wrote {path}")


# ---------------------------------------------------------------- backup

def load_plan(path: str, env: str) -> tuple[dict, Path]:
    p = Path(path).expanduser()
    plan = json.loads(p.read_text())
    if plan["env"] != env:
        die(f"{p} is a plan for {plan['env']}, not {env}")
    return plan, p


def plan_key(plan: dict) -> str:
    return plan["made"]


def victims(plan: dict, my: list[str], mg: list[str]) -> tuple[list[str], list[str]]:
    clients = {c["code"] for c in plan["clients"]}
    apps = {a["code"] for a in plan["apps"]}

    def hit(name: str) -> bool:
        c, rest = split_tenant(name) or ("", "")
        return c in clients or rest in apps or rest.removesuffix("_draft") in apps

    return [n for n in my if hit(n)], [n for n in mg if hit(n)]


def run(cmd: list[str], out: Path, env: dict[str, str] | None = None) -> None:
    with gzip.open(out, "wb") as f:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        assert p.stdout is not None
        shutil.copyfileobj(p.stdout, f)
        err = p.stderr.read().decode() if p.stderr else ""
        if p.wait() != 0:
            die(f"{cmd[0]} failed for {out.name}: {err.strip()[-300:]}")


def cmd_backup(a: argparse.Namespace) -> None:
    plan, path = load_plan(a.plan, a.env)
    e = db_env()
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = path.parent / "backups" / a.env / stamp
    dest.mkdir(parents=True)
    menv = {**os.environ, "MYSQL_PWD": e["MYSQL_PWD"]}
    base = ["mysqldump", "-h", e["MYSQL_HOST"], "-u", e["MYSQL_USER"], "--single-transaction", "--no-tablespaces",
            "--set-gtid-purged=OFF", "--column-statistics=0"]

    say("security schema ...")
    run(base + ["--routines", "security"], dest / "security.sql.gz", menv)

    codes = [c["code"] for c in plan["clients"]]
    if codes:
        tables = [r[0] for r in mysql("SELECT TABLE_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = 'core' AND COLUMN_NAME = 'CLIENT_CODE'")]
        for t in tables:
            say(f"core.{t} rows of the plan's clients ...")
            run(base + ["core", t, f"--where=CLIENT_CODE IN ({quoted(codes)})"], dest / f"core.{t}.sql.gz", menv)

    my, mg = tenant_names()
    my_v, mg_v = victims(plan, my, mg)
    say(f"tenant data: {len(my_v)} MySQL schemas, {len(mg_v)} Mongo databases ...")
    for i in range(0, len(my_v), 100):
        run(base + ["--databases", *my_v[i:i + 100]], dest / f"tenant-mysql-{i // 100:03d}.sql.gz", menv)
    for n in mg_v:
        r = subprocess.run(["mongodump", f"--uri={e['MONGO_URI']}", f"--db={n}", f"--archive={dest / ('tenant-mongo-' + n + '.archive.gz')}", "--gzip", "--quiet"],
                           capture_output=True, text=True)
        if r.returncode != 0:
            die(f"mongodump {n}: {r.stderr.strip()[-300:]}")

    apps = [x["code"] for x in plan["apps"]]
    say("ui/core definitions of the plan's clients and apps ...")
    for d in ("ui", "core"):
        names = mongo_eval(f"print(db.getSiblingDB('{d}').getCollectionNames().join('\\n'))").split()
        for c in names:
            q = {"$or": [{"clientCode": {"$in": codes}}, {"appCode": {"$in": apps}}, {"objectAppCode": {"$in": apps}}]}
            qfile = dest / f".q-{d}-{c}.json"
            qfile.write_text(json.dumps(q))
            r = subprocess.run(["mongodump", f"--uri={e['MONGO_URI']}", f"--db={d}", f"--collection={c}", f"--queryFile={qfile}",
                                f"--archive={dest / f'defs-{d}-{c}.archive.gz'}", "--gzip", "--quiet"], capture_output=True, text=True)
            qfile.unlink()
            if r.returncode != 0:
                die(f"mongodump {d}.{c}: {r.stderr.strip()[-300:]}")

    manifest = dict(plan=str(path), plan_made=plan_key(plan), env=a.env, at=stamp, mysql_tenant=my_v, mongo_tenant=mg_v,
                    clients=len(codes), apps=len(apps))
    (dest / "MANIFEST.json").write_text(json.dumps(manifest, indent=1))
    size = sum(f.stat().st_size for f in dest.iterdir())
    say(f"backup done: {dest} ({size / 1e6:.1f} MB)")


def has_backup(plan: dict, path: Path, env: str) -> Path | None:
    root = path.parent / "backups" / env
    for m in sorted(root.glob("*/MANIFEST.json"), reverse=True) if root.is_dir() else []:
        if json.loads(m.read_text()).get("plan_made") == plan_key(plan):
            return m.parent
    return None


# ---------------------------------------------------------------- purge

def api_for(env: str, base_url: str | None) -> pc.Api:
    if env == "local":
        return pc.Api.connect(base_url or pc.DEFAULT_BASE_URL)
    if not base_url:
        die("--base-url is required off local (e.g. https://appbuilder.dev.modlix.com)")
    tok = os.environ.get("MODLIX_PURGE_TOKEN", "").strip()
    if not tok:
        die("set MODLIX_PURGE_TOKEN to a SYSTEM token for this environment")
    api = pc.Api(base_url.rstrip("/"), tok)
    api.ctx = None  # real certificates off local
    return api


def call(api: pc.Api, path: str, dry: bool) -> tuple[int, object]:
    url = f"{api.base}{path}?dryRun={'true' if dry else 'false'}"
    req = urllib.request.Request(url, method="DELETE", headers=api.headers())
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, context=api.ctx, timeout=300) as r:
                body = r.read()
                return r.status, json.loads(body) if body else None
        except urllib.error.HTTPError as e:
            body = e.read()
            try:
                return e.code, json.loads(body)
            except ValueError:
                return e.code, body.decode("utf-8", "replace")[:500]
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == 2:
                return 0, str(e)
            time.sleep(2 * (attempt + 1))
    return 0, "unreachable"


def cmd_purge(a: argparse.Namespace) -> None:
    plan, path = load_plan(a.plan, a.env)
    dry = not a.go
    if not dry:
        b = has_backup(plan, path, a.env)
        if not b:
            die("no backup of this plan yet: run backup first")
        say(f"backup: {b}")
    api = api_for(a.env, a.base_url)
    log = path.parent / f"purge-{a.env}-{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}{'-dry' if dry else ''}.jsonl"
    say(f"{'DRY RUN' if dry else 'PURGING'} {a.env}: {len(plan['apps'])} apps, then {len(plan['clients'])} clients; log {log}")
    stats = {"ok": 0, "refused": 0, "failed": 0}

    def one(kind: str, code: str) -> dict:
        t0 = time.time()
        st, body = call(api, f"/api/multi/purge/{kind}/{code}", dry)
        outcome = "ok" if st == 200 else "refused" if st in (400, 404, 409) else "failed"
        return dict(kind=kind, code=code, status=st, outcome=outcome, ms=int((time.time() - t0) * 1000), body=body)

    def batch(kind: str, codes: list[str], f) -> None:
        with cf.ThreadPoolExecutor(max_workers=a.workers) as ex:
            for r in ex.map(lambda c: one(kind, c), codes):
                f.write(json.dumps(r) + "\n")
                f.flush()
                stats[r["outcome"]] += 1
                if r["outcome"] != "ok":
                    say(f"  {r['outcome']} {kind} {r['code']}: {r['status']} {str(r['body'])[:200]}")
                if r["outcome"] == "failed" and stats["failed"] >= a.max_failures:
                    die(f"stopping after {stats['failed']} failures; see {log}")

    limit = a.limit or 10**9
    with log.open("w") as f:
        apps = [x["code"] for x in plan["apps"]][:limit]
        batch("application", apps, f)
        say(f"apps done: {stats}")
        # Deepest first, one depth at a time: a manager goes only after the clients it manages.
        clients = plan["clients"][:limit]
        for depth in sorted({c["depth"] for c in clients}, reverse=True):
            batch("client", [c["code"] for c in clients if c["depth"] == depth], f)
            say(f"clients at depth {depth} done: {stats}")
    say(f"finished: {stats}; log {log}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--env", required=True, choices=["local", "dev", "stage"])
    p.add_argument("--report", required=True)
    p.add_argument("--out", required=True)
    b = sub.add_parser("backup")
    b.add_argument("--env", required=True, choices=["local", "dev", "stage"])
    b.add_argument("--plan", required=True)
    g = sub.add_parser("purge")
    g.add_argument("--env", required=True, choices=["local", "dev", "stage"])
    g.add_argument("--plan", required=True)
    g.add_argument("--base-url")
    g.add_argument("--go", action="store_true", help="really delete (default: dry run)")
    g.add_argument("--limit", type=int, help="only the first N apps and N clients (a trial run)")
    g.add_argument("--workers", type=int, default=4)
    g.add_argument("--max-failures", type=int, default=10)
    a = ap.parse_args()
    {"plan": cmd_plan, "backup": cmd_backup, "purge": cmd_purge}[a.cmd](a)


if __name__ == "__main__":
    main()
