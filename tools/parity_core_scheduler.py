#!/usr/bin/env python3
"""Step 4 parity: the Java scheduler (in the local Java core) and the Rust one (core-scheduler
and core-events, run by the gated test `scheduler_parity::scheduler_parity_run`) on the same
scratch schedules, compared per tick.

What it does, and where it writes:
- creates scratch EventDefinitions (with schedules), EventActions and two functions in the
  scratch app `monkbars` (client SYSTEM) through the Java definitions API, names starting
  `RPS_` / `RustParitySched`;
- copies those documents into a scratch Mongo database `rs_scratch_sched_parity_<tag>`, which
  is the only database the Rust side reads and writes (so the two schedulers never claim each
  other's ticks, and the Rust side never touches the real `schedule_run` / `scheduled_event`);
- schedules the same one-off on each side (Java through a stored function calling
  CoreServices.Event.ScheduleEvent, Rust in the harness);
- runs the Rust side for --minutes on a scratch exchange and scratch queues of the local broker
  (never the real `events` exchange: the Java core consumes it);
- compares, for the ticks both sides had in the window, the `schedule_run` rows, the one-off's
  `scheduled_event` row and the `core_event_runs` rows each side wrote;
- deletes the scratch definitions (Java API), the scratch database and the scratch run-log rows
  of `monkbars` / `RPS_*`. Java's own `schedule_run` rows of the scratch app are left to their
  TTL index.

Verdicts as the other parity scripts: SAME, EXPECTED <tag> (crates/core/DIFFERENCES.md), DIFF.
With --real-load the scratch app is not used: every stored EventDefinition is copied into the
scratch database, the Rust side runs in no-op mode (each raised event is closed as done without
running anything; the run log is off) and its `schedule_run` ticks are compared, per tick, with
the ones the local Java scheduler claims on the real store over the same window. Java runs its
ticks in-process with a few run slots, so on a busy stack it reaches fewer ticks than Rust
(which only publishes); a tick Java has and Rust does not is the failure this mode looks for.

Usage: tools/parity_core_scheduler.py [--minutes=5] [--keep] [--real-load]
"""
import json
import os
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import parity_core_exec as P  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEEP = "--keep" in sys.argv
REAL_LOAD = "--real-load" in sys.argv
MINUTES = next((int(a.split("=", 1)[1]) for a in sys.argv if a.startswith("--minutes=")), 5)
TAG = secrets.token_hex(3)
APP, CLIENT, NS = "monkbars", "SYSTEM", "RustParitySched"
SCRATCH_DB = f"rs_scratch_sched_parity_{TAG}"
EXCHANGE = f"rs_scratch_parity_{TAG}"
QUEUES = [f"rs_scratch_parity{i}_{TAG}" for i in (1, 2, 3)]
ONE_OFF_KEY = f"rp-once-{TAG}"


def H(json_body=True):
    return P.headers(app="appbuilder", client=CLIENT, json_body=json_body)


def java(method, path, body=None, hdrs=None):
    s, _, b = P.fetch(P.JAVA, method, path, hdrs or H(), body)
    return s, P.parse(b)


def task(name):
    return {"t1": {"key": "t1", "order": 1, "type": "CALL_CORE_FUNCTION",
                   "parameters": {"namespace": NS, "name": name, "functionParameterName": "dataObject"}}}


SCHEDULES = {
    "RPS_EVERY": ({"cron": "* * * * *"}, "noop"),
    "RPS_FAILING": ({"cron": "* * * * *"}, "missing"),
    "RPS_SPREAD": ({"cron": "*/2 * * * *", "spread": True}, "noop"),
    "RPS_KOLKATA": ({"cron": "* * * * *", "timezone": "Asia/Kolkata"}, "noop"),
    "RPS_NO_ACTION": ({"cron": "* * * * *"}, None),
    "RPS_ONE_OFF": (None, "noop"),
}


def value(v):
    return {"one": {"key": "one", "type": "VALUE", "value": v, "order": 1}}


FUNCTIONS = [
    {"name": f"{NS}.noop", "definition": {
        "name": "noop", "namespace": NS, "steps": {},
        "parameters": {"dataObject": {"parameterName": "dataObject", "schema": {"type": ["OBJECT", "NULL"]}}}}},
    {"name": f"{NS}.scheduleOne", "definition": {
        "name": "scheduleOne", "namespace": NS,
        "steps": {"s1": {"statementName": "s1", "namespace": "CoreServices.Event", "name": "ScheduleEvent",
                         "parameterMap": {"eventName": value("RPS_ONE_OFF"), "key": value(ONE_OFF_KEY),
                                          "data": value({"n": 1, "who": "parity"})}}}}},
]

CREATED = []


def setup():
    for f in FUNCTIONS:
        s, v = java("POST", "/api/core/functions", dict(f, appCode=APP, clientCode=CLIENT))
        assert s == 200, f"function {f['name']}: {s} {v}"
        CREATED.append(("functions", v["id"]))
    for name, (schedule, fn) in SCHEDULES.items():
        body = {"name": name, "appCode": APP, "clientCode": CLIENT}
        if schedule:
            body["schedule"] = schedule
        s, v = java("POST", "/api/core/eventDefinitions", body)
        assert s == 200, f"eventDefinition {name}: {s} {v}"
        CREATED.append(("eventDefinitions", v["id"]))
        if fn:
            s, v = java("POST", "/api/core/eventActions", {"name": name, "appCode": APP, "clientCode": CLIENT, "tasks": task(fn)})
            assert s == 200, f"eventAction {name}: {s} {v}"
            CREATED.append(("eventActions", v["id"]))


def mongosh(script):
    out = subprocess.run(["mongosh", "--quiet", "mongodb://localhost:27017/core", "--eval", script],
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out) if out.strip() else None


def copy_to_scratch():
    mongosh("""
    const dst = db.getSiblingDB('%s');
    for (const c of ['eventDefinition', 'eventAction', 'function']) {
      db[c].find({appCode: '%s', name: {$regex: '^(RPS_|%s)'}}).forEach(d => dst[c].insertOne(d));
    }
    print(JSON.stringify(1));
    """ % (SCRATCH_DB, APP, NS))


def local_env():
    env = {}
    with open(os.path.join(ROOT, "config/local.env")) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k] = v
    return env


def copy_all_definitions():
    mongosh("""
    const dst = db.getSiblingDB('%s');
    db.eventDefinition.find({}).forEach(d => dst.eventDefinition.insertOne(d));
    print(JSON.stringify(dst.eventDefinition.countDocuments({})));
    """ % SCRATCH_DB)


def mysql(sql):
    env = dict(os.environ, MYSQL_PWD=os.environ.get("MODLIX__DATABASE__PASSWORD") or local_env().get("MODLIX__DATABASE__PASSWORD", ""))
    out = subprocess.run(["mysql", "-h", "127.0.0.1", "-u", "root", "-N", "-B", "core", "-e", sql],
                         capture_output=True, text=True, check=True, env=env).stdout
    return [line.split("\t") for line in out.splitlines() if line]


def run_rust(start_ms):
    env = dict(local_env(), **os.environ)
    env.update({
        "CORE_LOCAL_STACK": "1",
        "CARGO_INCREMENTAL": "0",
        "CONFIG_FILE": os.path.join(ROOT, "config/core-events.toml"),
        "MODLIX__MONGO__DATABASE": SCRATCH_DB,
        "MODLIX__MQ__EVENTS_EXCHANGE": EXCHANGE,
        "MODLIX__MQ__EVENTS_ROUTING_KEYS": ",".join(QUEUES),
        "MODLIX__EVENTS__QUEUES": ",".join(QUEUES),
        "MODLIX__EVENTS__DECLARE": "true",
        "MODLIX__MQ__PASSWORD": env.get("MODLIX__MQ__PASSWORD", "guest"),
        "MODLIX__CORE__SCHEDULER__ENABLED": "true",
        "MODLIX__CORE__SCHEDULER__INITIAL_DELAY_MS": "0",
        "RS_PARITY_MINUTES": str(MINUTES),
        "RS_PARITY_ONE_OFF_KEY": ONE_OFF_KEY,
        "RS_PARITY_ONE_OFF_EVENT": "RPS_ONE_OFF",
        "RS_PARITY_APP": APP,
    })
    if REAL_LOAD:
        env.update({"RS_PARITY_NOOP": "1", "MODLIX__CORE__EVENT_RUNS__ENABLED": "false"})
    r = subprocess.run(["cargo", "test", "-p", "core", "--lib", "--", "--ignored", "--exact",
                        "scheduler_parity::scheduler_parity_run", "--nocapture"],
                       cwd=ROOT, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-4000:], r.stderr[-4000:])
        raise SystemExit("the Rust side failed")


def plain(v):
    """Relaxed EJSON flattened: {"$date": t} is t, {"$oid": h} is h."""
    if isinstance(v, dict):
        if set(v) == {"$date"}:
            return v["$date"]
        if set(v) == {"$oid"}:
            return v["$oid"]
        return {k: plain(x) for k, x in v.items()}
    if isinstance(v, list):
        return [plain(x) for x in v]
    return v


def runs(dbname, since_ms, until_ms):
    return plain(mongosh("""
    const d = db.getSiblingDB('%s');
    print(EJSON.stringify(d.schedule_run.find({appCode: '%s', eventName: {$regex: '^RPS_'},
        tickAt: {$gte: new Date(%d), $lt: new Date(%d)}}).toArray(), {relaxed: true}));
    """ % (dbname, APP, since_ms, until_ms)))


def one_off(dbname):
    return plain(mongosh("""
    print(EJSON.stringify(db.getSiblingDB('%s').scheduled_event.findOne({appCode: '%s', key: '%s'}), {relaxed: true}));
    """ % (dbname, APP, ONE_OFF_KEY)))


def event_runs():
    rows = mysql(f"SELECT EVENT_NAME, CLIENT_CODE, TRIGGER_TYPE, STATUS, SCHEDULE_RUN_ID, SCHEDULED_FOR, ATTEMPT, "
                 f"TASK_COUNT, FAILED_TASK_COUNT, IFNULL(TASKS, ''), IFNULL(ERROR, '') FROM core_event_runs "
                 f"WHERE APP_CODE = '{APP}' AND EVENT_NAME LIKE 'RPS\\_%'")
    keys = ["event", "client", "trigger", "status", "runId", "scheduledFor", "attempt", "taskCount", "failedTaskCount",
            "tasks", "error"]
    return [dict(zip(keys, r)) for r in rows]


def task_shape(tasks):
    if not tasks:
        return []
    return [{k: t.get(k) for k in ("key", "type", "target", "order", "status", "error")} for t in json.loads(tasks)]


def compare(java_runs, rust_runs, java_one, rust_one, java_log, rust_log):
    jt = {(r["clientCode"], r["eventName"], r["tickAt"]): r for r in java_runs}
    rt = {(r["clientCode"], r["eventName"], r["tickAt"]): r for r in rust_runs}
    both = sorted(set(jt) & set(rt))
    only_java = sorted(set(jt) - set(rt))
    only_rust = sorted(set(rt) - set(jt))
    P.record(f"ticks in the window: {len(both)} on both sides", "SAME" if both else "DIFF",
             f"only Java {only_java[:5]} only Rust {only_rust[:5]}")
    for k in only_java + only_rust:
        P.record(f"tick {k}", "DIFF", f"java {jt.get(k)}\n    rust {rt.get(k)}")
    for k in both:
        j, r = jt[k], rt[k]
        jv = {f: j.get(f) for f in ("status", "error")}
        rv = {f: r.get(f) for f in ("status", "error")}
        fields_j, fields_r = [f for f in j if f != "owner"], [f for f in r if f != "owner"]
        P.record(f"schedule_run {k[1]} {k[0]} {k[2]}", "SAME" if (jv, fields_j) == (rv, fields_r) else "DIFF",
                 f"java {jv} {fields_j}\n    rust {rv} {fields_r}")
    keep = ("status", "attempts", "maxAttempts", "eventName", "data", "draft", "scheduledBy", "lastError")
    jo = {k: (java_one or {}).get(k) for k in keep}
    ro = {k: (rust_one or {}).get(k) for k in keep}
    P.record("scheduled_event of the one-off", "SAME" if jo == ro else "DIFF", f"java {jo}\n    rust {ro}")

    java_ids = {r["_id"] for r in java_runs} | {(java_one or {}).get("_id", "")}
    rust_ids = {r["_id"] for r in rust_runs} | {(rust_one or {}).get("_id", "")}

    def logged(rows, ids):
        out = {}
        for row in rows:
            if row["runId"] in ids:
                out[(row["event"], row["client"], row["scheduledFor"])] = row
        return out

    jl, rl = logged(java_log, java_ids), logged(rust_log, rust_ids)
    for k in sorted(set(jl) | set(rl)):
        j, r = jl.get(k), rl.get(k)
        if not j or not r:
            P.record(f"core_event_runs {k}", "DIFF", f"java {j}\n    rust {r}")
            continue
        shape = lambda x: {f: x[f] for f in ("trigger", "status", "attempt", "taskCount", "failedTaskCount", "error")}  # noqa: E731
        same = shape(j) == shape(r) and task_shape(j["tasks"]) == task_shape(r["tasks"])
        P.record(f"core_event_runs {k}", "SAME" if same else "DIFF",
                 f"java {shape(j)} {task_shape(j['tasks'])}\n    rust {shape(r)} {task_shape(r['tasks'])}")
    # NO_ACTION rows carry no run id: compared by event.
    jn = [r for r in java_log if r["status"] == "NO_ACTION" and r["event"] == "RPS_NO_ACTION"]
    rn = [r for r in rust_log if r["status"] == "NO_ACTION" and r["event"] == "RPS_NO_ACTION"]
    P.record("NO_ACTION rows (throttled: one an hour per instance)",
             "SAME" if len(rn) == 1 and jn and jn[0]["error"] == rn[0]["error"] else "DIFF",
             f"java {[(r['error'][:120]) for r in jn]}\n    rust {[(r['error'][:120]) for r in rn]}")


def cleanup():
    if KEEP:
        print(f"# kept: {CREATED} {SCRATCH_DB}")
        return
    # The Java one-off, if Java never reached it (as ScheduledEventService.cancel does).
    mongosh("""
    const now = new Date();
    db.scheduled_event.updateMany({appCode: '%s', key: '%s', status: 'PENDING'},
                                  {$set: {status: 'CANCELLED', finishedAt: now, updatedAt: now}});
    print(JSON.stringify(1));
    """ % (APP, ONE_OFF_KEY))
    for kind, oid in CREATED:
        s, v = java("DELETE", f"/api/core/{kind}/{oid}", hdrs=H(json_body=False))
        if s != 200:
            print(f"# cleanup: {kind} {oid}: {s} {v}")
    mongosh("db.getSiblingDB('%s').dropDatabase(); print(JSON.stringify(1));" % SCRATCH_DB)
    mysql(f"DELETE FROM core_event_runs WHERE APP_CODE = '{APP}' AND EVENT_NAME LIKE 'RPS\\_%'")


def all_runs(dbname, since_ms, until_ms):
    return plain(mongosh("""
    const d = db.getSiblingDB('%s');
    print(EJSON.stringify(d.schedule_run.find({tickAt: {$gte: new Date(%d), $lt: new Date(%d)}},
        {appCode: 1, clientCode: 1, eventName: 1, tickAt: 1, status: 1}).toArray(), {relaxed: true}));
    """ % (dbname, since_ms, until_ms)))


def real_load():
    copy_all_definitions()
    start = int(time.time() * 1000)
    try:
        run_rust(start)
        end = int(time.time() * 1000)
        time.sleep(60)  # Java claims a busy tick late, inside its fresh window
        since = (start // 60000 + 2) * 60000
        until = (end // 60000 - 1) * 60000
        jr = all_runs("core", since, until)
        rr = all_runs(SCRATCH_DB, since, until)
        dump = os.environ.get("RS_PARITY_DUMP")
        if dump:
            with open(dump, "w") as f:
                json.dump({"java": jr, "rust": rr, "window": [since, until]}, f, indent=1)
    finally:
        mongosh("db.getSiblingDB('%s').dropDatabase(); print(JSON.stringify(1));" % SCRATCH_DB)
    key = lambda r: (r["appCode"], r["clientCode"], r["eventName"], r["tickAt"])  # noqa: E731
    jt, rt = {key(r): r for r in jr}, {key(r): r for r in rr}
    both, java_only, rust_only = set(jt) & set(rt), sorted(set(jt) - set(rt)), sorted(set(rt) - set(jt))
    P.record(f"real load: {len(jt)} Java ticks, {len(rt)} Rust ticks, {len(both)} on both", "SAME" if both else "DIFF")
    P.record(f"ticks Java claimed that Rust did not: {len(java_only)}", "SAME" if not java_only else "DIFF",
             "\n    ".join(map(str, java_only[:20])))
    P.record(f"ticks only Rust reached (Java's run slots were full): {len(rust_only)}",
             "SAME" if not rust_only else "EXPECTED J1_java_run_slots_full", "\n    ".join(map(str, rust_only[:5])))
    pairs = {}
    for k in both:
        p = (jt[k]["status"], rt[k]["status"])
        pairs[p] = pairs.get(p, 0) + 1
    print(f"# statuses (java, rust) of the shared ticks: {pairs}")


def main():
    if REAL_LOAD:
        real_load()
        counts = {}
        for _, v, _ in P.RESULTS:
            counts[v.split(" ")[0]] = counts.get(v.split(" ")[0], 0) + 1
        print(f"\n{len(P.RESULTS)} checks: " + ", ".join(f"{k} {n}" for k, n in sorted(counts.items())))
        sys.exit(1 if counts.get("DIFF") else 0)
    active = mongosh("print(JSON.stringify(db.schedule_run.countDocuments({createdAt: {$gt: new Date(Date.now() - 600000)}})))")
    if not active:
        raise SystemExit("the local Java scheduler has written no schedule_run row in 10 minutes: nothing to compare with")
    try:
        setup()
        copy_to_scratch()
        start = int(time.time() * 1000)
        s, v = java("POST", f"/api/core/function/execute/{NS}/scheduleOne", {}, P.headers(app=APP, client=CLIENT, json_body=True))
        P.record("Java schedules the one-off", "SAME" if s == 200 else "DIFF", f"{s} {json.dumps(v)[:300]}")
        run_rust(start)
        end = int(time.time() * 1000)
        time.sleep(45)  # Java's last runs finishing
        # The window: from the first full minute after both started to a minute before the end.
        since = (start // 60000 + 2) * 60000
        until = (end // 60000 - 1) * 60000
        data = {"java_runs": runs("core", since, until), "rust_runs": runs(SCRATCH_DB, since, until),
                "java_one": one_off("core"), "rust_one": one_off(SCRATCH_DB), "event_runs": event_runs(),
                "window": [since, until]}
        dump = os.environ.get("RS_PARITY_DUMP")
        if dump:
            with open(dump, "w") as f:
                json.dump(data, f, indent=1, default=str)
        compare(data["java_runs"], data["rust_runs"], data["java_one"], data["rust_one"], data["event_runs"], data["event_runs"])
    finally:
        cleanup()
    counts = {}
    for _, v, _ in P.RESULTS:
        counts[v.split(" ")[0]] = counts.get(v.split(" ")[0], 0) + 1
    print(f"\n{len(P.RESULTS)} checks: " + ", ".join(f"{k} {n}" for k, n in sorted(counts.items())))
    sys.exit(1 if counts.get("DIFF") else 0)


if __name__ == "__main__":
    main()
