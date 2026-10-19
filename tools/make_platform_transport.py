#!/usr/bin/env python3
"""Makes, from LOCAL, the core transport file that carries the platform app's jobs to
dev / stage / prod. It only writes files: nothing is applied anywhere.

  1. exports from local, as app-transport.sh does, scoped to exactly the seed's objects:
       POST /api/core/transports/makeTransport
            {appCode: platform, clientCode: SYSTEM, objectList: {Function: [...11],
             EventDefinition: [...11], EventAction: [...11]}}
  2. checks the zip holds exactly those objects (3 per job) and nothing else, each matching
     tools/platform_seed/definitions.json (fields core manages aside);
  3. sets each EventDefinition's schedule to the seed's (on), since local keeps them off
     (see seed_platform_app.py), and records that in the manifest;
  4. writes <out> (default ./platform_SYSTEM.cmodl) and <out>.manifest.json: the app's
     security fields (security is not transported), the objects, the zip's sha256, and the
     steps to apply it.

    python3 tools/make_platform_transport.py [--out FILE] [--base-url URL]

Applying it is the owner's step, per environment, with approval; the manifest lists it.
LOCAL only: a base URL whose host is not loopback is refused (see platform_common.py).
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import zipfile
from pathlib import Path
from typing import Any

from platform_common import DEFAULT_BASE_URL, KINDS, Api, comparable, die, differences, info, load_seed


def object_list(seed: dict[str, Any]) -> dict[str, list[str]]:
    # Two or more names per type are matched exactly (one name is an unanchored pattern).
    return {folder: sorted(d["name"] for d in seed[key]) for _, folder, key in KINDS}


def export(api: Api, seed: dict[str, Any]) -> bytes:
    body = {
        "appCode": seed["app"]["appCode"],
        "clientCode": seed["app"]["clientCode"],
        "name": f"platform jobs {datetime.date.today().isoformat()}",
        "objectList": object_list(seed),
    }
    st, payload = api.call("POST", "/api/core/transports/makeTransport", body, raw=True)
    if st != 200:
        die(f"export failed (HTTP {st}): {payload[:300]!r}")
    if not payload.startswith(b"PK"):
        die(f"export did not answer a zip: {payload[:300]!r}")
    return payload


def entries(zf: zipfile.ZipFile) -> dict[str, bytes]:
    return {i.filename.lstrip("/"): zf.read(i) for i in zf.infolist() if not i.is_dir()}


def check_and_fix(files: dict[str, bytes], seed: dict[str, Any]) -> tuple[dict[str, bytes], list[str]]:
    """The zip's objects against the seed; answers the files to write and what was changed."""
    if "transport.json" not in files:
        die("the export has no transport.json")
    expected = {(folder, d["name"]): d for _, folder, key in KINDS for d in seed[key]}
    found: dict[tuple[str, str], str] = {}
    problems: list[str] = []
    for path, data in files.items():
        if path == "transport.json":
            continue
        folder = path.split("/", 1)[0]
        try:
            doc = json.loads(data)
        except ValueError:
            problems.append(f"{path}: not JSON")
            continue
        key = (folder, doc.get("name"))
        if key not in expected:
            problems.append(f"{path}: not in the seed ({folder} {doc.get('name')})")
            continue
        found[key] = path
        want = comparable(expected[key])
        if folder == "EventDefinition":
            # Local keeps schedules off; the file carries the seed's.
            want = {k: v for k, v in want.items() if k != "schedule"}
            sched = doc.get("schedule") or {}
            want_sched = {k: v for k, v in expected[key]["schedule"].items() if k != "enabled"}
            problems.extend(f"{path}: schedule{d}" for d in differences(want_sched, sched))
        if (doc.get("appCode"), doc.get("clientCode")) != ("platform", "SYSTEM"):
            problems.append(f"{path}: app/client {doc.get('appCode')}/{doc.get('clientCode')}")
        problems.extend(f"{path}: {d}" for d in differences(want, doc))
    for key in expected:
        if key not in found:
            problems.append(f"{key[0]} {key[1]}: missing from the export (seed local first)")
    if problems:
        die("the export does not match tools/platform_seed/definitions.json:\n  " + "\n  ".join(problems))

    out = dict(files)
    changed = []
    for (folder, name), path in sorted(found.items()):
        if folder != "EventDefinition":
            continue
        doc = json.loads(files[path])
        sched = dict(doc.get("schedule") or {})
        target = expected[(folder, name)]["schedule"]
        if any(sched.get(k) != v for k, v in target.items()):
            before = {k: sched.get(k) for k in target}
            sched.update(target)
            doc["schedule"] = sched
            out[path] = json.dumps(doc).encode()
            changed.append(f"{name}: schedule {json.dumps(before)} -> {json.dumps(target)}")
    return out, changed


def write_zip(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # transport.json first, then each type folder, as the services write them.
        for path in sorted(files, key=lambda p: (p != "transport.json", p)):
            zf.writestr(path, files[path])
    return buf.getvalue()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"the LOCAL gateway (default {DEFAULT_BASE_URL})")
    ap.add_argument("--out", default="platform_SYSTEM.cmodl", help="the transport file to write")
    args = ap.parse_args()

    seed = load_seed()
    api = Api.connect(args.base_url)
    app = seed["app"]

    st, meta = api.call("GET", f"/api/security/applications/appCode/{app['appCode']}")
    if st != 200 or not isinstance(meta, dict) or meta.get("appCode") != app["appCode"]:
        die(f"app {app['appCode']} is not on local (HTTP {st}); run tools/seed_platform_app.py first")

    count = sum(len(v) for v in object_list(seed).values())
    jobs = len(seed["jobs"])
    info(f"exporting {count} objects of {app['appCode']} from {api.base}")
    with zipfile.ZipFile(io.BytesIO(export(api, seed))) as zf:
        files = entries(zf)
    transport = json.loads(files["transport.json"])
    files, changed = check_and_fix(files, seed)
    data = write_zip(files)

    out = Path(args.out).resolve()
    out.write_bytes(data)
    sha = hashlib.sha256(data).hexdigest()
    create_app = {k: meta.get(k) or app[k] for k in ("appCode", "appName", "appType", "appAccessType")}
    manifest = {
        "file": out.name,
        "sha256": sha,
        "madeFrom": api.base,
        "madeAt": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "uniqueTransportCode": transport.get("uniqueTransportCode"),
        "app": create_app,
        "objects": object_list(seed),
        "changedFromLocal": changed,
        "apply": [
            "Per environment, with approval; nothing here has been applied.",
            "1. Only after the switch: the Java services (worker and core included) stopped, core-scheduler and "
            "core-events running (the runbook, oci-config rust/RUNBOOK.md). Java core has no CoreServices.Platform.* and the worker "
            "would run every job a second time.",
            f"2. If the app is missing there: POST <env>/api/security/applications {json.dumps(create_app)} "
            "(security is not transported).",
            f"3. POST <env>/api/core/transports/createAndApply?isForBaseApp=true&applicationCode={app['appCode']} "
            f"multipart file=@{out.name} (as app-transport.sh applies a core chunk; {count} objects, one request).",
            f"4. Verify: GET <env>/api/core/eventDefinitions?appCode=platform&clientCode=SYSTEM lists the {jobs} jobs "
            "with their schedules; the first ticks show in the event run log.",
        ],
    }
    Path(str(out) + ".manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    info(f"wrote {out} ({len(data)} bytes, sha256 {sha})")
    info(f"wrote {out}.manifest.json")
    for c in changed:
        info(f"  set from the seed: {c}")
    info("nothing was applied; the manifest lists the steps")


if __name__ == "__main__":
    main()
