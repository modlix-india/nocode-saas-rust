#!/usr/bin/env python3
"""Creates the `platform` app (client SYSTEM) on LOCAL with the retired worker's jobs, through
the APIs, from tools/platform_seed/definitions.json:

  1. the security app `platform`       POST /api/security/applications   (when missing)
  2. a job function per job            /api/core/functions   (Platform.Jobs.<job>)
  3. an EventDefinition per job        /api/core/eventDefinitions   (the schedule)
  4. an EventAction per job            /api/core/eventActions

Idempotent: an object is created when missing, updated (PUT of the stored document with the
seed's fields) when it differs, and left alone when it already holds what the seed says.
Nothing is deleted unless --prune is given: then the functions, EventDefinitions and
EventActions the platform app holds for SYSTEM that the seed no longer lists are deleted
through the API (definitions first, so no tick raises an event whose action is gone).

Schedules are written OFF on local unless --enable-schedules is given. On local the jobs would
otherwise run for real as soon as a Rust core-events is up (TOKEN_CLEANUP calls security's
tokens/cleanup, which must not run on the local stack). The transport made by
tools/make_platform_transport.py carries the schedules as definitions.json has them (on)
whatever local holds.

    python3 tools/seed_platform_app.py --dry-run            # what it would do (reads only)
    python3 tools/seed_platform_app.py                      # create / update, schedules off
    python3 tools/seed_platform_app.py --enable-schedules   # the same, schedules on
    python3 tools/seed_platform_app.py --prune --dry-run    # what a prune would delete
    python3 tools/seed_platform_app.py --prune              # create / update, then delete the rest

LOCAL only: a base URL whose host is not loopback is refused (see platform_common.py).
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from typing import Any

from platform_common import (DEFAULT_BASE_URL, KINDS, Api, comparable, contains, die, differences, info,
                             load_seed)

APP_ROUTE = "/api/security/applications"


def desired_docs(seed: dict[str, Any], enable_schedules: bool) -> dict[str, list[dict[str, Any]]]:
    docs = {key: copy.deepcopy(seed[key]) for _, _, key in KINDS}
    for d in docs["eventDefinitions"]:
        d["schedule"]["enabled"] = bool(enable_schedules)
    return docs


def ensure_app(api: Api, seed: dict[str, Any], dry: bool) -> bool:
    """Creates the security app when it is missing; answers whether it exists now (a dry run
    leaves a missing app missing)."""
    app = seed["app"]
    code = app["appCode"]
    if api.token is None:
        info(f"app {code}: (state unknown, no token) would create if missing: {json.dumps(app)}")
        return False
    st, body = api.call("GET", f"{APP_ROUTE}/appCode/{code}")
    if st == 200 and isinstance(body, dict) and body.get("appCode") == code:
        info(f"app {code}: exists (id {body.get('id')}, clientId {body.get('clientId')}, "
             f"type {body.get('appType')}, access {body.get('appAccessType')})")
        if body.get("appType") != app["appType"] or body.get("appAccessType") != app["appAccessType"]:
            info(f"  note: differs from the seed ({app['appType']}/{app['appAccessType']}); left as it is")
        return True
    create = {k: app[k] for k in ("appCode", "appName", "appType", "appAccessType")}
    if dry:
        info(f"app {code}: would create {json.dumps(create)}")
        return False
    st, body = api.call("POST", APP_ROUTE, create)
    if st not in (200, 201) or not isinstance(body, dict) or body.get("appCode") != code:
        die(f"creating app {code} failed (HTTP {st}): {json.dumps(body)[:300]}")
    info(f"app {code}: created (id {body.get('id')}, clientId {body.get('clientId')})")
    return True


def stored(api: Api, route: str, app: str, client: str) -> dict[str, dict[str, Any]]:
    """The documents the client itself holds in the app, by name."""
    st, body = api.call("GET", f"/api/core/{route}", params={"appCode": app, "clientCode": client, "page": 0, "size": 500})
    if st != 200 or not isinstance(body, dict):
        die(f"listing {route} failed (HTTP {st}): {str(body)[:300]}")
    rows = [r for r in body.get("content", []) if r.get("appCode") == app and r.get("clientCode") == client]
    return {r["name"]: r for r in rows}


def full(api: Api, route: str, row: dict[str, Any]) -> dict[str, Any]:
    st, body = api.call("GET", f"/api/core/{route}/{row['id']}")
    if st != 200 or not isinstance(body, dict):
        die(f"reading {route}/{row['id']} failed (HTTP {st})")
    return body


def upsert_kind(api: Api, route: str, docs: list[dict[str, Any]], dry: bool, app_exists: bool = True) -> list[str]:
    """Creates or updates each document; answers the names that need (or got) a write."""
    app, client = docs[0]["appCode"], docs[0]["clientCode"]
    if api.token is None:
        for d in docs:
            info(f"{route} {d['name']}: (state unknown, no token) would create or update")
        return [d["name"] for d in docs]
    # An app that does not exist yet holds nothing (and core refuses to list it).
    current = stored(api, route, app, client) if app_exists else {}
    written = []
    for d in docs:
        name = d["name"]
        row = current.get(name)
        if row is None:
            if dry:
                info(f"{route} {name}: would create")
            else:
                st, body = api.call("POST", f"/api/core/{route}", d)
                if st not in (200, 201):
                    die(f"creating {route} {name} failed (HTTP {st}): {json.dumps(body)[:300]}")
                info(f"{route} {name}: created")
            written.append(name)
            continue
        doc = full(api, route, row)
        want = comparable(d)
        if contains(want, doc):
            info(f"{route} {name}: unchanged")
            continue
        diff = differences(want, doc)
        if dry:
            info(f"{route} {name}: would update ({'; '.join(diff)[:400]})")
        else:
            new = dict(doc)
            new.update(d)
            st, body = api.call("PUT", f"/api/core/{route}/{doc['id']}", new)
            if st != 200:
                die(f"updating {route} {name} failed (HTTP {st}): {json.dumps(body)[:300]}")
            info(f"{route} {name}: updated ({'; '.join(diff)[:400]})")
        written.append(name)
    return written


def prune(api: Api, docs: dict[str, list[dict[str, Any]]], dry: bool, app_exists: bool) -> int:
    """Deletes what the app holds for its client that the seed does not list; answers how many
    objects were (or would be) deleted. Definitions, then actions, then functions."""
    if api.token is None or not app_exists:
        info("prune: nothing to compare (no token or no app)")
        return 0
    removed = 0
    by_route = {route: (route, folder, key) for route, folder, key in KINDS}
    for route, _, key in (by_route[r] for r in ("eventDefinitions", "eventActions", "functions")):
        app, client = docs[key][0]["appCode"], docs[key][0]["clientCode"]
        wanted = {d["name"] for d in docs[key]}
        for name, row in sorted(stored(api, route, app, client).items()):
            if name in wanted:
                continue
            removed += 1
            if dry:
                info(f"{route} {name}: would delete (id {row['id']}, not in the seed)")
                continue
            st, body = api.call("DELETE", f"/api/core/{route}/{row['id']}")
            if st not in (200, 204):
                die(f"deleting {route} {name} failed (HTTP {st}): {json.dumps(body)[:300]}")
            info(f"{route} {name}: deleted (not in the seed)")
    return removed


def verify(api: Api, docs: dict[str, list[dict[str, Any]]], pruned: bool = False) -> None:
    bad = []
    for route, _, key in KINDS:
        current = stored(api, route, docs[key][0]["appCode"], docs[key][0]["clientCode"])
        for d in docs[key]:
            row = current.get(d["name"])
            if row is None:
                bad.append(f"{route} {d['name']}: missing")
                continue
            diff = differences(comparable(d), full(api, route, row))
            if diff:
                bad.append(f"{route} {d['name']}: {'; '.join(diff)[:300]}")
        if pruned:
            extra = sorted(set(current) - {d["name"] for d in docs[key]})
            bad.extend(f"{route} {name}: still there after the prune" for name in extra)
    if bad:
        die("after the writes, local does not hold the seed:\n  " + "\n  ".join(bad))
    info("verified: local holds every object of the seed" + (" and nothing else" if pruned else ""))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"the LOCAL gateway (default {DEFAULT_BASE_URL})")
    ap.add_argument("--dry-run", action="store_true", help="print what would be done; only reads")
    ap.add_argument("--enable-schedules", action="store_true",
                    help="write the schedules on (as definitions.json has them); off by default on local")
    ap.add_argument("--prune", action="store_true",
                    help="also delete the platform app's functions, EventDefinitions and EventActions (SYSTEM) "
                         "that the seed no longer lists")
    args = ap.parse_args()

    seed = load_seed()
    api = Api.connect(args.base_url, need_token=not args.dry_run)
    docs = desired_docs(seed, args.enable_schedules)
    mode = "DRY RUN, nothing is written" if args.dry_run else "writing"
    info(f"platform seed on {api.base} ({mode}); schedules {'ON' if args.enable_schedules else 'off'}")
    if args.enable_schedules:
        info("  warning: with schedules on, a running Rust core-events executes these jobs against LOCAL,\n"
             "  TOKEN_CLEANUP included (security tokens/cleanup must not run on the local stack).")

    app_exists = ensure_app(api, seed, args.dry_run)
    total = 0
    # Functions first: an action names its function, a definition is raised to its action.
    for route, _, key in KINDS:
        total += len(upsert_kind(api, route, docs[key], args.dry_run, app_exists))
    removed = prune(api, docs, args.dry_run, app_exists) if args.prune else 0
    if args.dry_run:
        info(f"dry run: {total} object(s) would be created or updated, {removed} deleted")
        return
    if api.token is not None:
        verify(api, docs, pruned=args.prune)
    info(f"done: {total} object(s) created or updated, {removed} deleted")


if __name__ == "__main__":
    main()
