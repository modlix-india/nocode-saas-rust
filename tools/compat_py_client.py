#!/usr/bin/env python3
"""The real py_eureka_client (0.11.10, what the ai service uses) against a running Lighthouse.

Registers, heartbeats, fetches the registry and its delta (both read through the library's own
XML parser), drains with an OUT_OF_SERVICE override and back, and stops. Every step is checked
through the library's own calls; the first failure exits 1.

    python tools/compat_py_client.py [http://127.0.0.1:8761/eureka/]

Locally: nocode-ai/venv/bin/python (py_eureka_client 0.11.10) with a Lighthouse started by
`cargo run -p lighthouse`. In CI: .github/workflows/lighthouse-py-compat.yml.
"""

import asyncio
import sys
import time
import urllib.error

import py_eureka_client
from py_eureka_client import eureka_basic, logger
from py_eureka_client.eureka_client import EurekaClient

# The library logs the 404 that asks it to register again as a warning with a traceback; that
# 404 is one of the steps checked here.
logger.set_level("ERROR")

SERVER = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8761/eureka/"
APP = "PY-COMPAT"
ID = "py-compat-1"


def check(cond, what):
    if not cond:
        print(f"FAIL {what}", flush=True)
        sys.exit(1)
    print(f"ok   {what}", flush=True)


async def read_instance():
    """The instance as py reads it (XML through ElementTree), or None when the server says 404."""
    try:
        return await eureka_basic.get_app_instance(SERVER, APP, ID)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


async def eventually(pred, seconds, what):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if await pred():
            check(True, what)
            return
        await asyncio.sleep(0.1)
    check(False, what)


def find(apps, app, instance_id):
    for a in apps.applications:
        if a.name == app:
            for i in a.instances:
                if i.instanceId == instance_id:
                    return i
    return None


async def main():
    check(py_eureka_client.version == "0.11.10", f"py_eureka_client {py_eureka_client.version}")
    client = EurekaClient(
        eureka_server=SERVER,
        app_name="py-compat",
        instance_id=ID,
        instance_host="127.0.0.1",
        instance_ip="127.0.0.1",
        instance_port=9099,
        renewal_interval_in_secs=1,
        duration_in_secs=5,
        metadata={"runtime": "python", "with_underscore": "kept"},
    )
    await client.start()

    # Registered, and the whole registry parses with py's XML reader.
    apps = await eureka_basic.get_applications(SERVER)
    me = find(apps, APP, ID)
    check(me is not None, "registered; GET apps/ parses")
    check(me.status == "UP", "status UP")
    check(me.port.port == 9099 and me.port.enabled, "port 9099, enabled")
    check(not me.securePort.enabled, "secure port disabled")
    check(me.dataCenterInfo.className.endswith("DefaultDataCenterInfo"), "dataCenterInfo class")
    check(me.leaseInfo.renewalIntervalInSecs == 1 and me.leaseInfo.durationInSecs == 5, "its own lease, 1/5 s")
    check(me.metadata.get("runtime") == "python", "metadata")
    # The registry protocol's XML writes `_` in an element name as `__` (XStream); py reads it back like that from Java too.
    check(me.metadata.get("with__underscore") == "kept", "metadata key with an underscore, as Lighthouse writes it")
    check("UP_" in apps.appsHashcode, f"apps__hashcode {apps.appsHashcode}")

    # Heartbeats renew the lease.
    first = me.leaseInfo.lastRenewalTimestamp

    async def renewed():
        i = await read_instance()
        return i is not None and i.leaseInfo.lastRenewalTimestamp > first

    await eventually(renewed, 5, "heartbeats renew the lease")

    # The delta parses, and after merging it py's own hash code matches the server's.
    delta = await eureka_basic.get_delta(SERVER)
    check(delta.versionsDelta != "", f"delta parses (version {delta.versionsDelta})")
    check(find(delta, APP, ID) is not None, "the registration is in the delta")
    await asyncio.sleep(1.5)
    local = client.applications
    check(find(local, APP, ID) is not None, "the client's own registry cache has it")
    server_hash = (await eureka_basic.get_applications(SERVER)).appsHashcode
    check(client._EurekaClient__get_applications_hash() == server_hash, f"py's hash code matches ({server_hash})")
    app = await eureka_basic.get_application(SERVER, APP)
    check(app.name == APP and len(app.instances) == 1, "GET apps/PY-COMPAT parses")

    # Drain: an OUT_OF_SERVICE override survives heartbeats.
    await client.status_update("OUT_OF_SERVICE")
    await asyncio.sleep(1.5)
    i = await read_instance()
    check(i.status == "OUT_OF_SERVICE" and i.overriddenstatus == "OUT_OF_SERVICE", "OUT_OF_SERVICE holds through heartbeats")
    # Deleting the override leaves UNKNOWN; the next heartbeat is answered 404 and py registers again.
    await client.delete_status_override()

    async def back_up():
        i = await read_instance()
        return i is not None and i.status == "UP"

    await eventually(back_up, 6, "override deleted: py registered again and is UP")

    # Stop: py registers DOWN, then cancels.
    await client.stop()

    async def gone():
        return await read_instance() is None

    await eventually(gone, 1, "stopped: deregistered")
    try:
        await eureka_basic.get_application(SERVER, APP)
        check(False, "GET apps/PY-COMPAT answers 404 once empty")
    except urllib.error.HTTPError as e:
        check(e.code == 404, "GET apps/PY-COMPAT answers 404 once empty")
    print("PASS py_eureka_client 0.11.10 against Lighthouse", flush=True)


if __name__ == "__main__":
    asyncio.run(main())
