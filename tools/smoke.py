#!/usr/bin/env python3
"""Smoke test of the Rust stack after the switch, through gateway-rust. Read-only.

    tools/smoke.py <gateway-base> [--host APP_HOST] [--page NAME] [--static-path PATH]
                   [--direct UNIT=URL ...] [--timeout SECONDS] [--insecure]

On an environment's host: tools/smoke.py http://localhost:8080 --host <app host>.
Locally: tools/smoke.py http://localhost:8182 --host leadzump.local.modlix.com.

Prints one line per check (OK, FAIL, SKIP; INFO lines never fail) and exits 1 when any check
failed, 2 on a usage error. The checks:

  readiness   gateway-rust's /readyz, then every unit behind the gateway from the gateway's own
              health checks (`gateway_pool_healthy_instances` on /metrics). core-scheduler and
              core-events serve no routes through the gateway: they are checked only when
              --direct names their address (core-scheduler=http://127.0.0.1:8108), else SKIP.
  anonymous   with Host: APP_HOST, as a browser loads the app: the application definition
              (ui-engine), its default page or --page (ui-engine), the index page (ui-shell),
              System.Math.Add through /api/core/function/execute (core-exec), a static file
              (files-serve; --static-path, else the first image the app definition names), and
              the notification stream refusing an anonymous caller.
  signed in   only when credentials are in the environment (never guessed, never retried):
                MODLIX_SMOKE_TOKEN                     a bearer token to use as it is, or
                MODLIX_SMOKE_USER, MODLIX_SMOKE_PASSWORD  one sign-in (POST /api/security/authenticate);
                                                       the token it makes is revoked at the end
                MODLIX_SMOKE_USER_ID                   (optional) the user's id, sent as userId
                MODLIX_SMOKE_CLIENT_CODE, MODLIX_SMOKE_APP_CODE  (optional) clientCode / appCode
                                                       headers, when the host alone does not pick them
              then verifyToken (security-auth), the application signed in (ui-engine), one page of
              core functions (core-editor), of ui pages (ui-editor), of static files (files-manage),
              the app's security record (security-admin), and the notification stream's first event
              (notification). Use an account that may read those (the client's owner). A token
              given in MODLIX_SMOKE_TOKEN must come from a sign-in on the same app host: the
              platform revokes a token presented on another app's host.

Nothing is written, except the sign-in's token (and its revoke) when a password is given.
The token and the password are never printed. Standard library only, Python 3.6 or later (the
hosts' python3), so it runs on a host as it is.
"""

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

# Every unit and the gateway pool that sends it traffic (first present wins: locally the Rust
# multi pool is multi-rs, next to the Java one).
POOLS = {
    "security-auth": ["security-auth"],
    "security-internal": ["security-internal"],
    "security-admin": ["security-admin"],
    "core-exec": ["core-exec"],
    "core-editor": ["core-editor"],
    "ui-engine": ["ui-engine"],
    "ui-shell": ["ui-shell"],
    "ui-editor": ["ui-editor"],
    "files-serve": ["files-serve"],
    "files-manage": ["files-manage"],
    "multi": ["multi-rs", "multi"],
    "notification": ["notification"],
}
# Units with no route through the gateway.
NOT_ROUTED = ("core-scheduler", "core-events")

STATIC_RE = re.compile(r"api/files/static/file/[^\"'\s\\)]+?\.(?:png|svg|jpe?g|gif|webp|ico)\b", re.IGNORECASE)
POOL_RE = re.compile(r"^gateway_pool_healthy_instances\{([^}]*)\}\s+(\S+)", re.MULTILINE)
LABEL_RE = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')


class Reply:
    def __init__(self, status: int, headers: Dict[str, str], body: bytes, ms: int) -> None:
        self.status, self.headers, self.body, self.ms = status, headers, body, ms

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except ValueError:
            return None

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "")


class Skip(Exception):
    """The check cannot run here; not a failure."""


class Fail(Exception):
    """The check ran and failed."""


class Smoke:
    def __init__(self, base: str, host: Optional[str], timeout: float, insecure: bool) -> None:
        self.base, self.host, self.timeout, self.insecure = base, host, timeout, insecure
        self.results = []  # type: List[Tuple[str, str, str]]
        self.ctx = ssl.create_default_context()
        if self.insecure:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    # ------------------------------------------------------------ http

    def url(self, path: str) -> str:
        return self.base + (path if path.startswith("/") else "/" + path)

    def headers(self, extra: Optional[Dict[str, str]] = None, app_scoped: bool = True) -> Dict[str, str]:
        h = {"Accept": "application/json, */*", "User-Agent": "modlix-smoke/1"}
        if app_scoped and self.host:
            h["Host"] = self.host
        h.update(extra or {})
        return h

    def call(self, method: str, path: str, *, headers: Optional[Dict[str, str]] = None, body: Any = None,
             app_scoped: bool = True, url: Optional[str] = None) -> Reply:
        h = self.headers(headers, app_scoped)
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(url or self.url(path), data=data, method=method, headers=h)
        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                payload = r.read()
                status, hdrs = r.status, r.headers
        except urllib.error.HTTPError as e:
            payload, status, hdrs = e.read(), e.code, e.headers
        except (urllib.error.URLError, OSError) as e:
            raise Fail(f"{method} {path}: {getattr(e, 'reason', e)}") from None
        ms = int((time.monotonic() - start) * 1000)
        return Reply(status, {k.lower(): v for k, v in hdrs.items()}, payload, ms)

    def first_event(self, path: str, headers: Dict[str, str]) -> Tuple[int, str, int]:
        """Opens an event stream and reads up to its first event; answers the status, the event's
        name (or the error body) and the time to it."""
        h = self.headers(dict(headers, Accept="text/event-stream"))
        req = urllib.request.Request(self.url(path), method="GET", headers=h)
        start = time.monotonic()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as r:
                for _ in range(20):
                    line = r.readline().decode("utf-8", "replace").strip()
                    if line.startswith("event:"):
                        return r.status, line.split(":", 1)[1].strip(), int((time.monotonic() - start) * 1000)
                return r.status, "", int((time.monotonic() - start) * 1000)
        except urllib.error.HTTPError as e:
            return e.code, e.read()[:200].decode("utf-8", "replace"), int((time.monotonic() - start) * 1000)
        except (urllib.error.URLError, OSError) as e:
            raise Fail(f"GET {path}: {getattr(e, 'reason', e)}") from None

    # ------------------------------------------------------------ reporting

    def check(self, name: str, fn: Callable[[], str]) -> bool:
        try:
            status, detail = "OK", fn()
        except Skip as e:
            status, detail = "SKIP", str(e)
        except Fail as e:
            status, detail = "FAIL", str(e)
        except Exception as e:  # noqa: BLE001 - a broken check is a failed check, with its reason
            status, detail = "FAIL", f"{type(e).__name__}: {e}"
        self.line(status, name, detail)
        return status == "OK"

    def line(self, status: str, name: str, detail: str) -> None:
        if status != "INFO":
            self.results.append((status, name, detail))
        print(f"{status:<4}  {name:<30} {detail}", flush=True)


def expect(reply: Reply, *statuses: int, what: str) -> None:
    if reply.status not in statuses:
        snippet = reply.body[:200].decode("utf-8", "replace").replace("\n", " ")
        raise Fail(f"{what}: HTTP {reply.status} ({snippet})")


def kb(n: int) -> str:
    return f"{n / 1024:.0f} KB" if n >= 1024 else f"{n} B"


# ---------------------------------------------------------------- readiness

def readiness(s: Smoke, direct: Dict[str, str]) -> None:
    def gateway() -> str:
        r = s.call("GET", "/readyz", app_scoped=False)
        expect(r, 200, what="/readyz")
        return f"/readyz 200 ({r.ms} ms)"

    s.check("ready gateway-rust", gateway)

    pools = None  # type: Optional[Dict[str, float]]
    metrics_error = ""
    try:
        r = s.call("GET", "/metrics", app_scoped=False)
        if r.status == 200:
            pools = {}
            for labels, value in POOL_RE.findall(r.body.decode("utf-8", "replace")):
                pool = dict(LABEL_RE.findall(labels)).get("pool")
                if pool:
                    pools[pool] = float(value)
        else:
            metrics_error = f"/metrics answered HTTP {r.status}"
    except Fail as e:
        metrics_error = str(e)

    used = set()
    for unit, candidates in POOLS.items():
        def pool_check(unit: str = unit, candidates: List[str] = candidates) -> str:
            pool = next((p for p in candidates if p in (pools or {})), None)
            if pool:
                used.add(pool)
            if unit in direct:
                return direct_ready(s, unit, direct[unit])
            if pools is None:
                raise Fail(f"no pool health ({metrics_error})")
            if pool is None:
                raise Skip(f"the gateway has no pool {' or '.join(candidates)}")
            n = int(pools[pool])
            if n < 1:
                raise Fail(f"pool {pool}: no healthy instance")
            return f"pool {pool}: {n} healthy"

        s.check(f"ready {unit}", pool_check)

    for unit in NOT_ROUTED:
        def routed_check(unit: str = unit) -> str:
            if unit in direct:
                return direct_ready(s, unit, direct[unit])
            raise Skip("no route through the gateway; pass --direct " + unit + "=http://<addr>:<port>")

        s.check(f"ready {unit}", routed_check)

    if pools:
        others = {p: int(n) for p, n in sorted(pools.items()) if p not in used}
        if others:
            s.line("INFO", "other gateway pools", ", ".join(f"{p} {n}" for p, n in others.items()))


def direct_ready(s: Smoke, unit: str, base: str) -> str:
    r = s.call("GET", "/readyz", app_scoped=False, url=base.rstrip("/") + "/readyz")
    expect(r, 200, what=f"{unit} /readyz")
    return f"{base.rstrip('/')}/readyz 200 ({r.ms} ms)"


# ---------------------------------------------------------------- anonymous

class AppInfo:
    def __init__(self) -> None:
        self.app_code = ""
        self.client_code = ""
        self.page = ""
        self.statics = []  # type: List[str]


def anonymous(s: Smoke, page_arg: Optional[str], static_arg: Optional[str]) -> AppInfo:
    info = AppInfo()
    need_host = "needs --host <app host>"

    def app() -> str:
        if not s.host:
            raise Skip(need_host)
        r = s.call("GET", "/api/ui/application")
        expect(r, 200, what="/api/ui/application")
        doc = r.json()
        if not isinstance(doc, dict) or not doc.get("appCode"):
            raise Fail("/api/ui/application: not an application definition")
        info.app_code, info.client_code = doc["appCode"], doc.get("clientCode", "")
        props = doc.get("properties") or {}
        info.page = page_arg or props.get("defaultPage") or ""
        info.statics = STATIC_RE.findall(r.body.decode("utf-8", "replace"))
        return f"{info.app_code} ({info.client_code}), {kb(len(r.body))}, defaultPage {props.get('defaultPage')!r} ({r.ms} ms)"

    app_ok = s.check("app definition (anonymous)", app)

    def page() -> str:
        if not s.host:
            raise Skip(need_host)
        if not app_ok and not page_arg:
            raise Skip("no application definition to name the page")
        if not info.page:
            raise Skip("the app names no defaultPage; pass --page")
        r = s.call("GET", "/api/ui/page/" + urllib.parse.quote(info.page))
        expect(r, 200, what=f"/api/ui/page/{info.page}")
        doc = r.json()
        if not isinstance(doc, dict) or not doc.get("name"):
            raise Fail(f"/api/ui/page/{info.page}: not a page definition")
        info.statics += STATIC_RE.findall(r.body.decode("utf-8", "replace"))
        return f"{doc['name']}, {kb(len(r.body))} ({r.ms} ms)"

    s.check("page (anonymous)", page)

    def shell() -> str:
        if not s.host:
            raise Skip(need_host)
        r = s.call("GET", "/", headers={"Accept": "text/html"})
        expect(r, 200, what="GET /")
        if "html" not in r.content_type.lower():
            raise Fail(f"GET /: content-type {r.content_type!r}, not HTML")
        return f"index page, {kb(len(r.body))} ({r.ms} ms)"

    s.check("index page (anonymous)", shell)

    def function() -> str:
        if not s.host:
            raise Skip(need_host)
        r = s.call("POST", "/api/core/function/execute/System.Math/Add", body={"value": [2, 3]})
        expect(r, 200, what="System.Math.Add")
        out = r.json()
        try:
            value = out[0]["result"]["value"]
        except (TypeError, KeyError, IndexError):
            raise Fail(f"System.Math.Add: unexpected answer {r.body[:200]!r}") from None
        if value != 5:
            raise Fail(f"System.Math.Add: 2 + 3 = {value}")
        return f"System.Math.Add 2 + 3 = 5 ({r.ms} ms)"

    s.check("server function (anonymous)", function)

    def static() -> str:
        if static_arg:
            candidates = [static_arg]
        elif not s.host:
            raise Skip("needs --host <app host> or --static-path")
        else:
            seen = {}  # type: Dict[str, None]
            for c in info.statics:
                seen.setdefault(c, None)
            candidates = sorted(seen, key=lambda c: ("favicon" not in c.lower(), len(c)))[:5]
            if not candidates:
                raise Skip("the app names no static image; pass --static-path")
        failures = []
        for c in candidates:
            path = c if c.startswith("/") else "/" + c
            r = s.call("GET", path, headers={"Accept": "*/*"})
            if r.status == 200 and r.body and "json" not in r.content_type.lower():
                return f"{path}: {kb(len(r.body))} {r.content_type} ({r.ms} ms)"
            failures.append(f"{path} HTTP {r.status}")
        raise Fail("; ".join(failures))

    s.check("static file (anonymous)", static)

    def notification() -> str:
        if not s.host:
            raise Skip(need_host)
        app_code = info.app_code or "nothing"
        r = s.call("GET", f"/api/notification/subscribe?appCode={urllib.parse.quote(app_code)}",
                   headers={"Accept": "text/event-stream"})
        if r.status not in (401, 403):
            raise Fail(f"an anonymous stream should be refused, got HTTP {r.status}")
        code = (r.json() or {}).get("code") if "json" in r.content_type else None
        return f"refused anonymous: HTTP {r.status}{f' {code}' if code else ''} ({r.ms} ms)"

    s.check("notification (anonymous)", notification)
    return info


# ---------------------------------------------------------------- signed in

def signed_in(s: Smoke, info: AppInfo) -> None:
    token = os.environ.get("MODLIX_SMOKE_TOKEN", "").strip()
    user = os.environ.get("MODLIX_SMOKE_USER", "").strip()
    password = os.environ.get("MODLIX_SMOKE_PASSWORD", "")
    codes = {}
    if os.environ.get("MODLIX_SMOKE_CLIENT_CODE"):
        codes["clientCode"] = os.environ["MODLIX_SMOKE_CLIENT_CODE"].strip()
    if os.environ.get("MODLIX_SMOKE_APP_CODE"):
        codes["appCode"] = os.environ["MODLIX_SMOKE_APP_CODE"].strip()
    app_code = codes.get("appCode") or info.app_code
    client_code = codes.get("clientCode") or info.client_code

    if not token and not (user and password):
        s.line("SKIP", "signed in", "set MODLIX_SMOKE_USER and MODLIX_SMOKE_PASSWORD (or MODLIX_SMOKE_TOKEN)")
        return
    if not s.host and not codes:
        s.line("SKIP", "signed in", "needs --host <app host> or MODLIX_SMOKE_CLIENT_CODE / MODLIX_SMOKE_APP_CODE")
        return

    minted = False
    if not token:
        state = {}  # type: Dict[str, str]

        def sign_in() -> str:
            # One attempt only: a refused sign-in counts against the account.
            body = {"userName": user, "password": password, "rememberMe": False}
            if os.environ.get("MODLIX_SMOKE_USER_ID", "").strip():
                body["userId"] = int(os.environ["MODLIX_SMOKE_USER_ID"].strip())
            r = s.call("POST", "/api/security/authenticate", headers=codes, body=body)
            expect(r, 200, what="sign-in")
            body = r.json() or {}
            if not body.get("accessToken"):
                raise Fail("sign-in answered no accessToken")
            state["token"] = body["accessToken"]
            u = body.get("user") or {}
            c = body.get("client") or {}
            return f"user {u.get('id')} of {c.get('code') or u.get('clientId')} ({r.ms} ms)"

        if not s.check("sign-in (security-auth)", sign_in):
            return
        token, minted = state["token"], True

    auth = dict(codes, Authorization=token if token.lower().startswith(("bearer ", "basic ")) else f"Bearer {token}")

    def verify() -> str:
        r = s.call("GET", "/api/security/verifyToken", headers=auth)
        expect(r, 200, what="verifyToken")
        body = r.json() or {}
        u = body.get("user") or {}
        return f"token valid for user {u.get('id')} ({r.ms} ms)"

    s.check("verifyToken (security-auth)", verify)

    def read(name: str, path: str, need_app: bool = True) -> None:
        def run() -> str:
            if need_app and not app_code:
                raise Skip("no app code (no app definition; set MODLIX_SMOKE_APP_CODE)")
            r = s.call("GET", path, headers=auth)
            expect(r, 200, what=path.split("?", 1)[0] + (" (the account may lack the right)" if r.status == 403 else ""))
            doc = r.json()
            if isinstance(doc, dict) and "content" in doc:
                return f"{doc.get('totalElements', len(doc.get('content') or []))} row(s) ({r.ms} ms)"
            return f"{kb(len(r.body))} ({r.ms} ms)"

        s.check(name, run)

    q_app = urllib.parse.urlencode({"appCode": app_code, "clientCode": client_code, "page": 0, "size": 1})
    read("app definition (ui-engine)", "/api/ui/application")
    read("functions page (core-editor)", f"/api/core/functions?{q_app}")
    read("pages page (ui-editor)", f"/api/ui/pages?{q_app}")
    read("static files (files-manage)", "/api/files/static?size=1", need_app=False)
    read("app record (security-admin)", f"/api/security/applications/appCode/{urllib.parse.quote(app_code or 'none')}")

    def stream() -> str:
        if not app_code:
            raise Skip("no app code")
        status, event, ms = s.first_event(f"/api/notification/subscribe?appCode={urllib.parse.quote(app_code)}", auth)
        if status != 200:
            raise Fail(f"HTTP {status} ({event})")
        if event != "init":
            raise Fail(f"opened, but the first event was {event!r}, not 'init'")
        return f"stream opened, first event 'init' ({ms} ms)"

    s.check("notification stream", stream)

    if minted:
        def revoke() -> str:
            r = s.call("GET", "/api/security/revoke", headers=auth)
            expect(r, 200, what="revoke")
            return f"the smoke test's token revoked ({r.ms} ms)"

        s.check("revoke (security-auth)", revoke)


# ---------------------------------------------------------------- main

def parse_direct(values: List[str]) -> Dict[str, str]:
    out = {}
    known = set(POOLS) | set(NOT_ROUTED)
    for v in values:
        unit, sep, url = v.partition("=")
        if not sep or unit not in known or not url.startswith(("http://", "https://")):
            print(f"error: --direct wants UNIT=http://addr:port with UNIT one of {', '.join(sorted(known))}; got {v!r}",
                  file=sys.stderr)
            sys.exit(2)
        out[unit] = url
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("gateway", help="gateway-rust's base URL (http://localhost:8080 on a host, http://localhost:8182 locally)")
    ap.add_argument("--host", help="the app host to load as a browser does (sent as the Host header)")
    ap.add_argument("--page", help="the page to load (default: the app's defaultPage)")
    ap.add_argument("--static-path", help="a static file path to download (default: the first image the app names)")
    ap.add_argument("--direct", action="append", default=[], metavar="UNIT=URL",
                    help="check a unit's /readyz at this address instead of (or, for core-scheduler and core-events, "
                         "as well as) through the gateway; repeatable")
    ap.add_argument("--timeout", type=float, default=20.0, help="seconds per request (default 20)")
    ap.add_argument("--insecure", action="store_true", help="accept a self-signed certificate (https bases only)")
    args = ap.parse_args()

    u = urllib.parse.urlparse(args.gateway)
    if u.scheme not in ("http", "https") or not u.netloc:
        print(f"error: not an http(s) URL: {args.gateway}", file=sys.stderr)
        sys.exit(2)
    s = Smoke(args.gateway.rstrip("/"), args.host, args.timeout, args.insecure)
    print(f"smoke: {s.base}" + (f" as {args.host}" if args.host else "") + f" at {time.strftime('%Y-%m-%d %H:%M:%S %Z')}", flush=True)

    readiness(s, parse_direct(args.direct))
    info = anonymous(s, args.page, args.static_path)
    signed_in(s, info)

    failed = [n for st, n, _ in s.results if st == "FAIL"]
    counts = {st: sum(1 for x, _, _ in s.results if x == st) for st in ("OK", "FAIL", "SKIP")}
    print(f"smoke: {counts['OK']} ok, {counts['FAIL']} failed, {counts['SKIP']} skipped"
          + (f" (failed: {', '.join(failed)})" if failed else ""), flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
