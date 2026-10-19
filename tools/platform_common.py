"""What tools/seed_platform_app.py and tools/make_platform_transport.py share: the seed file,
the LOCAL-only guard, the token, and the HTTP calls (standard library only).

LOCAL only. A base URL is accepted when its host is `localhost`, a loopback address, or a
name that resolves to loopback addresses only (`apps.local.modlix.com` on a developer
machine). Anything else is refused before a request is made.

The token, in this order:
  1. MODLIX_LOCAL_TOKEN in the environment;
  2. MODLIX_TOKEN in modlix-mcp/.env, when that file's MODLIX_GATEWAY_URL is local too;
  3. a sign-in with MODLIX_LOCAL_PASSWORD from ~/.nocode-saas/variables.sh (the user
     app-transport.sh signs in as on local), only when that password is set.
The token is never printed.
"""

from __future__ import annotations

import ipaddress
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SEED_FILE = HERE / "platform_seed" / "definitions.json"
DEFAULT_BASE_URL = "https://apps.local.modlix.com"
MCP_ENV = Path("/Users/kirangrandhi/kiran/fincity/modlix-mcp/.env")
VARIABLES = Path.home() / ".nocode-saas" / "variables.sh"

# The builder app the API calls run under, as the UI and app-transport.sh do.
CONTEXT_APP = "appbuilder"
AUTH_CLIENT = "SYSTEM"
LOCAL_USER = ("kiran@modlix.com", 142)

KINDS = (
    # (core route, transport folder, seed key)
    ("functions", "Function", "functions"),
    ("eventDefinitions", "EventDefinition", "eventDefinitions"),
    ("eventActions", "EventAction", "eventActions"),
)

# The jobs the seed carries: the worker's 11 less ENTITY_PROCESSOR_METERING (entity-processor
# retired with the switch to Rust, 2026-10-18). A seed with any other count is refused, so a job
# lost by an edit is caught before anything is written or exported.
EXPECTED_JOBS = 10

# Fields core manages on every document; never compared, never sent on a create.
MANAGED = {"id", "_id", "version", "createdAt", "createdBy", "updatedAt", "updatedBy", "uniqueName", "baseClientCode", "message"}


def die(msg: str) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def info(msg: str) -> None:
    print(msg, file=sys.stderr)


# ---------------------------------------------------------------- the seed

def load_seed() -> dict[str, Any]:
    seed = json.loads(SEED_FILE.read_text())
    check_seed(seed)
    return seed


def check_seed(seed: dict[str, Any]) -> None:
    """The file is what the Rust test checks: EXPECTED_JOBS jobs, one function, definition and action each."""
    app = seed["app"]
    if (app.get("appCode"), app.get("clientCode")) != ("platform", "SYSTEM"):
        die("definitions.json is not for app platform / SYSTEM")
    names = [j["name"] for j in seed["jobs"]]
    if len(names) != EXPECTED_JOBS or len(set(names)) != EXPECTED_JOBS:
        die(f"definitions.json should hold {EXPECTED_JOBS} distinct jobs, has {names}")
    for key, prefix in (("functions", "Platform.Jobs."), ("eventDefinitions", ""), ("eventActions", "")):
        got = sorted(d["name"] for d in seed[key])
        if got != sorted(prefix + n for n in names):
            die(f"definitions.json {key} do not match the jobs: {got}")
        for d in seed[key]:
            if (d.get("appCode"), d.get("clientCode")) != ("platform", "SYSTEM"):
                die(f"definitions.json {key} {d['name']} is not platform / SYSTEM")


# ---------------------------------------------------------------- local only

def require_local(base_url: str) -> str:
    u = urllib.parse.urlparse(base_url)
    if u.scheme not in ("http", "https") or not u.hostname:
        die(f"not an http(s) URL: {base_url}")
    host = u.hostname
    if host != "localhost":
        try:
            addrs = {ipaddress.ip_address(host)}
        except ValueError:
            try:
                addrs = {ipaddress.ip_address(a[4][0]) for a in socket.getaddrinfo(host, u.port or 443)}
            except OSError as e:
                die(f"cannot resolve {host}: {e}")
        if not addrs or not all(a.is_loopback for a in addrs):
            die(f"{base_url} is not local ({host} -> {', '.join(sorted(map(str, addrs)))}); this tool runs against LOCAL only")
    return base_url.rstrip("/")


def _ssl_context() -> ssl.SSLContext:
    # The local stack's certificate is self-signed; only loopback hosts get here.
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _env_file(path: Path) -> dict[str, str]:
    vals: dict[str, str] = {}
    if not path.is_file():
        return vals
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip().removeprefix("export ").strip()
        vals[k] = v.strip().strip('"').strip("'")
    return vals


def _is_local_url(url: str) -> bool:
    try:
        u = urllib.parse.urlparse(url)
        if u.hostname == "localhost":
            return True
        return bool(u.hostname) and all(
            ipaddress.ip_address(a[4][0]).is_loopback for a in socket.getaddrinfo(u.hostname, u.port or 443))
    except (OSError, ValueError):
        return False


class Api:
    """The local gateway, as the signed-in SYSTEM user."""

    def __init__(self, base_url: str, token: str | None):
        self.base = base_url
        self.token = token
        self.ctx = _ssl_context()

    @classmethod
    def connect(cls, base_url: str, need_token: bool = True) -> "Api":
        api = cls(require_local(base_url), None)
        api.token = api._token(need_token)
        return api

    def _token(self, need: bool) -> str | None:
        tok = os.environ.get("MODLIX_LOCAL_TOKEN", "").strip()
        if tok:
            info("token: MODLIX_LOCAL_TOKEN")
            return tok
        env = _env_file(MCP_ENV)
        if env.get("MODLIX_TOKEN") and _is_local_url(env.get("MODLIX_GATEWAY_URL", "")):
            info(f"token: {MCP_ENV} (gateway {env.get('MODLIX_GATEWAY_URL')})")
            return env["MODLIX_TOKEN"]
        pw = _env_file(VARIABLES).get("MODLIX_LOCAL_PASSWORD", "")
        if pw:
            info(f"token: signing in on local as {LOCAL_USER[0]}")
            st, body = self.call("POST", "/api/security/authenticate",
                                 {"userName": LOCAL_USER[0], "userId": LOCAL_USER[1], "password": pw}, auth=False)
            if st == 200 and isinstance(body, dict) and body.get("accessToken"):
                return body["accessToken"]
            die(f"sign-in on local failed (HTTP {st})")
        if need:
            die("no local token: set MODLIX_LOCAL_TOKEN, or have modlix-mcp/.env point at local, "
                "or MODLIX_LOCAL_PASSWORD in ~/.nocode-saas/variables.sh")
        return None

    def headers(self, auth: bool = True) -> dict[str, str]:
        h = {"appCode": CONTEXT_APP, "clientCode": AUTH_CLIENT, "Accept": "application/json"}
        if auth and self.token:
            t = self.token
            h["Authorization"] = t if t.lower().startswith(("bearer ", "basic ")) else f"Bearer {t}"
        return h

    def call(self, method: str, path: str, body: Any = None, params: dict[str, Any] | None = None,
             auth: bool = True, raw: bool = False) -> tuple[int, Any]:
        url = self.base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        data = None
        h = self.headers(auth)
        if body is not None:
            data = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=300) as r:
                payload = r.read()
                status = r.status
        except urllib.error.HTTPError as e:
            payload = e.read()
            status = e.code
        except urllib.error.URLError as e:
            die(f"{method} {path}: {e.reason}")
        if raw:
            return status, payload
        if not payload:
            return status, None
        try:
            return status, json.loads(payload)
        except ValueError:
            return status, payload.decode("utf-8", "replace")


# ---------------------------------------------------------------- comparing

def contains(expected: Any, actual: Any) -> bool:
    """Every field `expected` has, `actual` has with the same value (numbers by value)."""
    if isinstance(expected, dict):
        return isinstance(actual, dict) and all(k in actual and contains(v, actual[k]) for k, v in expected.items())
    if isinstance(expected, list):
        return isinstance(actual, list) and len(expected) == len(actual) and all(map(contains, expected, actual))
    if isinstance(expected, bool) or isinstance(actual, bool):
        return expected is actual or expected == actual and type(expected) is type(actual)
    if isinstance(expected, (int, float)) and isinstance(actual, (int, float)):
        return float(expected) == float(actual)
    return expected == actual


def differences(expected: Any, actual: Any, path: str = "") -> list[str]:
    """Where `actual` does not contain `expected`, as paths."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        out: list[str] = []
        for k, v in expected.items():
            if k not in actual:
                out.append(f"{path}.{k} missing")
            else:
                out.extend(differences(v, actual[k], f"{path}.{k}"))
        return out
    return [] if contains(expected, actual) else [f"{path or '.'}: want {json.dumps(expected)[:120]}, have {json.dumps(actual)[:120]}"]


def comparable(doc: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in doc.items() if k not in MANAGED}
