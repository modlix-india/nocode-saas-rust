#!/usr/bin/env python3
"""Copies an environment's secrets from the Java settings (oci-config) into its OCI Vault.

Usage: vault_secrets.py <oci-config-dir> <env> [--apply]
       env: dev, stage or prod. Without --apply it only reports, by name, what it would do.

The values come from `lighthouse render` (the same rendering the units' env files use), so a
secret here is byte for byte what the units read today. It runs target/release/lighthouse, or
the binary LIGHTHOUSE_BIN names. Each secret is stored without an
environment prefix (one vault per environment, decided 2026-10-19): `security-db-password`,
`jwt-key`, ... Lighthouse resolves `{vault:<name>}` references against these in phase 3.

Nothing prints a value. Values reach the OCI CLI through a 0600 file in a private temporary
directory, never on a command line, and the directory is removed afterwards. A secret that
already holds the same value (compared by SHA-256) is left alone; a changed one gets a new
version; an empty or unset value is skipped and reported by name.
"""
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent

# Vault per environment: (compartment, vault display name, key display name).
VAULTS = {
    "dev": ("non-prod", "modlix-dev", "modlix-dev-key"),
    "stage": ("non-prod", "modlix-stage", "modlix-stage-key"),
    "prod": ("prod", "modlix-prod", "modlix-prod-key"),
}

# Secret name per rendered variable: (file, variable) -> secret name. Only secrets; plain
# settings (URLs, flags, model names) stay in oci-config.
SECRETS = {
    ("rust", "MODLIX__REDIS__URL"): "redis-url",
    ("rust", "MODLIX__JWT__KEY"): "jwt-key",
    ("rust", "MODLIX__MQ__URI"): "mq-uri",
    ("rust", "MODLIX__SMS__TWO_FACTOR_API_KEY"): "sms-two-factor-api-key",
    ("rust", "MODLIX__STORAGE__ACCESS_KEY_ID"): "storage-access-key-id",
    ("rust", "MODLIX__STORAGE__SECRET_ACCESS_KEY"): "storage-secret-access-key",
    ("rust", "MODLIX__SHELL__ANALYTICS_ENGINE_SECRET"): "analytics-engine-secret",
    ("rust", "MODLIX__EDITOR__APPLE_API_KEY_ID"): "apple-api-key-id",
    ("rust", "MODLIX__EDITOR__APPLE_API_ISSUER_ID"): "apple-api-issuer-id",
    ("rust", "MODLIX__EDITOR__APPLE_API_KEY_CONTENT"): "apple-api-key-content",
    ("rust", "SECURITY_DB_PASSWORD"): "security-db-password",
    ("rust", "CORE_DB_PASSWORD"): "core-db-password",
    ("rust", "FILES_DB_PASSWORD"): "files-db-password",
    ("rust", "NOTIFICATION_DB_PASSWORD"): "notification-db-password",
    ("rust", "CORE_MONGO_URI"): "core-mongo-uri",
    ("rust", "UI_MONGO_URI"): "ui-mongo-uri",
    ("ai", "ANTHROPIC_API_KEY"): "ai-anthropic-api-key",
    ("ai", "OPENAI_API_KEY"): "ai-openai-api-key",
    ("ai", "DEEPSEEK_API_KEY"): "ai-deepseek-api-key",
    ("ai", "MINIMAX_API_KEY"): "ai-minimax-api-key",
    ("ai", "GOOGLE_API_KEY"): "ai-google-api-key",
    ("ai", "GOOGLE_MAPS_API_KEY"): "ai-google-maps-api-key",
    ("ai", "SCRAPECREATORS_API_KEY"): "ai-scrapecreators-api-key",
    ("ai", "REDIS_URL"): "ai-redis-url",
    ("ai", "MYSQL_PASSWORD"): "ai-db-password",
    ("ai", "ADZUMP_GOOGLE_ADS_DEVELOPER_TOKEN"): "adzump-google-ads-developer-token",
    ("ai", "ADZUMP_GOOGLE_ADS_ACCESS_TOKEN"): "adzump-google-ads-access-token",
    ("ai", "ADZUMP_GOOGLE_ADS_REFRESH_TOKEN"): "adzump-google-ads-refresh-token",
    ("ai", "ADZUMP_GOOGLE_ADS_CLIENT_ID"): "adzump-google-ads-client-id",
    ("ai", "ADZUMP_GOOGLE_ADS_CLIENT_SECRET"): "adzump-google-ads-client-secret",
    ("ai", "ADZUMP_META_ACCESS_TOKEN"): "adzump-meta-access-token",
    ("ssr", "REDIS_URL"): "ssr-redis-url",
    ("ssr", "REDIS_INVALIDATION_URL"): "ssr-redis-invalidation-url",
}


def unquote(raw):
    """The value of a rendered env line: `'v'` literally, `"v"` with its backslash escapes undone."""
    if len(raw) >= 2 and raw[0] == raw[-1] == "'":
        return raw[1:-1]
    if len(raw) >= 2 and raw[0] == raw[-1] == '"':
        out, i, body = [], 0, raw[1:-1]
        while i < len(body):
            if body[i] == "\\" and i + 1 < len(body) and body[i + 1] in '\\"$n':
                out.append("\n" if body[i + 1] == "n" else body[i + 1])
                i += 2
            else:
                out.append(body[i])
                i += 1
        return "".join(out)
    return raw


def env_file(path):
    """{NAME: value} of a rendered env file; a missing file is empty."""
    if not path.exists():
        return {}
    values = {}
    for line in path.read_text().splitlines():
        if line.lstrip().startswith("#") or "=" not in line:
            continue
        name, raw = line.split("=", 1)
        values[name] = unquote(raw)
    return values


def rendered_values(oci_dir, env):
    """{(file, variable): value} for every variable in SECRETS, as the units' env files hold it."""
    binary = os.environ.get("LIGHTHOUSE_BIN") or str(HERE.parent / "target" / "release" / "lighthouse")
    tmp = Path(tempfile.mkdtemp(prefix="vault-render-"))
    try:
        os.chmod(tmp, 0o700)
        # Exit 1 means a required value is missing somewhere: the files are written all the same,
        # and a missing secret is reported by name below.
        res = subprocess.run([binary, "render", str(oci_dir), env, str(tmp / "out")], capture_output=True, text=True)
        if res.returncode not in (0, 1):
            sys.exit(f"lighthouse render failed ({res.returncode}): {res.stderr.strip()[:500]}")
        out_dir = tmp / "out"
        files = {"rust": env_file(out_dir / "rust-units.env"), "ai": env_file(out_dir / "ai.env"), "ssr": env_file(out_dir / "ssr.env")}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {(f, var): files[f].get(var) for (f, var) in SECRETS}


def oci(*args, input_file=None):
    cmd = ["oci", *args]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        # The CLI's error text carries no secret content (values never go on the command line).
        msg = res.stderr.strip().splitlines()[-1] if res.stderr.strip() else "unknown error"
        raise RuntimeError(f"oci {' '.join(args[:4])}: {msg[:200]}")
    return json.loads(res.stdout) if res.stdout.strip() else None


def tenancy():
    cfg = Path.home() / ".oci" / "config"
    for line in cfg.read_text().splitlines():
        if line.strip().startswith("tenancy"):
            return line.split("=", 1)[1].strip()
    raise RuntimeError("no tenancy in ~/.oci/config")


def compartment_id(name):
    data = oci("iam", "compartment", "list", "--compartment-id", tenancy(), "--all")["data"]
    for c in data:
        if c["name"] == name and c["lifecycle-state"] == "ACTIVE":
            return c["id"]
    raise RuntimeError(f"no compartment {name}")


def vault_and_key(env):
    comp_name, vault_name, key_name = VAULTS[env]
    comp = compartment_id(comp_name)
    vaults = oci("kms", "management", "vault", "list", "--compartment-id", comp, "--all")["data"]
    vault = next((v for v in vaults if v["display-name"] == vault_name and v["lifecycle-state"] == "ACTIVE"), None)
    if not vault:
        raise RuntimeError(f"vault {vault_name} is not ACTIVE in {comp_name}")
    keys = oci("kms", "management", "key", "list", "--compartment-id", comp, "--all",
               "--endpoint", vault["management-endpoint"])["data"]
    key = next((k for k in keys if k["display-name"] == key_name and k["lifecycle-state"] == "ENABLED"), None)
    if not key:
        raise RuntimeError(f"key {key_name} is not ENABLED in vault {vault_name}")
    return comp, vault["id"], key["id"]


def existing_secrets(comp, vault_id):
    data = oci("vault", "secret", "list", "--compartment-id", comp, "--vault-id", vault_id, "--all")
    return {s["secret-name"]: s["id"] for s in (data or {}).get("data", []) if s["lifecycle-state"] == "ACTIVE"}


def current_digest(secret_id):
    data = oci("secrets", "secret-bundle", "get", "--secret-id", secret_id)
    content = data["data"]["secret-bundle-content"]["content"]
    return hashlib.sha256(base64.b64decode(content)).hexdigest()


def write_secret(tmp, comp, vault_id, key_id, name, value, secret_id):
    body = base64.b64encode(value.encode()).decode()
    path = Path(tmp) / f"{name}.json"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        if secret_id:
            json.dump({"secretId": secret_id, "secretContentContent": body}, f)
        else:
            json.dump({"compartmentId": comp, "vaultId": vault_id, "keyId": key_id, "secretName": name,
                       "secretContentContent": body,
                       "description": "Copied from oci-config by tools/vault_secrets.py"}, f)
    try:
        if secret_id:
            oci("vault", "secret", "update-base64", "--from-json", f"file://{path}", "--force")
        else:
            oci("vault", "secret", "create-base64", "--from-json", f"file://{path}")
    finally:
        path.unlink(missing_ok=True)


def main(argv):
    args = [a for a in argv[1:] if not a.startswith("--")]
    if len(args) != 2 or args[1] not in VAULTS:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    oci_dir, env = args
    apply = "--apply" in argv
    values = rendered_values(oci_dir, env)
    comp, vault_id, key_id = vault_and_key(env)
    existing = existing_secrets(comp, vault_id)
    plan = {"create": [], "update": [], "same": [], "empty": []}
    tmp = tempfile.mkdtemp(prefix="vault-")
    os.chmod(tmp, 0o700)
    try:
        for (f, var), name in SECRETS.items():
            value = values.get((f, var))
            if value is None or str(value) == "":
                plan["empty"].append(name)
                continue
            value = str(value)
            sid = existing.get(name)
            if sid and current_digest(sid) == hashlib.sha256(value.encode()).hexdigest():
                plan["same"].append(name)
                continue
            plan["update" if sid else "create"].append(name)
            if apply:
                write_secret(tmp, comp, vault_id, key_id, name, value, sid)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    verb = "Did" if apply else "Would"
    print(f"{env}: vault {VAULTS[env][1]} ({'applied' if apply else 'dry run'})")
    for k in ("create", "update", "same", "empty"):
        label = {"create": f"{verb} create", "update": f"{verb} add a version", "same": "Unchanged", "empty": "Empty in oci-config, skipped"}[k]
        print(f"  {label}: {len(plan[k])}" + (f": {', '.join(plan[k])}" if plan[k] else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
