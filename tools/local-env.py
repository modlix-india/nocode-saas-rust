#!/usr/bin/env python3
"""Prints config/local.toml's [units.*] as `export MODLIX__<SECTION>__<KEY>='value'` lines, for the
gated live tests that read the local secrets from their environment:

    eval "$(tools/local-env.py)"; SECURITY_AUTH_LIVE=1 cargo test -p security ...

The units themselves never need this: Lighthouse merges the same table into their documents.
"""
import shlex
import sys
import tomllib
from pathlib import Path

path = Path(__file__).resolve().parent.parent / "config" / "local.toml"
if not path.exists():
    sys.exit(f"{path} is missing")
units = tomllib.loads(path.read_text()).get("units", {})


def walk(table, parts):
    for key, value in table.items():
        if isinstance(value, dict):
            walk(value, parts + [key])
        else:
            name = "MODLIX__" + "__".join(p.upper() for p in parts + [key])
            text = ("true" if value else "false") if isinstance(value, bool) else str(value)
            print(f"export {name}={shlex.quote(text)}")


walk(units, [])
