#!/usr/bin/env bash
# Runs a Rust unit against the local stack: tools/run-local.sh <binary> [--release]
#
# The units take their configuration from the local Lighthouse pair (8761, 8762): no TOML file and
# no secrets of their own, only LIGHTHOUSE_URLS and the token. Lighthouse serves each unit its
# config/<unit>.toml with the passwords and keys of config/local.toml (config/lighthouse.toml,
# [config.local]), so start Lighthouse first. LIGHTHOUSE=off runs a unit from config/<binary>.toml
# alone (no secrets: for a unit that needs none, or with MODLIX__ variables you set yourself).
#
# Lighthouse itself reads config/lighthouse.toml; its admin token is [lighthouse] admin_token in
# config/local.toml. For the second instance:
#   MODLIX__SERVER__PORT=8762 MODLIX__REGISTRY__SELF_URL=http://localhost:8762 tools/run-local.sh lighthouse
set -euo pipefail
cd "$(dirname "$0")/.."
bin="$1"; shift || true
profile="debug"; [[ "${1:-}" == "--release" ]] && profile="release"

# config/local.toml's admin token ([lighthouse] admin_token), or nothing.
admin_token() {
  [[ -f config/local.toml ]] || return 0
  python3 -c 'import sys, tomllib; print(tomllib.load(open(sys.argv[1], "rb")).get("lighthouse", {}).get("admin_token", ""), end="")' config/local.toml
}

# kirun dates follow the process locale as the JVM's do; the local Java core ran as en_IN.
export KIRUN_LOCALE="${KIRUN_LOCALE:-en_IN}"

if [[ "$bin" == "lighthouse" ]]; then
  token="$(admin_token)"
  if [[ -n "$token" ]]; then
    MODLIX__ADMIN_TOKEN_SHA256="$(printf '%s' "$token" | shasum -a 256 | cut -d' ' -f1)"
    export MODLIX__ADMIN_TOKEN_SHA256
  fi
  export MODLIX__REGISTRY__PEERS="${MODLIX__REGISTRY__PEERS:-[\"http://localhost:8761\",\"http://localhost:8762\"]}"
elif [[ "${LIGHTHOUSE:-on}" == "off" ]]; then
  :
else
  LIGHTHOUSE_TOKEN="$(admin_token)"
  if [[ -z "$LIGHTHOUSE_TOKEN" ]]; then
    echo "[lighthouse] admin_token is not in config/local.toml (or run with LIGHTHOUSE=off)" >&2
    exit 1
  fi
  export LIGHTHOUSE_TOKEN
  export LIGHTHOUSE_URLS="${LIGHTHOUSE_URLS:-http://localhost:8761,http://localhost:8762}"
  export LIGHTHOUSE_REQUIRED=true
  export CONFIG_FILE=none
fi
exec "target/$profile/$bin"
