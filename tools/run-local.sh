#!/usr/bin/env bash
# Runs a Rust unit against the local stack: tools/run-local.sh <binary> [--release]
# Reads config/<binary>.toml and the secrets in config/local.env.
set -euo pipefail
cd "$(dirname "$0")/.."
bin="$1"; shift || true
profile="debug"; [[ "${1:-}" == "--release" ]] && profile="release"
set -a; [[ -f config/local.env ]] && source config/local.env; set +a
exec "target/$profile/$bin"
