#!/usr/bin/env bash
# Restarts a Rust unit on the local stack: tools/restart-local.sh <binary> <port> [logfile]
# Stops whichever of this repo's binaries (release or debug build) holds the port, waits for it to
# drain and free the port, starts the release build, and checks that the new process is the one
# answering.
set -euo pipefail
cd "$(dirname "$0")/.."
bin="$1"; port="$2"; log="${3:-/tmp/$bin.log}"
repo="$(pwd)"

# Stale build outputs pile up in target/ (tens of GB a week); sweep them at most once a day, in the
# background, so a restart never waits on it. SWEEP=off skips it.
sweep_stale_builds() {
  [[ "${SWEEP:-on}" == "off" ]] && return 0
  local stamp="target/.last-sweep"
  [[ -n "$(find "$stamp" -mtime -1 2>/dev/null)" ]] && return 0
  touch "$stamp"
  nohup nice -n 19 python3 tools/sweep_target.py > /tmp/sweep-target.log 2>&1 &
}

# Only what holds THIS port: several copies of one binary can run on different ports (the two
# local gateways), so a name-wide pkill would stop the others too.
for pid in $(lsof -tiTCP:"$port" -sTCP:LISTEN 2>/dev/null || true); do
  # Only ever stop this repo's own binaries; anything else on the port is reported, not killed.
  if ps -o command= -p "$pid" | grep -q "^$repo/target/\|^target/"; then kill "$pid" || true; fi
done
for _ in $(seq 1 60); do lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 0.5; done
if lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port $port is still in use by:" >&2
  lsof -iTCP:"$port" -sTCP:LISTEN >&2
  exit 1
fi

nohup tools/run-local.sh "$bin" --release > "$log" 2>&1 &
for _ in $(seq 1 60); do
  if curl -sf "localhost:$port/healthz" >/dev/null 2>&1; then
    holder="$(lsof -tiTCP:"$port" -sTCP:LISTEN | head -1)"
    if ps -o command= -p "$holder" | grep -q "target/release/$bin"; then sweep_stale_builds; exit 0; fi
    echo "port $port answers, but not from target/release/$bin (pid $holder)" >&2; exit 1
  fi
  sleep 0.5
done
echo "$bin did not come up; see $log" >&2; tail -20 "$log" >&2; exit 1
