#!/usr/bin/env bash
# Applies sql/<database>/V<n>__*.sql to one environment's MySQL with Flyway, for rust-build-deploy.yml.
# Each database keeps what ran in its flyway_schema_history (the Java services filled it until the move),
# so Flyway carries on from there; sql/README.md has the rules for writing a change.
#
#   tools/ci_sql.sh ship <plan|migrate>
#       On the self-hosted runner, from the repository root. Copies sql/ and this script to the host
#       (ENV_NAME, SSH_KEY, SERVER_IP, TAG) and runs `run` there. The database user and password
#       (DB_USER, DB_PASSWORD) go over the SSH session's stdin: never a file, never a command line.
#       plan writes pending=<count> to $GITHUB_OUTPUT when it is set.
#
#   tools/ci_sql.sh run <plan|migrate> <dir> <mysql host>
#       Where Docker runs (the host, or a laptop against local MySQL), with FLYWAY_USER and
#       FLYWAY_PASSWORD set. plan checks every applied file is unchanged and lists what is pending;
#       migrate applies the pending files, database by database, creating a database that is missing.

set -euo pipefail

IMAGE=flyway/flyway:13.8.1
# Every folder under sql/ but rollback/ is one database.
databases() { find "$1" -mindepth 1 -maxdepth 1 -type d ! -name rollback -exec basename {} \; | sort; }

flyway() {
  local dir=$1 host=$2 db=$3
  shift 3
  docker run --rm \
    -e FLYWAY_USER -e FLYWAY_PASSWORD -e REDGATE_DISABLE_TELEMETRY=true \
    -v "$dir/$db:/flyway/sql:ro" \
    "$IMAGE" \
    -url="jdbc:mariadb://$host:3306/" \
    -schemas="$db" \
    -locations=filesystem:/flyway/sql \
    -table=flyway_schema_history \
    -placeholderReplacement=false \
    "$@" </dev/null
}

# The info table without the rows that already ran.
not_applied() { grep -E '^\| (Category|Versioned|Repeatable|Baseline)' | grep -v '| Success ' || true; }

run() {
  local mode=$1 dir=$2 host=$3 total=0 db out pending
  : "${FLYWAY_USER:?FLYWAY_USER is not set}" "${FLYWAY_PASSWORD:?FLYWAY_PASSWORD is not set}"
  for db in $(databases "$dir"); do
    echo "::group::$db"
    if [ "$mode" = migrate ]; then
      flyway "$dir" "$host" "$db" migrate
    else
      # An edited, missing or failed migration stops the deploy here, before anything is applied.
      flyway "$dir" "$host" "$db" "-ignoreMigrationPatterns=*:pending" validate
    fi
    out="$(flyway "$dir" "$host" "$db" info)"
    pending="$(grep -c '| Pending ' <<< "$out" || true)"
    total=$((total + pending))
    echo "$db: $pending pending"
    not_applied <<< "$out"
    echo "::endgroup::"
  done
  echo "pending=$total"
}

ship() {
  local mode=$1
  : "${ENV_NAME:?}" "${SSH_KEY:?}" "${SERVER_IP:?}" "${TAG:?}"
  if [ -z "${DB_USER:-}" ] || [ -z "${DB_PASSWORD:-}" ]; then
    echo "::error::the database user or password secret for $ENV_NAME is not set: the SQL cannot be checked or applied"
    exit 1
  fi
  local dir="/home/opc/rust/sql-ci/$TAG" host="$ENV_NAME-mysql.sub10150624021.modlixvcn.oraclevcn.com" out
  tar -cz sql tools/ci_sql.sh | \
    ssh -i "$SSH_KEY" -o BatchMode=yes "opc@$SERVER_IP" "rm -rf '$dir' && mkdir -p '$dir' && tar -xz -C '$dir'"
  out="$(printf '%s\n%s\n' "$DB_USER" "$DB_PASSWORD" | \
    ssh -i "$SSH_KEY" -o BatchMode=yes "opc@$SERVER_IP" \
    "IFS= read -r FLYWAY_USER; IFS= read -r FLYWAY_PASSWORD; export FLYWAY_USER FLYWAY_PASSWORD; trap \"rm -rf '$dir'\" EXIT; bash '$dir/tools/ci_sql.sh' run $mode '$dir/sql' '$host'" | tee /dev/stderr)"
  if [ "$mode" = plan ] && [ -n "${GITHUB_OUTPUT:-}" ]; then
    grep -E '^pending=[0-9]+$' <<< "$out" | tail -1 >> "$GITHUB_OUTPUT"
  fi
}

case "${1:-}" in
  ship) ship "${2:?plan or migrate}" ;;
  run) run "${2:?plan or migrate}" "${3:?sql folder}" "${4:?mysql host}" ;;
  *) echo "usage: $0 ship <plan|migrate> | run <plan|migrate> <dir> <mysql host>" >&2; exit 2 ;;
esac
