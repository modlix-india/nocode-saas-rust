#!/usr/bin/env bash
# Regenerates crates/appdata/tests/fixtures/java_oracle.json from the Java builders.
# Needs ../nocode-saas/commons-core built (target/classes) and its Maven deps in ~/.m2.
# Read-only: compiles and runs a local Java program, touches no database.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../.." && pwd)"
java_repo="$(cd "$root/../nocode-saas" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
(cd "$java_repo/commons-core" && mvn -o -q dependency:build-classpath -Dmdep.outputFile="$work/cp.txt")
cp="$(cat "$work/cp.txt"):$java_repo/commons-core/target/classes:$java_repo/core/target/classes"
python3 "$here/make_cases.py" "$root/crates/appdata/tests/fixtures/java_oracle_cases.json"
javac -d "$work" -cp "$cp" "$here/Oracle.java"
java -Dorg.jooq.no-logo=true -Dorg.jooq.no-tips=true -cp "$cp:$work" Oracle \
  "$root/crates/appdata/tests/fixtures/java_oracle_cases.json" "$root/crates/appdata/tests/fixtures/java_oracle.json" >/dev/null 2>&1
echo "wrote crates/appdata/tests/fixtures/java_oracle.json"
