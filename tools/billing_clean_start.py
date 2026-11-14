#!/usr/bin/env python3
"""Billing clean start (V90): empties the old token-billing test data of one environment, so
configs, meters, plans and bundles are entered fresh in the Billing settings tab. There are no
real customers yet (2026-11-14), so nothing is carried over.

Removed: usage records, invoice lines, payments, invoices, credit lots, wallet plans, the wallet
ledger, wallets, bundles, meters, plans and billing configs. Kept: buyers' billing profiles, the
invoice number counters (numbers are never reused), the AI model rates and the billing settings.

    MYSQL_PWD=... tools/billing_clean_start.py --host 127.0.0.1                 # dry run: counts only
    MYSQL_PWD=... tools/billing_clean_start.py --host 127.0.0.1 --apply         # dump, then delete
    MYSQL_PWD=... tools/billing_clean_start.py --host 127.0.0.1 --rollback FILE # restore the dump

Another environment: open a tunnel first (ssh -f -N -L 13306:<env>-mysql...:3306 jumphost) and pass
--host 127.0.0.1 --port 13306 --label <env>, so the dump file is named for the environment.

--apply first writes every row it will delete to ~/billing-clean-start/<host>-<time>.sql (mysqldump,
data only; outside the repo, the rows hold gateway secrets), then deletes in one transaction. --rollback replays that file. Local runs freely;
dev, stage and prod each need Kiran's go for that run.
"""

import argparse
import datetime
import os
import subprocess
import sys

# Children first: each table's rows go before the rows they point at.
TABLES = [
    "security_usage_record",
    "security_invoice_line",
    "security_payment",
    "security_invoice",
    "security_wallet_lot",
    "security_wallet_plan",
    "security_wallet_transaction",
    "security_wallet",
    "security_app_billing_bundle",
    "security_billing_meter",
    "security_billing_plan",
    "security_app_billing_config",
]


def mysql_args(a) -> list[str]:
    return ["-h", a.host, "-P", str(a.port), "-u", a.user]


def query(a, sql: str) -> str:
    r = subprocess.run(["mysql", *mysql_args(a), "-N", "-B", a.db, "-e", sql], capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(r.stderr.strip())
    return r.stdout.strip()


def present(a) -> list[str]:
    """TABLES that exist here, in TABLES order: an environment before V90 has no meter/plan/lot/usage tables."""
    have = set(query(a, "SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE()").split())
    return [t for t in TABLES if t in have]


def counts(a, tables) -> dict[str, int]:
    return {t: int(query(a, f"SELECT COUNT(*) FROM `{t}`") or 0) for t in tables}


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, default=3306)
    p.add_argument("--user", default="root")
    p.add_argument("--db", default="security")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--rollback", metavar="FILE")
    p.add_argument("--label", help="name used in the dump file (default: the host)")
    a = p.parse_args()
    if "MYSQL_PWD" not in os.environ:
        sys.exit("Set MYSQL_PWD (never pass the password on the command line).")

    if a.rollback:
        with open(a.rollback, "rb") as f:
            r = subprocess.run(["mysql", *mysql_args(a), a.db], stdin=f)
        print("restored" if r.returncode == 0 else "restore FAILED")
        return r.returncode

    tables = present(a)
    missing = [t for t in TABLES if t not in tables]
    if missing:
        print("not here (skipped): " + ", ".join(missing))
    before = counts(a, tables)
    width = max(len(t) for t in tables)
    for t in tables:
        print(f"{t:<{width}}  {before[t]:>9}")
    if not a.apply:
        print("dry run: nothing changed (add --apply to dump and delete)")
        return 0

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = os.path.expanduser("~/billing-clean-start")
    os.makedirs(out, mode=0o700, exist_ok=True)
    dump = os.path.join(out, f"{a.label or a.host}-{stamp}.sql")
    with open(os.open(dump, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
        r = subprocess.run(
            ["mysqldump", *mysql_args(a), "--no-create-info", "--skip-triggers", "--single-transaction",
             "--complete-insert", "--set-gtid-purged=OFF", a.db, *reversed(tables)],
            stdout=f,
        )
    if r.returncode != 0:
        sys.exit(f"dump failed; nothing deleted ({dump} may be partial)")
    print(f"dump: {dump}")

    deletes = " ".join(f"DELETE FROM `{t}`;" for t in tables)
    query(a, f"START TRANSACTION; {deletes} COMMIT;")
    after = counts(a, tables)
    left = {t: n for t, n in after.items() if n}
    print("done" if not left else f"rows left: {left}")
    return 0 if not left else 1


if __name__ == "__main__":
    sys.exit(main())
