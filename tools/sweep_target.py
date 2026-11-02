#!/usr/bin/env python3
"""Removes stale build outputs from target/: tools/sweep_target.py [--days N] [--dry-run]

Every feature set, `-p` selection and source change leaves a new hashed copy of a unit in
target/<profile>/deps and a new crate folder in target/<profile>/incremental; cargo never removes the
old ones, so target/ grows by tens of GB a week. A unit is stale when none of its files was read or
written for --days days (default 2, or SWEEP_DAYS): rustc reads every rlib it links against, so a
unit any current build uses keeps a fresh access time. Removing a unit that is still valid only costs
a rebuild of that unit: cargo sees the missing output and compiles it again.

Safe beside running builds and other sessions: it skips anything touched inside the window, never
touches the top-level binaries the local units run from (target/release/<bin>), and leaves build/
(build-script outputs, small) alone.
"""
import argparse
import os
import re
import shutil
import sys
import time
from collections import defaultdict
from pathlib import Path

# lib<name>-<hash>.rlib, <name>-<hash> (test/bin), <name>-<hash>.d, <name>-<hash>.dSYM, *.rcgu.o ...
UNIT = re.compile(r"^(?:lib)?(?P<name>.+?)-(?P<hash>[0-9a-f]{16})(?:\..*)?$")


def last_used(path: Path) -> float:
    st = path.lstat()
    return max(st.st_atime, st.st_mtime)


def disk_usage(st: os.stat_result) -> int:
    # Only the last link to an inode frees anything: cargo hard-links binaries into target/<profile>/.
    return st.st_blocks * 512 if st.st_nlink == 1 else 0


def size_of(path: Path) -> int:
    if path.is_symlink() or not path.is_dir():
        return disk_usage(path.lstat())
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += disk_usage(os.lstat(os.path.join(root, f)))
            except OSError:
                pass
    return total


def remove(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path, ignore_errors=True)
    else:
        path.unlink(missing_ok=True)


def stale_units(profile: Path, cutoff: float) -> list[Path]:
    """deps/ entries grouped by unit hash, with the unit's .fingerprint folder, when all are stale."""
    deps, fingerprint = profile / "deps", profile / ".fingerprint"
    groups: dict[str, list[Path]] = defaultdict(list)
    newest: dict[str, float] = defaultdict(float)
    for d in (deps, fingerprint):
        if not d.is_dir():
            continue
        for entry in d.iterdir():
            m = UNIT.match(entry.name)
            if not m:
                continue
            h = m["hash"]
            groups[h].append(entry)
            try:
                newest[h] = max(newest[h], last_used(entry))
                if d == fingerprint and entry.is_dir():
                    for f in entry.iterdir():
                        newest[h] = max(newest[h], last_used(f))
            except OSError:
                newest[h] = time.time()  # vanished or unreadable mid-scan: treat as in use
    return [p for h, paths in groups.items() if newest[h] < cutoff for p in paths]


def stale_incremental(profile: Path, cutoff: float) -> list[Path]:
    """incremental/<crate>-<hash> folders no compile has used since the cutoff.

    rustc opens a new session folder inside the crate folder on every compile, which bumps the
    crate folder's mtime, so the folder's own times are enough.
    """
    inc = profile / "incremental"
    if not inc.is_dir():
        return []
    out = []
    for entry in inc.iterdir():
        try:
            if entry.is_dir() and last_used(entry) < cutoff:
                out.append(entry)
        except OSError:
            pass
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--days", type=float, default=float(os.environ.get("SWEEP_DAYS", "2")))
    ap.add_argument("--dry-run", action="store_true", help="report, remove nothing")
    args = ap.parse_args()

    target = Path(__file__).resolve().parent.parent / "target"
    cutoff = time.time() - args.days * 86400
    total = 0
    for profile in sorted(p for p in target.iterdir() if p.is_dir() and (p / "deps").is_dir()):
        victims = stale_units(profile, cutoff) + stale_incremental(profile, cutoff)
        freed = 0
        for path in victims:
            try:
                freed += size_of(path)
            except OSError:
                continue
            if not args.dry_run:
                remove(path)
        total += freed
        print(f"{profile.name}: {len(victims)} stale entries, {freed / 1e9:.1f} GB")
    verb = "would free" if args.dry_run else "freed"
    print(f"{verb} {total / 1e9:.1f} GB (unused for {args.days:g}+ days)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
