#!/usr/bin/env python3
"""Lists what changed in the Java sources since each Rust crate was last reconciled with them.

Usage: tools/java_drift.py [crate ...]          report (all crates when none named)
       tools/java_drift.py --mark crate [commit] record that crate as reconciled (default HEAD)
       tools/java_drift.py --quiet [crate ...]   only crates with something to fold in

For each crate (tools/java_sources.toml): the commits since `reconciled` that touch its paths,
with the files each changed, and the uncommitted work in those paths (modified, added and
untracked files), since other people change the Java services while the port runs. Exits 1
when anything is listed, so a step can check it before reporting done.
"""
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "tools" / "java_sources.toml"


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True).stdout


def entries(cfg):
    for name, c in cfg["crates"].items():
        yield name, c, (ROOT / cfg["java_repo"]).resolve()
    if "kirun" in cfg:
        yield "kirun", cfg["kirun"], (ROOT / cfg["kirun_repo"]).resolve()


def report(name, c, repo):
    paths = c["paths"]
    lines = []
    log = git(repo, "log", "--format=@%h %ad %s", "--date=format:%Y-%m-%d %H:%M", "--name-status",
              f"{c['reconciled']}..HEAD", "--", *paths)
    for line in log.splitlines():
        if line.startswith("@"):
            lines.append("  commit " + line[1:])
        elif line.strip():
            status, *files = line.split("\t")
            if any(f.startswith(tuple(paths)) for f in files):
                lines.append(f"      {status[0]} {files[-1]}")
    status = git(repo, "status", "--porcelain", "--untracked-files=all", "--", *paths)
    if status.strip():
        stats = {}
        for line in git(repo, "diff", "--numstat", "HEAD", "--", *paths).splitlines():
            add, rem, f = line.split("\t", 2)
            stats[f] = f"+{add} -{rem}"
        lines.append("  uncommitted")
        for line in status.splitlines():
            code, f = line[:2], line[3:]
            lines.append(f"      {code.strip() or '?'} {f} {stats.get(f, '(new)' if code == '??' else '')}".rstrip())
    return lines


def mark(cfg_text, crate, commit):
    section = "kirun" if crate == "kirun" else f"crates.{crate}"
    pattern = re.compile(rf"(\[{re.escape(section)}\][^\[]*?reconciled = \")[^\"]*(\")", re.S)
    if not pattern.search(cfg_text):
        sys.exit(f"no [{section}] with a reconciled line in {CONFIG}")
    return pattern.sub(lambda m: m.group(1) + commit + m.group(2), cfg_text, count=1)


def main():
    cfg_text = CONFIG.read_text()
    cfg = tomllib.loads(cfg_text)
    args = sys.argv[1:]
    if args[:1] == ["--mark"]:
        crate = args[1]
        repo = next(r for n, _, r in entries(cfg) if n == crate)
        commit = args[2] if len(args) > 2 else git(repo, "rev-parse", "--short", "HEAD").strip()
        CONFIG.write_text(mark(cfg_text, crate, commit))
        print(f"{crate} reconciled at {commit}")
        return 0
    quiet = "--quiet" in args
    wanted = {a for a in args if not a.startswith("--")}
    found = False
    for name, c, repo in entries(cfg):
        if wanted and name not in wanted:
            continue
        lines = report(name, c, repo)
        found |= bool(lines)
        if lines or not quiet:
            print(f"== {name} (reconciled {c['reconciled']}, {repo.name})")
            print("\n".join(lines) if lines else "  nothing new")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
