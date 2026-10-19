#!/usr/bin/env python3
"""Which units a push needs to rebuild and deploy, for rust-build-deploy.yml.

    git diff --name-only <before> <sha> | tools/ci_affected_units.py <metadata.json> <units...>

Reads the changed paths on stdin and `cargo metadata --format-version 1 --no-deps` from the
file, and prints the affected units (a subset of <units>, in their order, space separated):

- a change to anything the whole build depends on (the workspace Cargo.toml or Cargo.lock, the
  Dockerfiles, the Rust workflows, the toolchain) affects every unit;
- a change under crates/<crate>/ affects that crate, every workspace crate that depends on it
  (normal or build dependencies, followed transitively), and so every unit binary of those;
- tests (crates/<crate>/tests/), benches, examples and Markdown change no binary.

Prints every unit when it cannot tell (no paths given: a new branch or a manual run).
"""
import json
import sys
from pathlib import PurePosixPath

WHOLE_BUILD = ("Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml", ".cargo/")
WHOLE_BUILD_PREFIXES = ("deploy/Dockerfile", ".github/workflows/rust-")
NO_BINARY_PARTS = {"tests", "benches", "examples"}


def affected(paths, metadata, units):
    paths = [p.strip() for p in paths if p.strip()]
    if not paths:
        return list(units)
    packages = metadata["packages"]
    root = PurePosixPath(metadata["workspace_root"])
    dir_of = {}
    for p in packages:
        rel = PurePosixPath(p["manifest_path"]).parent.relative_to(root).as_posix()
        dir_of[rel] = p["name"]
    names = {p["name"] for p in packages}
    # Who depends on whom, inside the workspace (dev-dependencies build no binary).
    dependents = {n: set() for n in names}
    for p in packages:
        for d in p.get("dependencies", []):
            if d.get("kind") == "dev":
                continue
            dep = d.get("rename") or d["name"]
            if d["name"] in names:
                dependents[d["name"]].add(p["name"])
            elif dep in names:
                dependents[dep].add(p["name"])
    changed = set()
    for path in paths:
        if path in WHOLE_BUILD or path.startswith(WHOLE_BUILD_PREFIXES) or any(path.startswith(w) for w in WHOLE_BUILD if w.endswith("/")):
            return list(units)
        if path.endswith(".md"):
            continue
        parts = PurePosixPath(path).parts
        # The deepest package directory holding the path.
        for i in range(len(parts) - 1, 0, -1):
            pkg_dir = "/".join(parts[:i])
            if pkg_dir in dir_of:
                rest = parts[i:]
                if rest and rest[0] in NO_BINARY_PARTS:
                    break
                changed.add(dir_of[pkg_dir])
                break
    todo, hit = list(changed), set(changed)
    while todo:
        for d in dependents.get(todo.pop(), ()):
            if d not in hit:
                hit.add(d)
                todo.append(d)
    bins = set()
    for p in packages:
        if p["name"] in hit:
            bins.update(t["name"] for t in p["targets"] if "bin" in t["kind"])
    return [u for u in units if u in bins]


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit("usage: git diff --name-only A B | ci_affected_units.py <metadata.json> <units...>")
    with open(sys.argv[1]) as f:
        meta = json.load(f)
    print(" ".join(affected(sys.stdin.read().splitlines(), meta, sys.argv[2:])))
