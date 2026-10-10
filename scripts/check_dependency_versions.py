#!/usr/bin/env python3
"""Fail closed when the runtime parser requirements are unpinned or mismatched.

This checks exact *installed package versions*, not supply-chain artifact
hashes, platform wheels, publisher trust or advisory database status.
"""
from __future__ import annotations

import argparse
from importlib import metadata
from pathlib import Path
import re
import sys

PIN = re.compile(r"^([A-Za-z][A-Za-z0-9_.-]*)==([0-9][A-Za-z0-9.+!_-]*)$")
MAX_REQUIREMENTS_BYTES = 16 * 1024


def parse_requirements(contents: str) -> dict[str, str]:
    if not isinstance(contents, str) or len(contents.encode("utf-8")) > MAX_REQUIREMENTS_BYTES:
        raise ValueError("Invalid or oversized requirements content")
    versions: dict[str, str] = {}
    for line_number, raw in enumerate(contents.splitlines(), start=1):
        entry = raw.partition("#")[0].strip()
        if not entry:
            continue
        match = PIN.fullmatch(entry)
        if match is None:
            raise ValueError(f"Unpinned or unsupported requirement at line {line_number}")
        name, version = match.groups()
        normalized_name = re.sub(r"[-_.]+", "-", name).lower()
        if normalized_name in versions:
            raise ValueError(f"Duplicate runtime dependency at line {line_number}")
        versions[normalized_name] = version
    if not versions:
        raise ValueError("No pinned runtime requirements found")
    return versions


def check_installed(requirements: dict[str, str], *, installed_version=None) -> None:
    lookup = installed_version or metadata.version
    for name, expected in sorted(requirements.items()):
        try:
            actual = lookup(name)
        except metadata.PackageNotFoundError as exc:
            raise ValueError(f"Missing runtime dependency: {name}") from exc
        if actual != expected:
            raise ValueError(f"Runtime package version mismatch: {name}")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("requirements", nargs="?", default="requirements-normalization.txt")
    args = parser.parse_args(argv)
    try:
        pinned = parse_requirements(Path(args.requirements).read_text(encoding="utf-8"))
        check_installed(pinned)
    except (OSError, ValueError) as exc:
        print("Runtime dependency gate refused:", exc, file=sys.stderr)
        return 2
    print("Runtime dependency versions match pinned requirements:", ", ".join(
        f"{name}=={version}" for name, version in sorted(pinned.items())
    ))
    return 0


if __name__ == "__main__":
    sys.exit(main())
