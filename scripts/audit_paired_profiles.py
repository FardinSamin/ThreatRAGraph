#!/usr/bin/env python3
"""Audit two already-frozen B0/G1 output JSON files; no gold labels.

This CLI is developer tooling. A successful receipt checks cross-method
structural parity, not historical authenticity or research approval.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from src.threatragraph.paired_profile_audit import audit_paired_profiles

MAX_JSON_BYTES = 8 * 1024 * 1024


def _read_profile(raw_path: str) -> dict:
    path = Path(raw_path)
    if path.is_symlink() or not path.is_file():
        raise ValueError("Profile must be a regular non-symlink file")
    size = path.stat().st_size
    if not 0 < size <= MAX_JSON_BYTES:
        raise ValueError("Profile file exceeds local input limit")
    with path.open("r", encoding="utf-8") as stream:
        obj = json.load(stream)
    if not isinstance(obj, dict):
        raise ValueError("Profile JSON must be an object")
    return obj


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--b0-profile", required=True)
    parser.add_argument("--g1-profile", required=True)
    args = parser.parse_args(argv)
    try:
        b0 = Path(args.b0_profile).resolve(strict=True)
        g1 = Path(args.g1_profile).resolve(strict=True)
        if b0 == g1:
            raise ValueError("B0 and G1 must be different sealed inputs")
        result = audit_paired_profiles(
            _read_profile(args.b0_profile), _read_profile(args.g1_profile)
        )
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            RecursionError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "status": "paired_audit_refused",
            "reason_category": type(exc).__name__,
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
