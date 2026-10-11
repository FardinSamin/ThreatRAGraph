#!/usr/bin/env python3
"""Inspect bounded, source-dated alias candidates without rewriting any graph."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from src.threatragraph.alias_history import inspect_alias

MAX_INPUT = 4 * 1024 * 1024


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate JSON field")
        out[key] = value
    return out


def _read(path):
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise ValueError("Symlink or missing input refused")
    if not 0 < file.stat().st_size <= MAX_INPUT:
        raise ValueError("Unsafe alias input size")
    with file.open(encoding="utf-8") as handle:
        record = json.load(handle, object_pairs_hook=_no_duplicates)
    if not isinstance(record, dict):
        raise ValueError("Input must contain a JSON object")
    return record


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--view", required=True)
    p.add_argument("--history", required=True)
    p.add_argument("--entity-id", required=True)
    args = p.parse_args(argv)
    try:
        if Path(args.view).resolve(strict=True) == Path(args.history).resolve(strict=True):
            raise ValueError("Source view and history must be different files")
        result = inspect_alias(
            _read(args.view), _read(args.history), args.entity_id
        )
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            RecursionError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "status": "alias_inspection_refused",
            "reason_category": type(exc).__name__,
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
