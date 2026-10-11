#!/usr/bin/env python3
"""Inspect bounded, source-dated alias candidates without rewriting any graph."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from src.threatragraph.alias_history import inspect_alias
from src.threatragraph.local_file_inputs import assert_distinct_input_files, read_local_json

MAX_INPUT = 4 * 1024 * 1024


def _read(path):
    return read_local_json(path, max_bytes=MAX_INPUT)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--view", required=True)
    p.add_argument("--history", required=True)
    p.add_argument("--entity-id", required=True)
    args = p.parse_args(argv)
    try:
        assert_distinct_input_files([args.view, args.history])
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
