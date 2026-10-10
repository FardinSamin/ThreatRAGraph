#!/usr/bin/env python3
"""Standalone, offline B0 cold-start profile from B0-only source/graph artifacts.

This process receives NO case registry, G1 graph, background corpus, external
intelligence or held-out evaluation labels. Both input files must have been
produced by the verified M1/M2/M3 preparation and review pipeline. This CLI
checks consistency, but cannot independently establish archive provenance.
"""
from pathlib import Path
import argparse
import json
import sys

from src.threatragraph.baseline_b0 import build_b0_profile

MAX_INPUT_BYTES = 8 * 1024 * 1024


def load_b0_json(path):
    file = Path(path)
    if file.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("B0 input artifact exceeds size limit")
    with file.open(encoding="utf-8") as stream:
        return json.load(stream)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--b0-view", required=True,
                        help="B0-only M3 source input JSON, no case/reference manifest")
    parser.add_argument("--b0-graph", required=True,
                        help="B0-only M2 graph projection JSON, no G1/held-out material")
    parser.add_argument("--development-only", action="store_true",
                        help="Mark synthetic unreviewed fixture outputs as not research-ready")
    args = parser.parse_args(argv)
    try:
        profile = build_b0_profile(
            load_b0_json(args.b0_view),
            load_b0_json(args.b0_graph),
            development_only=args.development_only,
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        # No raw input payload or cross-experiment source IDs in logs.
        print(json.dumps({
            "status": "refused", "reason": type(exc).__name__,
        }, indent=2))
        return 2
    print(json.dumps(profile, sort_keys=True, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
