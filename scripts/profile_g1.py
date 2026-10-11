#!/usr/bin/env python3
"""Offline, isolated M5 G1 profile; no gold labels, network or source registry.

All four input JSON files plus mandatory separately reviewed feature-lineage JSON must be sealed source/case snapshots
produced upstream; this script validates *structure* and B0/G1 early parity,
not independent historical publisher date or source authenticity.
"""
import argparse
import json
from pathlib import Path
import sys

from src.threatragraph.similarity_g1 import build_g1_profile

MAX_JSON = 8 * 1024 * 1024


def load_json(path):
    file = Path(path)
    if file.is_symlink() or file.stat().st_size > MAX_JSON:
        raise ValueError("Unsafe or oversized JSON input")
    with file.open(encoding="utf-8") as stream:
        return json.load(stream)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for opt in ("b0-view", "b0-graph", "g1-view", "g1-graph"):
        parser.add_argument("--" + opt, required=True, help="Sealed, pre-reviewed " + opt)
    parser.add_argument("--feature-lineage", required=True,
                        help="Separately reviewed exact-only per-claim as-of provenance JSON")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--min-overlap", type=int, default=1)
    parser.add_argument("--min-background-groups", type=int, default=2)
    parser.add_argument("--max-peers-per-feature", type=int, default=10)
    parser.add_argument("--development-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        output = build_g1_profile(
            load_json(args.b0_view), load_json(args.b0_graph),
            load_json(args.g1_view), load_json(args.g1_graph),
            feature_lineage=load_json(args.feature_lineage),
            top_k=args.top_k, min_overlap=args.min_overlap,
            min_background_groups=args.min_background_groups,
            max_peers_per_feature=args.max_peers_per_feature,
            development_only=args.development_only,
        )
    except (OSError, ValueError, TypeError, KeyError, OverflowError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "refused", "reason": type(exc).__name__}, sort_keys=True))
        return 2
    print(json.dumps(output, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
