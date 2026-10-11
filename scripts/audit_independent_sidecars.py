#!/usr/bin/env python3
"""Inspect independent graph and historical alias sidecars; no mutations."""
from __future__ import annotations

import argparse
import json
import sys

from scripts.exchange_graph_bundle import _read_json, _read_text
from src.threatragraph.portable_exchange import parse_bundle_json
from src.threatragraph.sidecar_reconciliation import reconcile_sidecars


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for field in ("b0-view", "b0-graph", "g1-view", "g1-graph",
                  "b0-bundle", "g1-bundle"):
        parser.add_argument("--" + field, required=True)
    parser.add_argument("--alias-history")
    args = parser.parse_args(argv)
    try:
        paths = [
            args.b0_view, args.b0_graph, args.g1_view, args.g1_graph,
            args.b0_bundle, args.g1_bundle,
        ]
        if args.alias_history:
            paths.append(args.alias_history)
        from pathlib import Path
        if len({Path(path).resolve(strict=True) for path in paths}) != len(paths):
            raise ValueError("Sidecar input files must be distinct")
        result = reconcile_sidecars(
            _read_json(args.b0_view), _read_json(args.b0_graph),
            _read_json(args.g1_view), _read_json(args.g1_graph),
            parse_bundle_json(_read_text(args.b0_bundle)),
            parse_bundle_json(_read_text(args.g1_bundle)),
            alias_history=(_read_json(args.alias_history)
                           if args.alias_history else None),
        )
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "status": "sidecar_reconciliation_refused",
            "reason_category": type(exc).__name__,
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps({
        "status": "candidate_sidecars_structurally_consistent",
        "receipt": result,
        "research_ready": False,
    }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
