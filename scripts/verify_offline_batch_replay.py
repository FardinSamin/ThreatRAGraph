#!/usr/bin/env python3
"""Audit a frozen unscored batch without gold, network or source-body reads."""
from __future__ import annotations

import argparse
import json
import sys

from src.threatragraph.batch_replay import replay_batch


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", required=True,
                        help="Directory of immutable SHA-addressed batch JSON files")
    parser.add_argument("--batch-receipt-sha256", required=True,
                        help="64-digit hex of saved batch receipt JSON bytes")
    args = parser.parse_args(argv)
    try:
        result = replay_batch(args.artifact_root, args.batch_receipt_sha256)
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "status": "unscored_batch_replay_refused",
            "reason_category": type(exc).__name__,
            "research_ready": False,
        }, sort_keys=True))
        return 2
    result["status"] = "unscored_batch_structural_integrity_verified"
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
