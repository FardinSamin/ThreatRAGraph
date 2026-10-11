#!/usr/bin/env python3
"""Read-only fail-closed completion probe for one *unscored* batch receipt.

Requires the exact digest from the batch preview. Never scans arbitrary
partial output files to infer success or permits research-ready status.
"""
from __future__ import annotations

import argparse
import json
import sys

from src.threatragraph.batch_publication import check_batch_completion


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--batch-receipt-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        result = check_batch_completion(
            args.artifact_root, args.batch_receipt_sha256
        )
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            RecursionError, UnicodeError, json.JSONDecodeError) as error:
        print(json.dumps({
            "status": "unscored_batch_completion_refused",
            "reason_category": type(error).__name__,
            "receipt_verified": False,
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["status"] == "sealed_unscored_batch_verified" else 2


if __name__ == "__main__":
    sys.exit(main())
