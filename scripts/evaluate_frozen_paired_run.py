#!/usr/bin/env python3
"""Separate held-out scorer: validate frozen profiles and run lock BEFORE gold read."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from scripts.freeze_case_snapshots import snapshot_sha256, write_immutable_view
from src.threatragraph.heldout_evaluation import (
    score_frozen_pair, validate_frozen_pair,
)

MAX_JSON = 8 * 1024 * 1024


def _unique_fields(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON field")
        obj[key] = value
    return obj


def _load(path):
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise ValueError("Refuse unsafe or missing local JSON")
    if not 0 < file.stat().st_size <= MAX_JSON:
        raise ValueError("Oversized or empty local JSON")
    with file.open(encoding="utf-8") as stream:
        value = json.load(stream, object_pairs_hook=_unique_fields)
    if not isinstance(value, dict):
        raise ValueError("Reference evaluation input must be an object")
    return value


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("b0-profile", "g1-profile", "paired-audit", "run-lock"):
        p.add_argument("--" + name, required=True)
    p.add_argument("--reference-partition", required=True,
                   help="Separate candidate reviewed later reference JSON")
    p.add_argument("--write", action="store_true")
    p.add_argument("--output-dir", default="artifacts/heldout_evaluation")
    args = p.parse_args(argv)
    try:
        paths = [getattr(args, name) for name in (
            "b0_profile", "g1_profile", "paired_audit", "run_lock",
            "reference_partition",
        )]
        realpaths = [Path(p).resolve(strict=True) for p in paths]
        if len(set(realpaths)) != len(paths):
            raise ValueError("Evaluation input files must be distinct")
        # Import only frozen profiler artifacts first. Do not even open the
        # held-out partition until exact profile/audit/lock validation succeeds.
        b0, g1, audit, lock = [_load(path) for path in paths[:4]]
        validate_frozen_pair(b0, g1, audit, lock)
        reference = _load(args.reference_partition)
        result = score_frozen_pair(b0, g1, audit, lock, reference)
        if args.write:
            digest, location, created = write_immutable_view(
                result, args.output_dir
            )
            written = {"content_sha256": digest, "path": str(location),
                       "created": created}
        else:
            written = {"content_sha256": snapshot_sha256(result),
                       "created": False}
        output = {
            "status": "candidate_evaluation_written" if args.write
                      else "candidate_evaluation_preview",
            "evaluation_id": result["evaluation_id"],
            "case_id": result["case_id"],
            "G1_novel": {
                key: result["methods"]["G1_novel_proposals"][key]
                for key in ("supported_count", "contradicted_count",
                            "not_assessable_count", "assessable_denominator",
                            "assessable_precision")
            },
            "artifact": written, "research_ready": False,
        }
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            RecursionError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "heldout_evaluation_refused",
                          "error_category": type(exc).__name__,
                          "research_ready": False}, sort_keys=True))
        return 2
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
