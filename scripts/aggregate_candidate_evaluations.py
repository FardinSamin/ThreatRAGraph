#!/usr/bin/env python3
"""Aggregate previously frozen candidate case evaluation JSON, without raw gold."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from scripts.evaluate_frozen_paired_run import _load
from scripts.freeze_case_snapshots import snapshot_sha256, write_immutable_view
from src.threatragraph.heldout_evaluation import aggregate_candidate_evaluations


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evaluations", nargs="+", required=True,
                        help="Distinct content-addressed per-case candidate reports")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--output-dir", default="artifacts/heldout_evaluation")
    args = parser.parse_args(argv)
    try:
        if len(args.evaluations) > 100:
            raise ValueError("No more than 100 candidate cases per aggregation")
        canonical = [Path(item).resolve(strict=True) for item in args.evaluations]
        if len(set(canonical)) != len(canonical):
            raise ValueError("Duplicate case evaluation file paths")
        # Only scored reports, not source articles, label partitions or raw
        # reviewer notes, are admitted to this read-only aggregation.
        reports = [_load(item) for item in args.evaluations]
        aggregate = aggregate_candidate_evaluations(reports)
        if args.write:
            sha, path, created = write_immutable_view(
                aggregate, args.output_dir
            )
            artifact = {"sha256": sha, "path": str(path), "created": created}
        else:
            artifact = {"sha256": snapshot_sha256(aggregate), "created": False}
        summary = {
            "status": "candidate_aggregate_written" if args.write
                      else "candidate_aggregate_preview",
            "aggregate_id": aggregate["aggregate_id"],
            "case_ids": aggregate["case_ids"],
            "case_count": aggregate["case_count"],
            "methods": aggregate["methods"],
            "artifact": artifact,
            "inferential_significance_claimed": False,
            "research_ready": False,
        }
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            RecursionError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "status": "candidate_aggregate_refused",
            "error_category": type(exc).__name__,
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
