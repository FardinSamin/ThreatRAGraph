#!/usr/bin/env python3
"""Build and optionally freeze an offline *unapproved* B0/G1 paired run.

This command does not accept held-out label inputs. Metadata hashes are
declarations, not independently authenticated source approval.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from scripts.freeze_case_snapshots import snapshot_sha256, write_immutable_view
from src.threatragraph.paired_run_freeze import build_paired_run

MAX_INPUT_BYTES = 8 * 1024 * 1024


def _no_duplicate_fields(pairs):
    obj = {}
    for name, value in pairs:
        if name in obj:
            raise ValueError("Duplicate JSON fields are not permitted")
        obj[name] = value
    return obj


def _load(pathname):
    file = Path(pathname)
    if file.is_symlink() or not file.is_file():
        raise ValueError("Unsafe or missing JSON input")
    size = file.stat().st_size
    if not 0 < size <= MAX_INPUT_BYTES:
        raise ValueError("Input JSON must be bounded")
    with file.open("r", encoding="utf-8") as stream:
        item = json.load(stream, object_pairs_hook=_no_duplicate_fields)
    if not isinstance(item, dict):
        raise ValueError("Input must be a JSON object")
    return item


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("b0-view", "b0-graph", "g1-view", "g1-graph",
                 "feature-lineage", "metadata", "g1-config"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--development-only", action="store_true")
    parser.add_argument("--write", action="store_true",
                        help="Write exclusive-creation, hash-addressed artifacts")
    parser.add_argument("--output-dir", default="artifacts/paired_runs")
    args = parser.parse_args(argv)
    try:
        files = {
            name.replace("-", "_"): _load(getattr(args, name.replace("-", "_")))
            for name in ("b0-view", "b0-graph", "g1-view", "g1-graph",
                         "feature-lineage", "metadata", "g1-config")
        }
        result = build_paired_run(
            files["b0_view"], files["b0_graph"],
            files["g1_view"], files["g1_graph"],
            files["feature_lineage"], metadata=files["metadata"],
            g1_config=files["g1_config"],
            development_only=args.development_only,
        )
        summary = {
            "status": "engineering_run_frozen" if args.write
                      else "engineering_run_preview_only",
            "case_id": result["run_lock"]["case_id"],
            "run_id": result["run_lock"]["run_id"],
            "paired_audit_id": result["paired_audit"]["audit_id"],
            "artifact_hashes": {
                name: write_immutable_view(item, args.output_dir)[0]
                if args.write else snapshot_sha256(item)
                for name, item in result.items()
            },
            "empirical_evaluation": "not_performed",
            "research_ready": False,
        }
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            RecursionError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "status": "paired_run_refused",
            "reason_category": type(exc).__name__,
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
