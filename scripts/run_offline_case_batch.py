#!/usr/bin/env python3
"""Offline *unscored* multi-case B0/G1 batch coordination.

All cases are built in memory before any output is written. No held-out
reference reader, gold label, model tuning or evaluation is imported here.
This is a content-addressed engineering manifest, not a verified study.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import sqlite3
import sys

from scripts.freeze_case_snapshots import snapshot_sha256, write_immutable_view
from scripts.freeze_paired_run import _load as load_json
from scripts.run_offline_case_pipeline import run_offline_case
from src.threatragraph.evidence_graph import fingerprint

VERSION = "unscored-multicase-batch-v1"
MAX_CASES = 100
PLAN_FIELDS = frozenset({
    "schema_version", "artifact_kind", "dataset_id",
    "dataset_version", "cases",
})
CASE_FIELDS = frozenset({
    "case_id", "claims_jsonl", "reviews_jsonl", "feature_lineage_json",
    "metadata_json", "g1_config_json",
})
FILE_FIELDS = ("claims_jsonl", "reviews_jsonl", "feature_lineage_json",
               "metadata_json", "g1_config_json")
CASE_SPECIFIC = ("claims_jsonl", "reviews_jsonl", "feature_lineage_json",
                 "metadata_json")
ARTIFACT_NAMES = (
    "b0_view", "b0_graph", "g1_view", "g1_graph",
    "feature_lineage", "b0_profile", "g1_profile",
    "paired_audit", "run_lock", "pipeline_receipt",
)


def validate_plan(plan, source_manifest, case_manifest):
    """Reject unknown fields, foreign cases, duplicate IDs and noncanonical order."""
    if not isinstance(plan, dict) or set(plan) != PLAN_FIELDS:
        raise ValueError("Exact no-label batch plan fields required")
    if (plan["schema_version"] != "1.0"
            or plan["artifact_kind"] != VERSION):
        raise ValueError("Unsupported batch plan version")
    for field in ("dataset_id", "dataset_version"):
        value = plan[field]
        if (type(value) is not str or not value
                or value != source_manifest.get(field)
                or value != case_manifest.get(field)):
            raise ValueError("Batch dataset identity mismatch")
    specs = plan["cases"]
    if not isinstance(specs, list) or not 1 <= len(specs) <= MAX_CASES:
        raise ValueError("Batch must declare one to 100 cases")
    known = case_manifest.get("cases")
    if not isinstance(known, list):
        raise ValueError("Case manifest missing cases")
    known_ids = {row["case_id"] for row in known
                 if isinstance(row, dict) and isinstance(row.get("case_id"), str)}
    ids, private_files = [], set()
    for spec in specs:
        if not isinstance(spec, dict) or set(spec) != CASE_FIELDS:
            raise ValueError("Unexpected fields in batch case or label input")
        case_id = spec["case_id"]
        if type(case_id) is not str or case_id not in known_ids:
            raise ValueError("Batch contains unknown or noncanonical case")
        ids.append(case_id)
        for key in FILE_FIELDS:
            value = spec[key]
            if (type(value) is not str or not value or len(value) > 512
                    or "\\" in value or "\x00" in value
                    or ":" in value or any(c in value for c in "\r\n")):
                raise ValueError("Unsafe batch input path")
            parts = PurePosixPath(value)
            if (parts.is_absolute() or not parts.parts
                    or any(part in (".", "..") for part in value.split("/"))
                    or not value.endswith((".json", ".jsonl"))):
                raise ValueError("Paths must be plain relative JSON/JSONL files")
            if key in CASE_SPECIFIC:
                if value in private_files:
                    raise ValueError("Cross-case claim/review/lineage path reused")
                private_files.add(value)
    if ids != sorted(set(ids)):
        raise ValueError("Cases must be unique and sorted by case_id")
    return specs


def _confined_file(root, relative):
    """Resolve local input, rejecting traversal and symlinks in every component."""
    root = Path(root).expanduser()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Input root must be a real local directory")
    base = root.resolve(strict=True)
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Symlinked batch input component refused")
    real = current.resolve(strict=True)
    if (not real.is_relative_to(base) or not real.is_file()):
        raise ValueError("Batch case file escapes dedicated input root")
    return real


def _receipt(cases, plan):
    """Hash-addressed receipt built from generated records; no raw report content."""
    records = []
    seen_runs = set()
    for spec, outputs in zip(plan["cases"], cases):
        if (not isinstance(outputs, dict) or set(outputs) != set(ARTIFACT_NAMES)):
            raise ValueError("Missing required per-case pipeline artifacts")
        case_id = spec["case_id"]
        pipeline = outputs["pipeline_receipt"]
        lock = outputs["run_lock"]
        b0 = outputs["b0_profile"]
        g1 = outputs["g1_profile"]
        audit = outputs["paired_audit"]
        lineage = outputs["feature_lineage"]
        declared_inputs = lock.get("input_artifact_sha256")
        if (not isinstance(lineage, dict)
                or not isinstance(declared_inputs, dict)
                or declared_inputs.get("feature_lineage") != fingerprint(lineage)
                or pipeline.get("feature_lineage_sha256") != fingerprint(lineage)):
            raise ValueError("Unfrozen or unbound as-of feature lineage")
        if (pipeline.get("case_id") != case_id
                or lock.get("case_id") != case_id
                or b0.get("case_id") != case_id
                or g1.get("case_id") != case_id
                or audit.get("case_id") != case_id
                or pipeline.get("run_id") != lock.get("run_id")
                or pipeline.get("b0_profile_id") != b0.get("profile_id")
                or pipeline.get("g1_profile_id") != g1.get("profile_id")
                or pipeline.get("paired_audit_id") != audit.get("audit_id")
                or pipeline.get("research_ready") is not False
                or lock.get("research_ready") is not False
                or pipeline.get("heldout_labels_opened") is not False
                or pipeline.get("empirical_evaluation") != "not_performed"):
            raise ValueError("Inconsistent or prematurely approved batch result")
        run_id = lock["run_id"]
        if type(run_id) is not str or run_id in seen_runs:
            raise ValueError("Duplicate or invalid batch run identity")
        seen_runs.add(run_id)
        records.append({
            "case_id": case_id,
            "pipeline_id": pipeline["pipeline_id"],
            "run_id": run_id,
            "b0_profile_id": b0["profile_id"],
            "g1_profile_id": g1["profile_id"],
            "paired_audit_id": audit["audit_id"],
            "g1_novel_proposal_count": len(g1["predictions"]),
            "g1_abstained": g1["abstention"]["abstained"],
            "artifacts": {
                key: snapshot_sha256(outputs[key]) for key in ARTIFACT_NAMES
            },
            "research_ready": False,
        })
    result = {
        "schema_version": "1.0",
        "artifact_kind": "unscored_multicase_engineering_receipt",
        "batch_version": VERSION,
        "dataset_id": plan["dataset_id"],
        "dataset_version": plan["dataset_version"],
        "plan_sha256": fingerprint(plan),
        "case_count": len(records),
        "cases": records,
        "later_reference_labels_accessed": False,
        "empirical_evaluation": "not_performed",
        "independent_study_approval": "not_verified",
        "research_ready": False,
    }
    result["batch_id"] = "batch:" + fingerprint(result)
    return result


def run_batch(plan, source_manifest, case_manifest, input_root, archive_root,
              dependency_lock_path, *, development_only=False):
    """Run all case-specific profiling steps before optional separate disk writes."""
    if type(development_only) is not bool:
        raise ValueError("Development-only must be a boolean")
    specs = validate_plan(plan, source_manifest, case_manifest)
    # Preflight *all* plan files before any projection. Fail closed on
    # missing/symlinked files even if they occur in a later case.
    local = [
        {key: _confined_file(input_root, spec[key]) for key in FILE_FIELDS}
        for spec in specs
    ]
    results = []
    for spec, paths in zip(specs, local):
        result = run_offline_case(
            source_manifest, case_manifest, spec["case_id"],
            paths["claims_jsonl"], archive_root,
            load_json(paths["feature_lineage_json"]),
            load_json(paths["metadata_json"]),
            load_json(paths["g1_config_json"]),
            dependency_lock_path=dependency_lock_path,
            reviews_path=paths["reviews_jsonl"],
            development_only=development_only,
        )
        results.append(result)
    return {
        "case_results": results,
        "batch_receipt": _receipt(results, plan),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "sources", "cases", "input-root",
                 "archive-root", "dependency-lock"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--development-only", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--output-dir", default="artifacts/offline_case_batches")
    args = parser.parse_args(argv)
    try:
        resolved = [Path(getattr(args, name)).resolve(strict=True) for name in
                    ("plan", "sources", "cases", "dependency_lock")]
        if len(set(resolved)) != len(resolved):
            raise ValueError("Batch control files must be distinct")
        source_manifest = load_json(args.sources)
        case_manifest = load_json(args.cases)
        plan = load_json(args.plan)
        built = run_batch(
            plan, source_manifest, case_manifest, args.input_root,
            args.archive_root, args.dependency_lock,
            development_only=args.development_only,
        )
        summary_cases = []
        for spec, outputs in zip(plan["cases"], built["case_results"]):
            pointers = {}
            for key in ARTIFACT_NAMES:
                artifact = outputs[key]
                if args.write:
                    digest, path, created = write_immutable_view(
                        artifact, args.output_dir
                    )
                    pointers[key] = {
                        "sha256": digest, "path": str(path), "created": created,
                    }
                else:
                    pointers[key] = {"sha256": snapshot_sha256(artifact)}
            summary_cases.append({"case_id": spec["case_id"],
                                  "artifacts": pointers})
        receipt = built["batch_receipt"]
        if args.write:
            digest, path, created = write_immutable_view(receipt, args.output_dir)
            batch_output = {"sha256": digest, "path": str(path),
                            "created": created}
        else:
            batch_output = {"sha256": snapshot_sha256(receipt)}
        output = {
            "status": ("unscored_batch_written" if args.write
                       else "unscored_batch_preview"),
            "batch_id": receipt["batch_id"],
            "case_count": receipt["case_count"],
            "cases": summary_cases,
            "batch_receipt": batch_output,
            "later_reference_labels_accessed": False,
            "empirical_evaluation": "not_performed",
            "research_ready": False,
        }
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            RecursionError, UnicodeError, json.JSONDecodeError,
            sqlite3.Error) as exc:
        print(json.dumps({
            "status": "unscored_batch_refused",
            "reason_category": type(exc).__name__,
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
