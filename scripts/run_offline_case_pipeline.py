#!/usr/bin/env python3
"""Offline source-to-B0/G1 case orchestration, with NO reference-label access.

Run source/case manifest validation, exact archived-byte evidence projection,
separately supplied as-of lineage validation, paired profiles, and a
deterministic engineering receipt. This does not produce study results.

The held-out scorer is deliberately NOT imported here. Inference never sees
reference partitions. Source approval/reviewer/date claims in metadata still
require independent real-world authentication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

from scripts.freeze_case_snapshots import (
    case_views, snapshot_sha256, write_immutable_view,
)
from scripts.freeze_paired_run import _load as _load_json
from scripts.project_case_graph import run as project_case_graph
from src.threatragraph.evidence_graph import fingerprint
from src.threatragraph.paired_run_freeze import build_paired_run

MAX_CLAIMS_BYTES = 5 * 1024 * 1024
MAX_DEPENDENCY_BYTES = 2 * 1024 * 1024
MAX_JSONL_RECORDS = 10000
CLAIM_KEYS = frozenset({
    "source_version_id", "subject_id", "predicate", "object_id",
    "assertion_kind", "polarity", "evidence_locator", "evidence_sha256",
    "extractor_version",
})
REVIEW_KEYS = frozenset({
    "schema_version", "claim_id", "source_version_id", "evidence_sha256",
    "decision", "reviewer_id", "reviewed_at", "rationale",
})
ARTIFACT_KEYS = (
    "b0_view", "b0_graph", "g1_view", "g1_graph",
    "b0_profile", "g1_profile", "paired_audit", "run_lock",
    "pipeline_receipt",
)


def _bytes(path, limit, *, allow_empty=False):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        raise ValueError("Input must be a regular non-symlink local file")
    size = p.stat().st_size
    if size > limit or (size == 0 and not allow_empty):
        raise ValueError("Input size exceeds limit or is empty")
    return p.read_bytes()


def _json_pairs_unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON field in source/review JSONL")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Nonfinite value in JSONL")


def _check_jsonl(payload, fields, name):
    if not isinstance(payload, bytes):
        raise ValueError("JSONL data must be bytes")
    lines = payload.decode("utf-8").splitlines()
    if len(lines) > MAX_JSONL_RECORDS + 1:
        raise ValueError("Too many JSONL records")
    count = 0
    for line in lines:
        if not line.strip():
            continue
        count += 1
        record = json.loads(line, object_pairs_hook=_json_pairs_unique,
                            parse_constant=_reject_constant)
        if not isinstance(record, dict) or set(record) != fields:
            raise ValueError("Unknown fields in " + name + " JSONL")
    return count


def run_offline_case(
    source_manifest, case_manifest, case_id, claims_path, archive_root,
    feature_lineage, metadata, g1_config, *,
    dependency_lock_path, reviews_path=None, development_only=False,
):
    """Build a single *unscored* paired candidate case from original local bytes.

    Caller supplies a separately reviewed exact-only feature-lineage artifact;
    automatically generating a lineage declaration from the graph is forbidden.
    """
    if type(development_only) is not bool:
        raise ValueError("Development-only flag must be boolean")
    if not isinstance(source_manifest, dict) or not isinstance(case_manifest, dict):
        raise ValueError("Manifest JSON objects are required")
    if not isinstance(metadata, dict) or not isinstance(g1_config, dict):
        raise ValueError("Exact metadata and parameter JSON objects required")

    # Do not accept gold fields as extras in claims, even if the downstream
    # ledger would otherwise ignore unrecognized attributes.
    claims_bytes = _bytes(claims_path, MAX_CLAIMS_BYTES, allow_empty=True)
    claim_count = _check_jsonl(claims_bytes, CLAIM_KEYS, "claim")
    review_bytes = (b"" if reviews_path is None else
                    _bytes(reviews_path, MAX_CLAIMS_BYTES, allow_empty=True))
    review_count = _check_jsonl(review_bytes, REVIEW_KEYS, "semantic review")
    if reviews_path is None and not development_only:
        raise ValueError("Strict pipeline requires separately prepared reviews")
    if review_count > claim_count:
        raise ValueError("More reviews than source-asserted claims")
    dependency_bytes = _bytes(dependency_lock_path, MAX_DEPENDENCY_BYTES)
    actual_hashes = {
        "source_manifest_sha256": fingerprint(source_manifest),
        "case_manifest_sha256": fingerprint(case_manifest),
        "review_set_sha256": hashlib.sha256(review_bytes).hexdigest(),
        "dependency_lock_sha256": hashlib.sha256(dependency_bytes).hexdigest(),
    }
    for key, actual in actual_hashes.items():
        if metadata.get(key) != actual:
            raise ValueError("Declared run provenance does not match local bytes: " + key)

    # The legacy runner performs the real bounded source archive integrity
    # audit, verified excerpt alignment, semantic review checks, and exact
    # pre-cutoff B0/G1 claim source partitions. Do NOT bypass those guards.
    projected = project_case_graph(
        source_manifest, case_manifest, case_id, claims_path, archive_root,
        development=development_only, reviews_path=reviews_path,
    )
    views = case_views(source_manifest, case_manifest, case_id)
    paired = build_paired_run(
        views["B0"], projected["B0"], views["G1"], projected["G1"],
        feature_lineage, metadata=metadata, g1_config=g1_config,
        development_only=development_only,
    )
    receipt = {
        "schema_version": "1.0",
        "artifact_kind": "offline_unscored_case_pipeline_receipt",
        "pipeline_version": "offline-source-to-paired-v1",
        "case_id": case_id,
        "cutoff_at": views["B0"]["cutoff_at"],
        "run_id": paired["run_lock"]["run_id"],
        "paired_audit_id": paired["paired_audit"]["audit_id"],
        "b0_profile_id": paired["b0_profile"]["profile_id"],
        "g1_profile_id": paired["g1_profile"]["profile_id"],
        "input_file_sha256": {
            "claims_jsonl": hashlib.sha256(claims_bytes).hexdigest(),
            "semantic_reviews_jsonl": actual_hashes["review_set_sha256"],
            "dependencies": actual_hashes["dependency_lock_sha256"],
        },
        "source_manifest_sha256": actual_hashes["source_manifest_sha256"],
        "case_manifest_sha256": actual_hashes["case_manifest_sha256"],
        "graph_sha256": {
            "B0": fingerprint(projected["B0"]),
            "G1": fingerprint(projected["G1"]),
        },
        "early_source_version_ids": list(
            paired["paired_audit"]["early_source_version_ids"]
        ),
        "raw_claim_records": claim_count,
        "semantic_review_records": review_count,
        "source_archive_bytes_checked_by_projection": True,
        "historical_publication_dates_independently_authenticated": False,
        "semantic_reviewer_identities_independently_authenticated": False,
        "original_source_rights_independently_approved": False,
        "heldout_labels_opened": False,
        "empirical_evaluation": "not_performed",
        "research_ready": False,
    }
    receipt["pipeline_id"] = "pipeline:" + fingerprint(receipt)
    artifacts = {
        "b0_view": views["B0"],
        "b0_graph": projected["B0"],
        "g1_view": views["G1"],
        "g1_graph": projected["G1"],
        "b0_profile": paired["b0_profile"],
        "g1_profile": paired["g1_profile"],
        "paired_audit": paired["paired_audit"],
        "run_lock": paired["run_lock"],
        "pipeline_receipt": receipt,
    }
    assert set(artifacts) == set(ARTIFACT_KEYS)
    return artifacts


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sources", "cases", "case-id", "claims", "archive-root",
                 "feature-lineage", "metadata", "g1-config",
                 "dependency-lock"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--reviews", help="Reviewed assertion ledger JSONL")
    parser.add_argument("--development-only", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--output-dir", default="artifacts/offline_case_pipeline")
    args = parser.parse_args(argv)
    try:
        inputs = [args.sources, args.cases, args.claims,
                  args.feature_lineage, args.metadata, args.g1_config,
                  args.dependency_lock]
        if args.reviews is not None:
            inputs.append(args.reviews)
        canonical = [Path(p).resolve(strict=True) for p in inputs]
        if len(set(canonical)) != len(canonical):
            raise ValueError("Pipeline input paths must be distinct")
        sources = _load_json(args.sources)
        cases = _load_json(args.cases)
        metadata = _load_json(args.metadata)
        config = _load_json(args.g1_config)
        lineage = _load_json(args.feature_lineage)
        result = run_offline_case(
            sources, cases, args.case_id, args.claims, args.archive_root,
            lineage, metadata, config,
            dependency_lock_path=args.dependency_lock,
            reviews_path=args.reviews,
            development_only=args.development_only,
        )
        items = {}
        for name in ARTIFACT_KEYS:
            item = result[name]
            if args.write:
                digest, path, created = write_immutable_view(
                    item, args.output_dir
                )
                items[name] = {
                    "sha256": digest, "path": str(path), "created": created
                }
            else:
                items[name] = {"sha256": snapshot_sha256(item)}
        output = {
            "status": ("offline_case_artifacts_written" if args.write
                       else "offline_case_preview"),
            "case_id": args.case_id,
            "run_id": result["run_lock"]["run_id"],
            "pipeline_id": result["pipeline_receipt"]["pipeline_id"],
            "artifacts": items,
            "heldout_labels_opened": False,
            "empirical_evaluation": "not_performed",
            "research_ready": False,
        }
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            RecursionError, UnicodeError, json.JSONDecodeError,
            sqlite3.Error) as exc:
        print(json.dumps({
            "status": "offline_case_pipeline_refused",
            "reason_category": type(exc).__name__,
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(output, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
