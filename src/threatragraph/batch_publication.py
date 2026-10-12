"""Fail-closed publication and retry of unscored multi-case artifacts.

Content-addressed leaves may survive partial failure. They never imply
completion: the final receipt is published only after ALL frozen leaves
pass the separate B0/G1 replay checks. No gold labels are opened.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from scripts.freeze_case_snapshots import canonical_bytes, snapshot_sha256, write_immutable_view
from scripts.run_offline_case_batch import ARTIFACT_NAMES
from src.threatragraph.batch_replay import (
    BATCH_FIELDS, CASE_FIELDS, HEX64, MAX_ARTIFACT_BYTES, _root_directory,
    _self_sealed, replay_batch, verify_unpublished_batch,
)

MAX_PUBLICATION_CASES = 100


def _expected_entries(built):
    """Validate in-memory inventory before creating output directories."""
    if type(built) is not dict or set(built) != {
            "case_results", "batch_receipt"}:
        raise ValueError("Exact candidate batch build fields required")
    cases, receipt = built["case_results"], built["batch_receipt"]
    if (not isinstance(cases, list) or not isinstance(receipt, dict)
            or not isinstance(receipt.get("cases"), list)
            or not 1 <= len(cases) == len(receipt["cases"])
                    <= MAX_PUBLICATION_CASES):
        raise ValueError("Incomplete candidate batch inventory")
    # Enforce size before further schema parsing, so even a malformed
    # oversized receipt never causes any leaf to be written.
    if len(canonical_bytes(receipt)) > MAX_ARTIFACT_BYTES:
        raise ValueError("Batch receipt exceeds replay reader size limit")
    if set(receipt) != BATCH_FIELDS:
        raise ValueError("Unexpected batch receipt keys before publication")
    _self_sealed(receipt, "batch:", "batch_id", "batch")
    if (receipt["schema_version"] != "1.0"
            or receipt["artifact_kind"]
                != "unscored_multicase_engineering_receipt"
            or receipt["batch_version"] != "unscored-multicase-batch-v1"
            or type(receipt["case_count"]) is not int
            or receipt["case_count"] != len(cases)
            or receipt["research_ready"] is not False
            or receipt["later_reference_labels_accessed"] is not False
            or receipt["independent_study_approval"] != "not_verified"
            or receipt["empirical_evaluation"] != "not_performed"):
        raise ValueError("Not an unscored and unapproved batch receipt")
    for field in ("dataset_id", "dataset_version"):
        if (type(receipt[field]) is not str
                or not receipt[field].strip()):
            raise ValueError("Incomplete sealed batch dataset identity")
    if (type(receipt["plan_sha256"]) is not str
            or not HEX64.fullmatch(receipt["plan_sha256"])):
        raise ValueError("Invalid sealed batch plan digest")

    records = []
    identifiers = []
    seen_runs = set()
    for entry, outputs in zip(receipt["cases"], cases):
        if (not isinstance(entry, dict)
                or set(entry) != CASE_FIELDS
                or not isinstance(outputs, dict)
                or set(outputs) != set(ARTIFACT_NAMES)
                or not isinstance(entry.get("artifacts"), dict)
                or set(entry["artifacts"]) != set(ARTIFACT_NAMES)):
            raise ValueError("Missing, extra or mislabeled batch artifact")
        case_id = entry.get("case_id")
        if type(case_id) is not str or not case_id or len(case_id) > 200:
            raise ValueError("Invalid batch case identifier")
        identifiers.append(case_id)
        if (entry["research_ready"] is not False
                or type(entry["g1_novel_proposal_count"]) is not int
                or entry["g1_novel_proposal_count"] < 0
                or type(entry["g1_abstained"]) is not bool):
            raise ValueError("Invalid prepublication per-case status")
        run_id = entry["run_id"]
        if type(run_id) is not str or not run_id or run_id in seen_runs:
            raise ValueError("Duplicate or invalid prepublication run identity")
        seen_runs.add(run_id)
        bound = {}
        for name in ARTIFACT_NAMES:
            artifact = outputs[name]
            if (not isinstance(artifact, dict)
                    or artifact.get("case_id") != case_id):
                raise ValueError("Cross-case or nonobject artifact")
            serialized = canonical_bytes(artifact)
            if len(serialized) > MAX_ARTIFACT_BYTES:
                raise ValueError(
                    "Batch artifact exceeds replay reader size limit"
                )
            digest = hashlib.sha256(serialized).hexdigest()
            if entry["artifacts"][name] != digest:
                raise ValueError("Candidate artifact differs from sealed receipt")
            bound[name] = digest
        # Do not leave newly written leaves behind for an already-invalid
        # receipt: the replay verifier previously caught these mismatches
        # only AFTER artifact publication. Preflight the inexpensive exact
        # per-case pointers, counts, and source-dataset binding first.
        for name, key, receipt_field in (
            ("pipeline_receipt", "pipeline_id", "pipeline_id"),
            ("run_lock", "run_id", "run_id"),
            ("b0_profile", "profile_id", "b0_profile_id"),
            ("g1_profile", "profile_id", "g1_profile_id"),
            ("paired_audit", "audit_id", "paired_audit_id"),
        ):
            if outputs[name].get(key) != entry[receipt_field]:
                raise ValueError("Prepublication case identity pointer mismatch")
        predictions = outputs["g1_profile"].get("predictions")
        abstention = outputs["g1_profile"].get("abstention")
        if (not isinstance(predictions, list)
                or not isinstance(abstention, dict)
                or type(abstention.get("abstained")) is not bool
                or len(predictions) != entry["g1_novel_proposal_count"]
                or abstention["abstained"] is not entry["g1_abstained"]):
            raise ValueError("Prepublication G1 count or abstention mismatch")
        for name in ("b0_view", "g1_view"):
            if (outputs[name].get("dataset_id") != receipt["dataset_id"]
                    or outputs[name].get("dataset_version")
                        != receipt["dataset_version"]):
                raise ValueError("Prepublication source-view dataset mismatch")
        records.append((case_id, outputs, bound))
    if identifiers != sorted(set(identifiers)):
        raise ValueError("Noncanonical duplicate or unordered case identifiers")
    return receipt, records


def publish_batch(built, output_root):
    """Write/reuse leaves, replay them, THEN publish one final receipt.

    Normal errors leave no new final receipt, though previously committed
    individual leaves (and pre-existing valid receipts) are not removed.
    Returns only after the final receipt can itself be replayed.
    """
    receipt, records = _expected_entries(built)
    # A final receipt is a commit marker. If one already exists, it must be
    # verified BEFORE writing/reusing any leaf. A corrupt marker blocks
    # recovery instead of letting a retry silently work around evidence of
    # previously committed but now invalid state.
    receipt_digest = snapshot_sha256(receipt)
    root = Path(output_root).expanduser()
    if root.exists() or root.is_symlink():
        safe = _root_directory(root)
        marker = safe / (receipt_digest + ".json")
        if marker.exists() or marker.is_symlink():
            existing = replay_batch(safe, receipt_digest)
            if (existing["receipt_published"] is not True
                    or existing["case_count"] != len(records)
                    or existing["research_ready"] is not False):
                raise ValueError("Existing batch receipt not valid for reuse")
            return {
                "batch_id": receipt["batch_id"],
                "case_count": len(records),
                "cases": [
                    {
                        "case_id": case_id,
                        "artifacts": {
                            key: {
                                "sha256": inventory[key],
                                "path": str(safe / (inventory[key] + ".json")),
                                "created": False,
                            }
                            for key in ARTIFACT_NAMES
                        },
                    }
                    for case_id, _, inventory in records
                ],
                "batch_receipt": {
                    "sha256": receipt_digest,
                    "path": str(marker),
                    "created": False,
                },
                "receipt_published": True,
                "stored_leaf_replay_verified": True,
                "existing_receipt_reused": True,
                "heldout_labels_accessed": False,
                "research_ready": False,
            }

    artifact_pointers = []
    for case_id, artifacts, inventory in records:
        pointers = {}
        for name in ARTIFACT_NAMES:
            digest, path, created = write_immutable_view(
                artifacts[name], output_root
            )
            if digest != inventory[name]:
                raise ValueError("Content-addressed leaf changed during write")
            pointers[name] = {
                "sha256": digest, "path": str(path), "created": created,
            }
        artifact_pointers.append({"case_id": case_id, "artifacts": pointers})

    # Perform full no-label, no-original-source B0/G1 reconstruction and
    # immutable filename verification before exposing the final receipt.
    checked = verify_unpublished_batch(output_root, receipt)
    if (checked["case_count"] != len(records)
            or checked["receipt_published"] is not False
            or checked["research_ready"] is not False):
        raise ValueError("Batch leaf audit did not certify sealed inventory")

    digest, path, created = write_immutable_view(receipt, output_root)
    if digest != receipt_digest:
        raise ValueError("Final batch receipt changed during publication")
    final = replay_batch(output_root, digest)
    if (final["receipt_published"] is not True
            or final["case_count"] != len(records)
            or final["research_ready"] is not False):
        raise ValueError("Published receipt failed independent replay")
    return {
        "batch_id": receipt["batch_id"],
        "case_count": len(records),
        "cases": artifact_pointers,
        "batch_receipt": {
            "sha256": digest, "path": str(path), "created": created,
        },
        "receipt_published": True,
        "stored_leaf_replay_verified": True,
        "existing_receipt_reused": not created,
        "heldout_labels_accessed": False,
        "research_ready": False,
    }


def check_batch_completion(output_root, receipt_digest):
    """Read-only status probe: without exact receipt, NO batch is complete."""
    if type(receipt_digest) is not str or not HEX64.fullmatch(receipt_digest):
        raise ValueError("Expected exact lowercase SHA-256 batch receipt digest")
    root = Path(output_root).expanduser()
    if not root.exists() and not root.is_symlink():
        return {
            "status": "uncommitted", "receipt_present": False,
            "full_artifact_integrity_verified": False,
            "research_ready": False,
        }
    safe = _root_directory(root)
    expected = safe / (receipt_digest + ".json")
    if not expected.exists() and not expected.is_symlink():
        return {
            "status": "uncommitted", "receipt_present": False,
            "full_artifact_integrity_verified": False,
            "research_ready": False,
        }
    # Any symlink, corruption, missing per-case leaf, forged metadata,
    # incomplete G1 recomputation or wrong hash causes a refusal.
    audit = replay_batch(safe, receipt_digest)
    if not audit["receipt_published"]:
        raise ValueError("Final sealed batch receipt is not published")
    return {
        "status": "sealed_unscored_batch_verified",
        "receipt_present": True,
        "full_artifact_integrity_verified": True,
        "case_count": audit["case_count"],
        "batch_id": audit["batch_id"],
        "research_ready": False,
        "empirical_evaluation": "not_performed",
    }
