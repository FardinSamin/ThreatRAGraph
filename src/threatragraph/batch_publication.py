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
    HEX64, MAX_ARTIFACT_BYTES, _root_directory, replay_batch,
    verify_unpublished_batch,
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
    if (receipt.get("case_count") != len(cases)
            or receipt.get("research_ready") is not False
            or receipt.get("later_reference_labels_accessed") is not False
            or receipt.get("empirical_evaluation") != "not_performed"):
        raise ValueError("Not an unscored and unapproved batch receipt")

    records = []
    identifiers = []
    for entry, outputs in zip(receipt["cases"], cases):
        if (not isinstance(entry, dict) or not isinstance(outputs, dict)
                or set(outputs) != set(ARTIFACT_NAMES)
                or not isinstance(entry.get("artifacts"), dict)
                or set(entry["artifacts"]) != set(ARTIFACT_NAMES)):
            raise ValueError("Missing, extra or mislabeled batch artifact")
        case_id = entry.get("case_id")
        if type(case_id) is not str or not case_id:
            raise ValueError("Invalid batch case identifier")
        identifiers.append(case_id)
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
        records.append((case_id, outputs, bound))
    if identifiers != sorted(set(identifiers)):
        raise ValueError("Noncanonical duplicate or unordered case identifiers")
    if len(canonical_bytes(receipt)) > MAX_ARTIFACT_BYTES:
        raise ValueError("Batch receipt exceeds replay reader size limit")
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
