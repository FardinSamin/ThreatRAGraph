"""Replay the real pinned January 2024 GHSA *candidate* through M2 offline.

Requires caller-acquired original advisory bytes. No source case approval,
historical timestamp attestation, human review, predictions or ledger insertion.
Emits a hash/locator-only receipt; never prints the source body.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from scripts.verify_advisory_public_witness import SOURCE_SHA256
from src.threatragraph.ghsa_candidates import (
    MAX_SOURCE_BYTES, extract_ghsa_candidates,
)
from src.threatragraph.ghsa_review_packets import build_packet

SOURCE_VERSION = "candidate:runc-ghsa-original:20240131"
ORIGINAL_GHSA = "GHSA-xr7r-f8xq-vfvv"
ORIGINAL_TARGET = "vulnerability:CVE-2024-21626"
ORIGINAL_PACKAGE = "software-product:go/github.com/opencontainers/runc"


def check_expected_association(report: dict, packet: dict) -> None:
    """Small deterministic expectation; not a semantic/scientific review."""
    if (report["original_ghsa_id"] != ORIGINAL_GHSA or
            report["cve_target_id"] != ORIGINAL_TARGET or
            len(report["candidates"]) != 1):
        raise ValueError("Original pinned GHSA structured candidate shape differs")
    candidate = report["candidates"][0]
    if (candidate["subject_id"] != ORIGINAL_TARGET or
            candidate["predicate"] != "AFFECTS" or
            candidate["object_id"] != ORIGINAL_PACKAGE or
            candidate["candidate_id"] != packet["candidate_id"] or
            packet["source_version_id"] != SOURCE_VERSION or
            packet["source_sha256"] != SOURCE_SHA256 or
            [f["evidence_locator"]["path"] for f in packet["field_evidence"]] !=
            ["/aliases/0", "/affected/0/package/name"]):
        raise ValueError("Original source-specific field association drifted")


def replay_original(raw: bytes) -> dict:
    report = extract_ghsa_candidates(
        raw, source_version_id=SOURCE_VERSION,
        expected_sha256=SOURCE_SHA256,
    )
    candidate_id = report["candidates"][0]["candidate_id"] if report["candidates"] else ""
    packet = build_packet(
        raw, source_version_id=SOURCE_VERSION,
        expected_sha256=SOURCE_SHA256, candidate_id=candidate_id,
    )
    check_expected_association(report, packet)
    return {
        "schema_version": "real-ghsa-candidate-replay-receipt-v1",
        "status": "original_pinned_ghsa_field_bytes_verified_candidate_only",
        "source_version_id": SOURCE_VERSION,
        "original_ghsa_id": ORIGINAL_GHSA,
        "source_sha256": SOURCE_SHA256,
        "source_byte_count": len(raw),
        "candidate_id": packet["candidate_id"],
        "packet_id": packet["packet_id"],
        "field_evidence": packet["field_evidence"],
        "replay_scope": "exact_pinned_byte_identity_not_independent_public_timestamp",
        "historical_public_event_independently_replayed_here": False,
        "rights_approved": False,
        "source_approved": False,
        "semantic_review_authenticated": False,
        "sourced_claim_registered": False,
        "g1_v2_target_method_eligible": False,
        "research_ready": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-file", required=True)
    args = parser.parse_args(argv)
    try:
        path = Path(args.input_file)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            raise ValueError("Expected bounded regular nonsymlink private source file")
        with path.open("rb") as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        result = replay_original(raw)
    except (OSError, ValueError, TypeError, IndexError) as exc:
        print(json.dumps({"status": "original_ghsa_replay_refused",
                          "reason": str(exc), "research_ready": False}))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
