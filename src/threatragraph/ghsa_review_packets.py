"""Byte-verified, multi-field GHSA review packets; separate from sourced claims.

A packet is candidate-only even after a self-declared reviewer attestation.
No automatic source approval, semantic review of a ledger claim, or G1 access.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3

from .evidence_alignment import _evidence_bytes
from .evidence_graph import as_utc, fingerprint, require_sha, validate_locator, validate_triple
from .ghsa_candidates import extract_ghsa_candidates
from .semantic_reviews import DECISIONS, REVIEWER_ID

PACKET_SCHEMA = "ghsa-compound-evidence-packet-v1"
REVIEW_SCHEMA = "ghsa-compound-candidate-review-v1"
MAX_REVIEW_RATIONALE = 2000


def build_packet(raw: bytes, *, source_version_id: str,
                 expected_sha256: str, candidate_id: str) -> dict:
    """Re-derive the candidate and independently verify BOTH field hashes.

    Never accept caller-constructed candidate content as a source of truth.
    A verified packet is not a verified source claim or approved source.
    """
    report = extract_ghsa_candidates(
        raw, source_version_id=source_version_id,
        expected_sha256=expected_sha256,
    )
    if not isinstance(candidate_id, str) or len(candidate_id) > 100:
        raise ValueError("Canonical candidate ID required")
    found = [c for c in report["candidates"] if c["candidate_id"] == candidate_id]
    if len(found) != 1:
        raise ValueError("Candidate ID is not present in pinned source")
    candidate = found[0]
    validate_triple(candidate["subject_id"], candidate["predicate"], candidate["object_id"])
    fields = candidate["supporting_source_fields"]
    if len(fields) != 2:
        raise ValueError("GHSA AFFECTS review requires exactly two fields")
    verified = []
    seen = set()
    for field in fields:
        if not isinstance(field, dict) or set(field) != {"evidence_locator", "evidence_sha256"}:
            raise ValueError("Malformed compound field support")
        locator = field["evidence_locator"]
        validate_locator(locator)
        if locator["kind"] != "json_pointer":
            raise ValueError("Compound GHSA supports only JSON scalar paths")
        if locator["path"] in seen:
            raise ValueError("Duplicate evidence path")
        seen.add(locator["path"])
        expected = require_sha(field["evidence_sha256"], "field.evidence_sha256")
        actual = hashlib.sha256(_evidence_bytes(
            raw, locator, source_version_id, source_kind="cve_advisory"
        )).hexdigest()
        if actual != expected:
            raise ValueError("Candidate evidence differs from exact source bytes")
        verified.append({"evidence_locator": locator, "evidence_sha256": actual})
    expected_paths = {"/aliases/", "/affected/"}
    if not all(any(path.startswith(prefix) for path in seen) for prefix in expected_paths):
        raise ValueError("Both alias and affected-package evidence required")
    packet_core = {
        "schema_version": PACKET_SCHEMA,
        "candidate_id": candidate_id,
        "source_version_id": source_version_id,
        "source_sha256": report["source_sha256"],
        "subject_id": candidate["subject_id"],
        "predicate": candidate["predicate"],
        "object_id": candidate["object_id"],
        "assertion_kind": candidate["assertion_kind"],
        "polarity": candidate["polarity"],
        "field_evidence": verified,
    }
    return {
        **packet_core,
        "packet_id": "packet:" + fingerprint(packet_core),
        "evidence_status": "both_structured_fields_byte_aligned",
        "semantic_review_status": "not_reviewed",
        "ledger_inserted": False,
        "source_approved": False,
        "research_ready": False,
        "limitations": "Field alignment is not source approval, semantic truth, or a sourced_claims ledger entry.",
    }


def validate_attestation(packet: dict, review: dict) -> dict:
    """Bind a self-declared human decision to the exact verified packet hash."""
    if not isinstance(review, dict) or set(review) != {
        "schema_version", "packet_id", "candidate_id", "source_version_id",
        "source_sha256", "decision", "reviewer_id", "reviewed_at", "rationale",
    }:
        raise ValueError("Review requires exact compound candidate review fields")
    if review["schema_version"] != REVIEW_SCHEMA:
        raise ValueError("Unsupported compound review schema")
    for key in ("packet_id", "candidate_id", "source_version_id", "source_sha256"):
        if review[key] != packet[key]:
            raise ValueError("Reviewer record is not bound to verified source packet")
    if not isinstance(review["decision"], str) or review["decision"] not in DECISIONS:
        raise ValueError("Invalid compound evidence decision")
    reviewer = review["reviewer_id"]
    if not isinstance(reviewer, str) or not REVIEWER_ID.fullmatch(reviewer):
        raise ValueError("Invalid bounded reviewer pseudonym")
    as_utc(review["reviewed_at"])
    rationale = review["rationale"]
    if (not isinstance(rationale, str) or len(rationale.strip()) < 12
            or len(rationale) > MAX_REVIEW_RATIONALE):
        raise ValueError("A meaningful bounded review rationale is required")
    data = json.dumps(review, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)
    return {
        "review_id": "candidate-review:" + hashlib.sha256(data.encode("utf-8")).hexdigest(),
        **review,
        "review_authentication": "self_declared_not_independently_verified",
        "ledger_inserted": False,
        "source_approved": False,
        "research_ready": False,
    }


class CompoundCandidateReviewLedger:
    """Append-only *separate* review records, never sourced_claims/semantic_reviews.

    A caller must supply verified source bytes for every record operation.
    Conflicting decisions cannot overwrite a frozen candidate packet.
    """

    def __init__(self, connection: sqlite3.Connection):
        self.conn = connection
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS ghsa_candidate_reviews (
                packet_id TEXT PRIMARY KEY,
                candidate_id TEXT NOT NULL,
                source_version_id TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                review_id TEXT NOT NULL,
                review_json TEXT NOT NULL
            )
        """)
        cols = self.conn.execute("PRAGMA table_info(ghsa_candidate_reviews)").fetchall()
        expected = ["packet_id", "candidate_id", "source_version_id",
                    "source_sha256", "review_id", "review_json"]
        if ([c[1] for c in cols] != expected or not cols[0][5]
                or any(not c[3] for c in cols[1:])):
            raise ValueError("Incompatible compound review ledger schema")

    def record(self, raw: bytes, *, source_version_id: str, expected_sha256: str,
               candidate_id: str, review: dict) -> dict:
        packet = build_packet(
            raw, source_version_id=source_version_id,
            expected_sha256=expected_sha256, candidate_id=candidate_id,
        )
        bound = validate_attestation(packet, review)
        serialized = json.dumps(bound, sort_keys=True, separators=(",", ":"),
                                ensure_ascii=False, allow_nan=False)
        stored = self.conn.execute(
            "SELECT review_id, review_json FROM ghsa_candidate_reviews WHERE packet_id=?",
            (packet["packet_id"],),
        ).fetchone()
        if stored is not None:
            if (stored[0], stored[1]) != (bound["review_id"], serialized):
                raise ValueError("Conflicting review for frozen compound packet")
        else:
            with self.conn:
                self.conn.execute("""
                    INSERT INTO ghsa_candidate_reviews
                    (packet_id, candidate_id, source_version_id,
                     source_sha256, review_id, review_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    packet["packet_id"], packet["candidate_id"],
                    packet["source_version_id"], packet["source_sha256"],
                    bound["review_id"], serialized,
                ))
        return {
            "status": "candidate_review_recorded_not_approved",
            "packet_id": packet["packet_id"],
            "review_id": bound["review_id"],
            "decision": bound["decision"],
            "review_authentication": bound["review_authentication"],
            "source_approved": False,
            "sourced_claim_registered": False,
            "semantic_claim_review_recorded": False,
            "research_ready": False,
        }
