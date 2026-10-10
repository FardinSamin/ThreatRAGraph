"""Separate human-declared semantic evidence review ledger.

Byte alignment verifies *where* words came from; manual review must assess
whether they support an extracted triple as stated. Reviewer identity is
self-declared metadata, NOT authentication or independent factual truth.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sqlite3
from typing import Any

from .evidence_graph import as_utc, require_sha

REVIEW_SCHEMA_VERSION = "semantic-evidence-v1"
DECISIONS = {"supported_by_excerpt", "unsupported_by_excerpt", "uncertain"}
REVIEWER_ID = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{1,63}$")
CLAIM_ID = re.compile(r"^claim:[0-9a-f]{64}$")
MAX_REVIEWS = 10000
MAX_FILE_BYTES = 5 * 1024 * 1024


class SemanticReviewLedger:
    """Append-only single-adjudication-per-claim ledger for a frozen run.

    Disagreements must be explicitly resolved in a separately versioned
    review file, not silently altered in the same run/database.
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS semantic_reviews (
                review_id TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL UNIQUE,
                source_version_id TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                decision TEXT NOT NULL
                    CHECK (decision IN (
                        'supported_by_excerpt','unsupported_by_excerpt','uncertain')),
                reviewer_id TEXT NOT NULL,
                reviewed_at TEXT NOT NULL,
                rationale TEXT NOT NULL,
                review_schema_version TEXT NOT NULL,
                FOREIGN KEY (claim_id) REFERENCES sourced_claims(claim_id)
            )
        """)

    def record(self, review: dict[str, Any]) -> str:
        if not isinstance(review, dict):
            raise ValueError("Review must be an object")
        needed = {
            "schema_version", "claim_id", "source_version_id", "evidence_sha256",
            "decision", "reviewer_id", "reviewed_at", "rationale",
        }
        if set(review) != needed:
            raise ValueError("Review must contain exact v1 fields")
        if review["schema_version"] != REVIEW_SCHEMA_VERSION:
            raise ValueError("Unsupported review schema version")
        cid = review["claim_id"]
        if not isinstance(cid, str) or not CLAIM_ID.fullmatch(cid):
            raise ValueError("Review requires canonical claim ID")
        sid = review["source_version_id"]
        if not isinstance(sid, str) or not sid.strip() or len(sid) > 300:
            raise ValueError("Review source version ID is invalid")
        digest = require_sha(review["evidence_sha256"], "review evidence SHA-256")
        decision = review["decision"]
        if not isinstance(decision, str) or decision not in DECISIONS:
            raise ValueError("Invalid semantic review decision")
        reviewer = review["reviewer_id"]
        if not isinstance(reviewer, str) or not REVIEWER_ID.fullmatch(reviewer):
            raise ValueError("Reviewer must use a bounded pseudonymous ID")
        as_utc(review["reviewed_at"])
        rationale = review["rationale"]
        if (not isinstance(rationale, str) or len(rationale.strip()) < 12
                or len(rationale) > 2000):
            raise ValueError("Review must include a meaningful bounded rationale")

        claim = self.conn.execute(
            """SELECT source_version_id, evidence_sha256, evidence_status
                 FROM sourced_claims WHERE claim_id=?""", (cid,)
        ).fetchone()
        if claim is None:
            raise ValueError("Semantic review claim does not exist in allowed graph")
        if (claim["source_version_id"] != sid or
                claim["evidence_sha256"] != digest):
            raise ValueError("Review provenance does not match source claim")
        if claim["evidence_status"] != "aligned":
            raise ValueError("Semantic review requires byte-aligned claim evidence")

        serialized = json.dumps(
            review, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False,
        ).encode("utf-8")
        review_id = "review:" + hashlib.sha256(serialized).hexdigest()
        stored = self.conn.execute(
            """SELECT review_id FROM semantic_reviews WHERE claim_id=?""", (cid,)
        ).fetchone()
        if stored is not None:
            if stored["review_id"] != review_id:
                raise ValueError("Conflicting semantic reviews for same claim")
            return review_id

        with self.conn:
            self.conn.execute(
                """INSERT INTO semantic_reviews
                   (review_id, claim_id, source_version_id, evidence_sha256,
                    decision, reviewer_id, reviewed_at, rationale, review_schema_version)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (review_id, cid, sid, digest, decision, reviewer,
                 review["reviewed_at"], rationale, REVIEW_SCHEMA_VERSION)
            )
        return review_id

    def status(self, ids: set[str], require_supported: bool) -> dict[str, str]:
        if not ids:
            if require_supported:
                raise ValueError("Research case has no extracted claims to review")
            return {}
        placeholders = ",".join("?" for _ in ids)
        rows = self.conn.execute(
            f"""SELECT claim_id, decision FROM semantic_reviews
               WHERE claim_id IN ({placeholders})""", tuple(sorted(ids)),
        ).fetchall()
        decisions = {row["claim_id"]: row["decision"] for row in rows}
        if require_supported and any(
            decisions.get(cid) != "supported_by_excerpt" for cid in ids
        ):
            raise ValueError("Research case has missing/uncertain/unsupported semantic review")
        return {cid: decisions.get(cid, "unreviewed") for cid in ids}


def read_review_jsonl(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("Review file exceeds size limit")
    reviews = []
    with path.open(encoding="utf-8") as stream:
        for line, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            if len(reviews) >= MAX_REVIEWS:
                raise ValueError("Review count exceeds limit")
            try:
                review = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on review line {line}") from exc
            if not isinstance(review, dict):
                raise ValueError(f"Semantic review line {line} must be an object")
            reviews.append(review)
    return reviews
