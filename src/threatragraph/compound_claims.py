"""Versioned compound GHSA sourced-claim extension to an approved-source M2 ledger.

Does not modify the v1 sourced_claims or semantic_reviews tables/projections.
Only a separately approved versioned GHSA source can supply compound claims.
A separate, self-declared semantic review is required for strict read views.
No candidate review from the unapproved sidecar is automatically imported.
"""
from __future__ import annotations

import json
import sqlite3

from .evidence_graph import EvidenceGraph, as_utc, fingerprint, require_sha
from .ghsa_review_packets import build_packet
from .semantic_reviews import DECISIONS, REVIEWER_ID

CLAIM_SCHEMA = "ghsa-compound-sourced-claim-v1"
REVIEW_SCHEMA = "ghsa-compound-semantic-review-v1"
PROJECTION_SCHEMA = "ghsa-compound-evidence-view-v1"
MAX_EXTRACTOR = 200
MAX_RATIONALE = 2000

CLAIM_FIELDS = {
    "schema_version", "source_version_id", "source_sha256", "candidate_id",
    "packet_id", "subject_id", "predicate", "object_id", "assertion_kind",
    "polarity", "field_evidence", "extractor_version",
}
REVIEW_FIELDS = {
    "schema_version", "claim_id", "source_version_id",
    "compound_evidence_sha256", "decision", "reviewer_id",
    "reviewed_at", "rationale",
}
CLAIM_COLUMNS = [
    ("claim_id", "TEXT", 0, 1),
    ("source_version_id", "TEXT", 1, 0),
    ("source_sha256", "TEXT", 1, 0),
    ("candidate_id", "TEXT", 1, 0),
    ("packet_id", "TEXT", 1, 0),
    ("subject_id", "TEXT", 1, 0),
    ("predicate", "TEXT", 1, 0),
    ("object_id", "TEXT", 1, 0),
    ("assertion_kind", "TEXT", 1, 0),
    ("polarity", "TEXT", 1, 0),
    ("field_evidence_json", "TEXT", 1, 0),
    ("compound_evidence_sha256", "TEXT", 1, 0),
    ("extractor_version", "TEXT", 1, 0),
]
REVIEW_COLUMNS = [
    ("review_id", "TEXT", 0, 1),
    ("claim_id", "TEXT", 1, 0),
    ("source_version_id", "TEXT", 1, 0),
    ("compound_evidence_sha256", "TEXT", 1, 0),
    ("decision", "TEXT", 1, 0),
    ("reviewer_id", "TEXT", 1, 0),
    ("reviewed_at", "TEXT", 1, 0),
    ("rationale", "TEXT", 1, 0),
]


def _check_existing(conn, table, expected):
    existing = conn.execute(
        "SELECT type FROM sqlite_master WHERE name=?", (table,)
    ).fetchone()
    if existing is None:
        return
    if existing[0] != "table":
        raise ValueError("Compound ledger schema name is not a table")
    got = [
        (r[1], r[2].upper(), r[3], r[5])
        for r in conn.execute("PRAGMA table_info(" + table + ")")
    ]
    if got != expected:
        raise ValueError("Incompatible compound ledger schema: explicit migration required")


class CompoundSourcedClaimLedger:
    """Append-only compound source claims in the *same* approved M2 database.

    Stored separately from v1: no implicit B0/G1 ranker ingestion or migration.
    """

    def __init__(self, graph: EvidenceGraph):
        if not isinstance(graph, EvidenceGraph) or graph.evidence_verifier is None:
            raise ValueError("Compound claims require an archive-verifying approved-source graph")
        self.graph = graph
        self.conn = graph.conn
        self.verifier = graph.evidence_verifier
        self.conn.execute("PRAGMA foreign_keys=ON")
        _check_existing(self.conn, "compound_sourced_claims_v1", CLAIM_COLUMNS)
        _check_existing(self.conn, "compound_semantic_reviews_v1", REVIEW_COLUMNS)
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS compound_sourced_claims_v1 (
                claim_id TEXT PRIMARY KEY,
                source_version_id TEXT NOT NULL,
                source_sha256 TEXT NOT NULL,
                candidate_id TEXT NOT NULL,
                packet_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                predicate TEXT NOT NULL CHECK (predicate='AFFECTS'),
                object_id TEXT NOT NULL,
                assertion_kind TEXT NOT NULL CHECK (assertion_kind='report_assertion'),
                polarity TEXT NOT NULL CHECK (polarity='positive'),
                field_evidence_json TEXT NOT NULL,
                compound_evidence_sha256 TEXT NOT NULL,
                extractor_version TEXT NOT NULL,
                FOREIGN KEY (source_version_id) REFERENCES source_versions(source_version_id)
            );
            CREATE INDEX IF NOT EXISTS idx_compound_source_v1
                ON compound_sourced_claims_v1(source_version_id);
            CREATE TABLE IF NOT EXISTS compound_semantic_reviews_v1 (
                review_id TEXT PRIMARY KEY,
                claim_id TEXT NOT NULL UNIQUE,
                source_version_id TEXT NOT NULL,
                compound_evidence_sha256 TEXT NOT NULL,
                decision TEXT NOT NULL CHECK
                    (decision IN ('supported_by_excerpt','unsupported_by_excerpt','uncertain')),
                reviewer_id TEXT NOT NULL,
                reviewed_at TEXT NOT NULL,
                rationale TEXT NOT NULL,
                FOREIGN KEY (claim_id) REFERENCES compound_sourced_claims_v1(claim_id)
            );
        """)

    def append(self, claim: dict) -> str:
        """Register one explicitly supplied compound claim, never a candidate packet."""
        if not isinstance(claim, dict) or set(claim) != CLAIM_FIELDS:
            raise ValueError("Versioned compound sourced claim requires exact fields")
        if claim["schema_version"] != CLAIM_SCHEMA:
            raise ValueError("Unsupported compound sourced-claim schema")
        source = claim["source_version_id"]
        if not isinstance(source, str):
            raise ValueError("Invalid source version")
        digest = require_sha(claim["source_sha256"], "compound.source_sha256")
        approved = self.verifier.versions.get(source)
        if approved is None or approved.get("source_kind") != "cve_advisory":
            raise ValueError("Compound GHSA requires approved advisory source version")
        stored = self.conn.execute(
            "SELECT sha256 FROM source_versions WHERE source_version_id=?", (source,)
        ).fetchone()
        if stored is None or stored[0] != digest or approved["sha256"] != digest:
            raise ValueError("Unregistered or mismatched approved source metadata")
        extractor = claim["extractor_version"]
        if (not isinstance(extractor, str) or not extractor.strip()
                or len(extractor) > MAX_EXTRACTOR):
            raise ValueError("Versioned extractor identity required")
        if not isinstance(claim["candidate_id"], str):
            raise ValueError("Candidate ID must be text")
        # Recheck the privately archived exact original bytes and reconstruct
        # BOTH fields and full compound packet without trusting caller claims.
        raw = self.verifier.read_approved_bytes(source)
        packet = build_packet(
            raw, source_version_id=source,
            expected_sha256=digest, candidate_id=claim["candidate_id"],
        )
        for key in ("source_version_id", "source_sha256", "candidate_id",
                    "packet_id", "subject_id", "predicate", "object_id",
                    "assertion_kind", "polarity"):
            if claim[key] != packet[key]:
                raise ValueError("Compound claim differs from pinned original source packet")
        if claim["field_evidence"] != packet["field_evidence"]:
            raise ValueError("Compound claim field citations differ from verified archive")
        canonical = {key: claim[key] for key in sorted(CLAIM_FIELDS)}
        compound_digest = fingerprint(packet["field_evidence"])
        cid = "claim:" + fingerprint(canonical)
        fields_json = json.dumps(
            packet["field_evidence"], sort_keys=True, separators=(",", ":")
        )
        row = (
            cid, source, digest, packet["candidate_id"], packet["packet_id"],
            packet["subject_id"], packet["predicate"], packet["object_id"],
            packet["assertion_kind"], packet["polarity"], fields_json,
            compound_digest, extractor,
        )
        old = self.conn.execute(
            "SELECT * FROM compound_sourced_claims_v1 WHERE claim_id=?", (cid,)
        ).fetchone()
        if old is not None:
            if tuple(old) != row:
                raise ValueError("Conflicting stored compound claim")
            return cid
        with self.conn:
            self.conn.execute("""
                INSERT INTO compound_sourced_claims_v1 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, row)
        return cid

    def review(self, record: dict) -> str:
        """Review a registered byte-verified claim; self-declared, not authenticated."""
        if not isinstance(record, dict) or set(record) != REVIEW_FIELDS:
            raise ValueError("Compound semantic review requires exact fields")
        if record["schema_version"] != REVIEW_SCHEMA:
            raise ValueError("Unsupported compound semantic review version")
        cid = record["claim_id"]
        if not isinstance(cid, str) or not cid.startswith("claim:") or len(cid) != 70:
            raise ValueError("Canonical compound claim ID required")
        stored = self.conn.execute("""
            SELECT source_version_id, compound_evidence_sha256
            FROM compound_sourced_claims_v1 WHERE claim_id=?
        """, (cid,)).fetchone()
        if (stored is None or record["source_version_id"] != stored[0] or
                record["compound_evidence_sha256"] != stored[1]):
            raise ValueError("Review not bound to registered compound claim evidence")
        if (not isinstance(record["decision"], str)
                or record["decision"] not in DECISIONS):
            raise ValueError("Invalid compound review decision")
        reviewer = record["reviewer_id"]
        if not isinstance(reviewer, str) or not REVIEWER_ID.fullmatch(reviewer):
            raise ValueError("Reviewer pseudonym malformed")
        as_utc(record["reviewed_at"])
        rationale = record["rationale"]
        if (not isinstance(rationale, str) or len(rationale.strip()) < 12
                or len(rationale) > MAX_RATIONALE):
            raise ValueError("Bounded meaningful rationale required")
        review_id = "review:" + fingerprint(record)
        values = (
            review_id, cid, record["source_version_id"], record["compound_evidence_sha256"],
            record["decision"], reviewer, record["reviewed_at"], rationale,
        )
        old = self.conn.execute(
            "SELECT * FROM compound_semantic_reviews_v1 WHERE claim_id=?", (cid,)
        ).fetchone()
        if old is not None:
            if tuple(old) != values:
                raise ValueError("Conflicting review: new frozen adjudication required")
            return review_id
        with self.conn:
            self.conn.execute(
                "INSERT INTO compound_semantic_reviews_v1 VALUES (?,?,?,?,?,?,?,?)",
                values,
            )
        return review_id

    def project(self, view: dict, *, require_supported: bool = False) -> dict:
        """Separate cutoff-safe, reviewed compound evidence view (NOT G1 graph)."""
        if type(require_supported) is not bool:
            raise ValueError("require_supported must be a boolean")
        # Delegate the complete source allowlist/date/role/hash contract to M2 v1.
        self.graph.project(view)
        allowed = [s["source_version_id"] for s in view["sources"]]
        if not allowed:
            raise ValueError("Empty historical source allowlist")
        placeholders = ",".join("?" for _ in allowed)
        rows = self.conn.execute(f"""
            SELECT c.*, r.decision, r.review_id
            FROM compound_sourced_claims_v1 c
            LEFT JOIN compound_semantic_reviews_v1 r ON c.claim_id=r.claim_id
            WHERE c.source_version_id IN ({placeholders})
            ORDER BY c.source_version_id, c.subject_id, c.object_id, c.claim_id
        """, allowed).fetchall()
        edges = []
        for row in rows:
            decision = row["decision"] or "unreviewed"
            if require_supported and decision != "supported_by_excerpt":
                raise ValueError("Strict compound view requires supported semantic review")
            edges.append({
                "claim_id": row["claim_id"],
                "source_version_id": row["source_version_id"],
                "source_sha256": row["source_sha256"],
                "subject_id": row["subject_id"], "predicate": row["predicate"],
                "object_id": row["object_id"],
                "assertion_kind": row["assertion_kind"],
                "polarity": row["polarity"],
                "field_evidence": json.loads(row["field_evidence_json"]),
                "compound_evidence_sha256": row["compound_evidence_sha256"],
                "evidence_status": "both_structured_fields_byte_aligned",
                "semantic_review_status": decision,
                "review_id": row["review_id"],
            })
        return {
            "schema_version": PROJECTION_SCHEMA,
            "artifact_kind": "historical_compound_sourced_evidence_not_g1_graph",
            "case_id": view["case_id"], "method": view["method"],
            "cutoff_at": view["cutoff_at"],
            "source_view_sha256": fingerprint(view),
            "edges": edges,
            "review_authentication": "self_declared_not_independently_verified",
            "research_ready": False,
            "g1_ranker_input_eligible": False,
            "limitations": "Separate reviewed source-assertions; not v1 B0/G1 feature graph, source rights approval or empirical validation.",
        }
