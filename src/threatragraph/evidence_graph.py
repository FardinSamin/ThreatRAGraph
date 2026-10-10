"""Immutable sourced-claim ledger and historically scoped CTI graph projection.

Reference implementation: Python stdlib + SQLite, no external services.
Only SOURCE-ASSERTED facts/rule semantics belong here. Predicted relations
must be stored elsewhere and never silently treated as sourced observations.

An optional evidence verifier aligns locators against approved source archive bytes.
Unverified direct API inserts remain clearly marked and are not research-ready.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

SCHEMA_VERSION = "1.0"
SHA = re.compile(r"^[0-9a-f]{64}$")
ID = re.compile(r"^[a-z][a-z0-9-]*:[^\s:][^\s]*$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Domain/range checks are deliberately narrow. These are not unrestricted
# triples; extend with an ontology-version change and explicit tests.
RELATIONS = {
    "USES": (
        {"threat-actor", "malware", "campaign"},
        {"tool", "malware", "attack-technique"},
    ),
    "EXPLOITS": (
        {"threat-actor", "malware", "campaign"},
        {"vulnerability"},
    ),
    "AFFECTS": (
        {"vulnerability"},
        {"software-product", "container-component", "kubernetes-resource"},
    ),
    "TARGETS": (
        {"threat-actor", "campaign"},
        {"software-product", "container-component", "kubernetes-resource"},
    ),
    "HAS_BEHAVIOR": (
        {"malware", "attack-technique"},
        {"attack-behavior"},
    ),
    "INVOLVES_SYSCALL": (
        {"attack-behavior", "falco-rule"},
        {"system-call"},
    ),
    "DETECTED_BY": (
        {"attack-behavior", "attack-technique"},
        {"falco-rule"},
    ),
    "APPLIES_TO_COMPONENT": (
        {"falco-rule", "vulnerability"},
        {"container-component", "kubernetes-resource"},
    ),
    "INDICATES": (
        {"indicator"},
        {"malware", "campaign"},
    ),
}
KINDS = {"report_assertion", "rule_semantics"}
POLARITIES = {"positive", "negative", "uncertain"}
VIEW_METHODS = {
    "B0_sparse_report_only": {"early"},
    "G1_early_plus_historical_background": {"early", "background"},
}
MAX_LOCATOR_LENGTH = 2048


def as_utc(raw: Any) -> datetime:
    if not isinstance(raw, str) or not DATE.fullmatch(raw):
        raise ValueError("Timestamp must be exact UTC YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError("Invalid UTC calendar date") from exc


def require_id(raw: Any, field: str) -> str:
    if not isinstance(raw, str) or not ID.fullmatch(raw):
        raise ValueError(f"{field}: typed ID with 'type:value' required")
    if len(raw) > 300:
        raise ValueError(f"{field}: ID too long")
    return raw


def require_sha(raw: Any, field: str) -> str:
    if not isinstance(raw, str) or not SHA.fullmatch(raw):
        raise ValueError(f"{field}: full lowercase SHA-256 required")
    return raw


def fingerprint(obj: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(
        obj, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")).hexdigest()


def validate_triple(subject: str, predicate: str, target: str) -> None:
    require_id(subject, "subject_id")
    require_id(target, "object_id")
    if not isinstance(predicate, str) or predicate not in RELATIONS:
        raise ValueError("Predicate is not allowed in ontology v1")
    allowed_subjects, allowed_targets = RELATIONS[predicate]
    if subject.split(":", 1)[0] not in allowed_subjects:
        raise ValueError("Subject type incompatible with predicate")
    if target.split(":", 1)[0] not in allowed_targets:
        raise ValueError("Object type incompatible with predicate")


def validate_locator(raw: Any) -> str:
    """Canonical, bounded evidence locator, not a trust assertion about text."""
    if not isinstance(raw, dict):
        raise ValueError("evidence_locator must be an object")
    kind = raw.get("kind")
    if not isinstance(kind, str):
        raise ValueError("Locator kind must be text")
    if kind == "text_span":
        keys = {"kind", "segment_id", "start", "end"}
        if set(raw) != keys:
            raise ValueError("text_span requires exact locator keys")
        segment = raw["segment_id"]
        start, end = raw["start"], raw["end"]
        if (not isinstance(segment, str) or not segment.strip() or
                type(start) is not int or type(end) is not int or
                start < 0 or end <= start):
            raise ValueError("Invalid text span locator")
    elif kind in {"json_pointer", "yaml_path"}:
        if set(raw) != {"kind", "path"} or not isinstance(raw["path"], str):
            raise ValueError("Structured locator requires string path")
        if not raw["path"].startswith("/") or len(raw["path"]) < 2:
            raise ValueError("Structured locator must be an absolute field path")
    else:
        raise ValueError("Unsupported evidence locator kind")
    value = json.dumps(raw, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    if len(value.encode("utf-8")) > MAX_LOCATOR_LENGTH:
        raise ValueError("Evidence locator exceeds size limit")
    return value


class EvidenceGraph:
    """Append-only sourced claims stored in SQLite; snapshot-scoped views."""

    def __init__(self, connection: sqlite3.Connection, evidence_verifier=None):
        self.conn = connection
        self.evidence_verifier = evidence_verifier
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS source_versions (
                source_version_id TEXT PRIMARY KEY,
                source_id TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                available_at TEXT NOT NULL,
                date_evidence TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sourced_claims (
                claim_id TEXT PRIMARY KEY,
                source_version_id TEXT NOT NULL,
                subject_id TEXT NOT NULL,
                predicate TEXT NOT NULL,
                object_id TEXT NOT NULL,
                assertion_kind TEXT NOT NULL
                    CHECK (assertion_kind IN ('report_assertion', 'rule_semantics')),
                polarity TEXT NOT NULL
                    CHECK (polarity IN ('positive','negative','uncertain')),
                evidence_locator TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                extractor_version TEXT NOT NULL,
                evidence_status TEXT NOT NULL DEFAULT 'unverified'
                    CHECK (evidence_status IN ('unverified', 'aligned')),
                FOREIGN KEY (source_version_id)
                    REFERENCES source_versions(source_version_id)
            );
            CREATE INDEX IF NOT EXISTS idx_claim_source
                ON sourced_claims(source_version_id);
            CREATE INDEX IF NOT EXISTS idx_claim_subject
                ON sourced_claims(subject_id, predicate);
        """)

    def register_source_versions(self, manifest: dict[str, Any]) -> int:
        """Register approved version metadata immutably. Does NOT hash files.

        Applications must run archived-byte integrity verification before
        enabling ingestion and actual case evaluation.
        """
        if not isinstance(manifest, dict) or not isinstance(manifest.get("sources"), list):
            raise ValueError("Source registry needs a sources array")
        registered = 0
        with self.conn:
            for record in manifest["sources"]:
                if not isinstance(record, dict):
                    raise ValueError("Source record must be object")
                if record.get("status") != "approved":
                    continue
                version = record.get("source_version_id")
                source = record.get("source_id")
                if not isinstance(version, str) or not version.strip():
                    raise ValueError("Approved source_version_id required")
                if not isinstance(source, str) or not source.strip():
                    raise ValueError("Approved source_id required")
                digest = require_sha(record.get("sha256"), "source.sha256")
                available = record.get("available_at")
                as_utc(available)
                if record.get("date_confidence") != "verified":
                    raise ValueError("Approved source requires verified availability")
                rationale = record.get("date_evidence")
                if not isinstance(rationale, str) or not rationale.strip():
                    raise ValueError("Approved source needs independent date evidence")
                row = (version, source, digest, available, rationale)
                old = self.conn.execute(
                    "SELECT * FROM source_versions WHERE source_version_id=?",
                    (version,),
                ).fetchone()
                if old is not None:
                    if tuple(old) != row:
                        raise ValueError("Immutable source version metadata changed")
                    continue
                self.conn.execute(
                    """INSERT INTO source_versions
                    (source_version_id, source_id, sha256, available_at, date_evidence)
                    VALUES (?, ?, ?, ?, ?)""", row,
                )
                registered += 1
        return registered

    def append_source_claim(self, record: dict[str, Any]) -> str:
        """Append one source assertion with a stable content-derived ID.

        This records what a source ASSERTS, not independently verified truth.
        This method cannot validate that the evidence locator really matches
        the text; that must be done by the extraction/evidence verifier.
        """
        if not isinstance(record, dict):
            raise ValueError("Claim must be an object")
        version = record.get("source_version_id")
        if not isinstance(version, str) or not version.strip():
            raise ValueError("source_version_id required")
        subject = record.get("subject_id")
        predicate = record.get("predicate")
        target = record.get("object_id")
        validate_triple(subject, predicate, target)
        kind = record.get("assertion_kind")
        if not isinstance(kind, str) or kind not in KINDS:
            raise ValueError("Sourced claim must be report_assertion or rule_semantics")
        polarity = record.get("polarity")
        if not isinstance(polarity, str) or polarity not in POLARITIES:
            raise ValueError("Unsupported claim polarity")
        extractor = record.get("extractor_version")
        if not isinstance(extractor, str) or not extractor.strip():
            raise ValueError("Extractor version is required")
        if len(extractor) > 200:
            raise ValueError("Extractor version too long")
        locator = validate_locator(record.get("evidence_locator"))
        evidence_sha = require_sha(record.get("evidence_sha256"), "evidence_sha256")
        verification_state = "unverified"
        if self.evidence_verifier is not None:
            alignment = self.evidence_verifier.verify(record)
            if (alignment.status != "aligned" or
                    alignment.source_version_id != version or
                    alignment.evidence_sha256 != evidence_sha):
                raise ValueError("Evidence alignment does not match claim")
            registered = self.conn.execute(
                "SELECT sha256 FROM source_versions WHERE source_version_id=?",
                (version,),
            ).fetchone()
            if registered is None or registered["sha256"] != alignment.source_sha256:
                raise ValueError("Aligned evidence source differs from registered source")
            verification_state = "aligned"

        canonical = {
            "schema_version": SCHEMA_VERSION,
            "source_version_id": version,
            "subject_id": subject,
            "predicate": predicate,
            "object_id": target,
            "assertion_kind": kind,
            "polarity": polarity,
            "evidence_locator": json.loads(locator),
            "evidence_sha256": evidence_sha,
            "extractor_version": extractor,
        }
        claim_id = "claim:" + fingerprint(canonical)
        row = (
            claim_id, version, subject, predicate, target,
            kind, polarity, locator, evidence_sha, extractor, verification_state,
        )
        with self.conn:
            existing = self.conn.execute(
                "SELECT * FROM sourced_claims WHERE claim_id=?", (claim_id,)
            ).fetchone()
            if existing is not None:
                if tuple(existing) != row:
                    raise ValueError("Existing claim ID does not match content")
                return claim_id
            try:
                self.conn.execute(
                    """INSERT INTO sourced_claims
                    (claim_id, source_version_id, subject_id, predicate, object_id,
                     assertion_kind, polarity, evidence_locator,
                     evidence_sha256, extractor_version, evidence_status)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)""", row,
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Claim source must be registered and approved") from exc
        return claim_id

    def project(self, view: dict[str, Any]) -> dict[str, Any]:
        """No ambient full graph access: ALL included claims must match view IDs.

        Use a validated case_views() result from the M3 manifest builder, not
        an arbitrary analyst-supplied view, for real research.
        """
        if not isinstance(view, dict) or view.get("artifact_kind") != "historical_source_input":
            raise ValueError("Historical source input view required")
        if view.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("Unsupported view schema version")
        method = view.get("method")
        if not isinstance(method, str) or method not in VIEW_METHODS:
            raise ValueError("Unknown historical view method")
        allowed_roles = VIEW_METHODS[method]
        cutoff = as_utc(view.get("cutoff_at"))
        sources = view.get("sources")
        if not isinstance(sources, list):
            raise ValueError("Historical view source list required")
        allowed_versions = []
        early_count = 0
        seen = set()

        for record in sources:
            if not isinstance(record, dict):
                raise ValueError("View source entry must be object")
            role = record.get("role")
            if not isinstance(role, str) or role not in allowed_roles:
                raise ValueError("Held-out or unrecognized source role prohibited")
            version = record.get("source_version_id")
            if not isinstance(version, str) or not version.strip() or version in seen:
                raise ValueError("Duplicate/invalid source version in view")
            seen.add(version)
            early_count += (role == "early")
            digest = require_sha(record.get("sha256"), "view.sha256")
            at = record.get("available_at")
            if as_utc(at) > cutoff:
                raise ValueError("Post-cutoff source cannot enter graph")
            stored = self.conn.execute(
                """SELECT sha256, available_at FROM source_versions
                   WHERE source_version_id=?""", (version,)
            ).fetchone()
            if stored is None or stored["sha256"] != digest or stored["available_at"] != at:
                raise ValueError("View source not approved or mismatches ledger metadata")
            allowed_versions.append(version)

        if early_count not in {1, 2}:
            raise ValueError("Historical view must contain 1–2 early sources")

        placeholders = ",".join("?" for _ in allowed_versions)
        # The query is ALLOWLIST-ONLY, not a global graph with a display filter.
        rows = self.conn.execute(
            f"""SELECT claim_id, source_version_id, subject_id, predicate,
                       object_id, assertion_kind, polarity, evidence_locator,
                       evidence_sha256, extractor_version, evidence_status
                  FROM sourced_claims
                 WHERE source_version_id IN ({placeholders})
              ORDER BY subject_id, predicate, object_id, claim_id""",
            allowed_versions,
        ).fetchall()

        edges = [
            {
                **{name: row[name] for name in (
                    "claim_id", "source_version_id", "subject_id", "predicate",
                    "object_id", "assertion_kind", "polarity",
                    "evidence_sha256", "extractor_version", "evidence_status",
                )},
                "evidence_locator": json.loads(row["evidence_locator"]),
            }
            for row in rows
        ]
        vertices = sorted({
            node for edge in edges for node in
            (edge["subject_id"], edge["object_id"])
        })
        return {
            "schema_version": SCHEMA_VERSION,
            "artifact_kind": "historical_sourced_graph",
            "case_id": view.get("case_id"),
            "method": method,
            "cutoff_at": view["cutoff_at"],
            "source_view_sha256": fingerprint(view),
            "nodes": vertices,
            "edges": edges,
            "caveat": (
                "Only source-asserted relationships. Aligned citation bytes do NOT "
                "establish claim semantic correctness or factual truth. Unverified "
                "direct-ledger claims are visibly labeled; model memorization and "
                "future-learned aliases remain separate risks."
            ),
        }

    @staticmethod
    def neighborhood(projection: dict[str, Any], entity_id: str) -> list[dict[str, Any]]:
        """Return outgoing/ingoing attributable multi-edges; no inferred hops."""
        require_id(entity_id, "entity_id")
        return [
            edge for edge in projection["edges"]
            if edge["subject_id"] == entity_id or edge["object_id"] == entity_id
        ]
