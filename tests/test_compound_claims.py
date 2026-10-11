"""Synthetic, fail-closed compound sourced-claim/review/cutoff regression tests."""
from contextlib import closing
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from src.threatragraph.compound_claims import (
    CLAIM_SCHEMA, REVIEW_SCHEMA, PROJECTION_SCHEMA, CompoundSourcedClaimLedger,
)
from src.threatragraph.evidence_alignment import EvidenceVerifier
from src.threatragraph.evidence_graph import EvidenceGraph, fingerprint
from src.threatragraph.ghsa_candidates import extract_ghsa_candidates
from src.threatragraph.ghsa_review_packets import build_packet


def source_bytes(cve="CVE-2024-21626"):
    return json.dumps({
        "schema_version": "1.4.0",
        "id": "GHSA-ab12-cd34-ef56",
        "aliases": [cve],
        "affected": [{"package": {"ecosystem": "Go",
                                   "name": "github.com/example/runtime"}}],
        "details": "Synthetic development fixture, not a historical event",
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class CompoundClaimsTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source_id = "src:test-early"
        self.raw = source_bytes()
        self.digest = sha(self.raw)
        self.later_id = "src:test-heldout"
        self.later_raw = source_bytes("CVE-2024-99999")
        self.later_sha = sha(self.later_raw)
        for raw in (self.raw, self.later_raw):
            digest = sha(raw)
            parent = self.root / digest[:2]
            parent.mkdir(exist_ok=True)
            (parent / digest).write_bytes(raw)
        self.sources = [
            self._source(self.source_id, self.digest, "2024-01-01T00:00:00Z"),
            self._source(self.later_id, self.later_sha, "2024-03-01T00:00:00Z"),
        ]
        self.manifest = {"sources": self.sources}
        self.conn = sqlite3.connect(":memory:")
        self.graph = EvidenceGraph(
            self.conn, evidence_verifier=EvidenceVerifier(self.manifest, self.root)
        )
        self.graph.register_source_versions(self.manifest)
        self.ledger = CompoundSourcedClaimLedger(self.graph)
        self.packet = self._packet(self.raw, self.source_id)
        self.claim = self._claim(self.packet)
        self.view = self._view()

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    @staticmethod
    def _source(sid, digest, when):
        return {
            "source_version_id": sid,
            "source_id": "source:" + sid,
            "source_kind": "cve_advisory",
            "status": "approved",
            "sha256": digest,
            "available_at": when,
            "date_confidence": "verified",
            "date_evidence": "Synthetic fixture date, not empirical approval",
        }

    def _packet(self, raw, sid):
        info = extract_ghsa_candidates(
            raw, source_version_id=sid, expected_sha256=sha(raw)
        )
        return build_packet(
            raw, source_version_id=sid, expected_sha256=sha(raw),
            candidate_id=info["candidates"][0]["candidate_id"],
        )

    @staticmethod
    def _claim(packet):
        return {
            "schema_version": CLAIM_SCHEMA,
            "source_version_id": packet["source_version_id"],
            "source_sha256": packet["source_sha256"],
            "candidate_id": packet["candidate_id"],
            "packet_id": packet["packet_id"],
            "subject_id": packet["subject_id"],
            "predicate": packet["predicate"],
            "object_id": packet["object_id"],
            "assertion_kind": packet["assertion_kind"],
            "polarity": packet["polarity"],
            "field_evidence": packet["field_evidence"],
            "extractor_version": "synthetic-ghsa/1",
        }

    def _view(self, sid=None, when="2024-02-01T00:00:00Z"):
        source = self.sources[0] if sid is None else next(
            x for x in self.sources if x["source_version_id"] == sid
        )
        return {
            "schema_version": "1.0",
            "artifact_kind": "historical_source_input",
            "dataset_id": "synthetic",
            "dataset_version": "test-v1",
            "case_id": "case:fixture",
            "target_entity_id": "vulnerability:CVE-2024-21626",
            "cutoff_at": when,
            "scope_warning": "Synthetic development only; not independent source approvals",
            "method": "B0_sparse_report_only",
            "sources": [{
                "role": "early", "source_version_id": source["source_version_id"],
                "sha256": source["sha256"], "available_at": source["available_at"],
                "independence_group": "fixture-early",
            }],
        }

    def _review(self, cid, decision="supported_by_excerpt"):
        return {
            "schema_version": REVIEW_SCHEMA,
            "claim_id": cid,
            "source_version_id": self.source_id,
            "compound_evidence_sha256": fingerprint(self.packet["field_evidence"]),
            "decision": decision,
            "reviewer_id": "reviewer-01",
            "reviewed_at": "2026-10-10T22:00:00Z",
            "rationale": "I manually checked both original scalar fields and the typed association.",
        }

    def test_approved_verified_two_fields_create_only_separate_v2_claim(self):
        cid = self.ledger.append(self.claim)
        self.assertEqual(cid, self.ledger.append(self.claim))
        self.assertTrue(cid.startswith("claim:"))
        self.assertEqual(1, self.conn.execute(
            "SELECT COUNT(*) FROM compound_sourced_claims_v1"
        ).fetchone()[0])
        self.assertEqual(0, self.conn.execute(
            "SELECT COUNT(*) FROM sourced_claims"
        ).fetchone()[0])
        out = self.ledger.project(self.view)
        self.assertEqual(PROJECTION_SCHEMA, out["schema_version"])
        self.assertFalse(out["research_ready"])
        self.assertFalse(out["g1_ranker_input_eligible"])
        self.assertEqual("unreviewed", out["edges"][0]["semantic_review_status"])
        self.assertEqual(2, len(out["edges"][0]["field_evidence"]))
        self.assertEqual([], self.graph.project(self.view)["edges"])

    def test_manual_review_is_distinct_from_candidate_attestation(self):
        cid = self.ledger.append(self.claim)
        with self.assertRaisesRegex(ValueError, "Strict compound view"):
            self.ledger.project(self.view, require_supported=True)
        rid = self.ledger.review(self._review(cid))
        self.assertEqual(rid, self.ledger.review(self._review(cid)))
        result = self.ledger.project(self.view, require_supported=True)
        self.assertEqual("supported_by_excerpt", result["edges"][0]["semantic_review_status"])
        self.assertEqual(rid, result["edges"][0]["review_id"])
        self.assertFalse(result["research_ready"])
        self.assertIsNone(self.conn.execute(
            "SELECT name FROM sqlite_master WHERE name='semantic_reviews'"
        ).fetchone())

    def test_unapproved_manifest_candidate_cannot_be_used(self):
        records = copy.deepcopy(self.manifest)
        records["sources"][0]["status"] = "candidate"
        with closing(sqlite3.connect(":memory:")) as conn:
            other = EvidenceGraph(
                conn, evidence_verifier=EvidenceVerifier(records, self.root)
            )
            other.register_source_versions(records)
            with self.assertRaisesRegex(ValueError, "approved"):
                CompoundSourcedClaimLedger(other).append(self.claim)

    def test_without_archive_verifier_compound_claims_refused(self):
        with closing(sqlite3.connect(":memory:")) as conn:
            graph = EvidenceGraph(conn)
            graph.register_source_versions(self.manifest)
            with self.assertRaises(ValueError):
                CompoundSourcedClaimLedger(graph)

    def test_archive_tamper_refused_even_when_metadata_claim_unchanged(self):
        path = self.root / self.digest[:2] / self.digest
        path.write_bytes(self.raw + b" ")
        with self.assertRaisesRegex(ValueError, "differs"):
            self.ledger.append(self.claim)

    def test_mismatched_source_or_field_or_compound_packet_refused(self):
        for field, value in [
            ("source_sha256", "0" * 64),
            ("subject_id", "malware:fake"),
            ("object_id", "software-product:go/github.com/evil/thing"),
            ("predicate", "USES"),
            ("packet_id", "packet:" + "0" * 64),
            ("candidate_id", "candidate:" + "0" * 64),
            ("field_evidence", []),
            ("field_evidence", list(reversed(self.packet["field_evidence"]))),
        ]:
            record = copy.deepcopy(self.claim)
            record[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.ledger.append(record)

    def test_unreviewed_candidate_packet_cannot_replace_versioned_claim(self):
        with self.assertRaises(ValueError):
            self.ledger.append(self.packet)
        with self.assertRaises(ValueError):
            self.ledger.append(dict(self.claim, extra="unauthorized"))
        with self.assertRaises(ValueError):
            self.ledger.append(dict(self.claim, schema_version="1.0"))

    def test_unsupported_or_mismatched_source_type_refused(self):
        wrong = copy.deepcopy(self.manifest)
        wrong["sources"][0]["source_kind"] = "cti_report"
        with closing(sqlite3.connect(":memory:")) as conn:
            g = EvidenceGraph(
                conn, evidence_verifier=EvidenceVerifier(wrong, self.root)
            )
            g.register_source_versions(wrong)
            with self.assertRaisesRegex(ValueError, "approved advisory"):
                CompoundSourcedClaimLedger(g).append(self.claim)

    def test_later_source_cannot_leak_into_early_view(self):
        later_packet = self._packet(self.later_raw, self.later_id)
        later_claim = self._claim(later_packet)
        late_cid = self.ledger.append(later_claim)
        self.ledger.append(self.claim)
        p = self.ledger.project(self.view)
        self.assertNotIn(late_cid, {x["claim_id"] for x in p["edges"]})
        self.assertNotIn("CVE-2024-99999", str(p))
        with self.assertRaisesRegex(ValueError, "post-cutoff"):
            self.ledger.project(self._view(sid=self.later_id))
        with self.assertRaises(ValueError):
            self.ledger.project(self._view(when="2023-01-01T00:00:00Z"))

    def test_view_metadata_hash_and_future_date_fails_closed(self):
        self.ledger.append(self.claim)
        view = self._view()
        view["sources"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            self.ledger.project(view)
        view = self._view()
        view["sources"][0]["role"] = "later"
        with self.assertRaises(ValueError):
            self.ledger.project(view)
        self.assertNotIn("later", self.ledger.project(self.view)["artifact_kind"])

    def test_wrong_review_provenance_and_decisions_refused(self):
        cid = self.ledger.append(self.claim)
        for key, value in [
            ("claim_id", "claim:" + "0" * 64),
            ("source_version_id", self.later_id),
            ("compound_evidence_sha256", "0" * 64),
            ("decision", "real-world-fact"),
            ("decision", ["supported_by_excerpt"]),
            ("reviewer_id", "email@example.com"),
            ("reviewed_at", "not UTC"),
            ("rationale", "too short"),
            ("schema_version", "semantic-evidence-v1"),
        ]:
            r = self._review(cid)
            r[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.ledger.review(r)

    def test_negative_or_uncertain_reviews_cannot_satisfy_strict_projection(self):
        for decision in ("unsupported_by_excerpt", "uncertain"):
            with self.subTest(decision=decision):
                with closing(sqlite3.connect(":memory:")) as db:
                    graph = EvidenceGraph(
                        db, evidence_verifier=EvidenceVerifier(self.manifest, self.root)
                    )
                    graph.register_source_versions(self.manifest)
                    led = CompoundSourcedClaimLedger(graph)
                    cid = led.append(self.claim)
                    led.review(self._review(cid, decision))
                    with self.assertRaises(ValueError):
                        led.project(self.view, require_supported=True)
                    self.assertEqual(decision, led.project(self.view)["edges"][0][
                        "semantic_review_status"
                    ])

    def test_conflicting_review_refused_and_record_stable(self):
        cid = self.ledger.append(self.claim)
        first = self.ledger.review(self._review(cid))
        change = self._review(cid, "uncertain")
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            self.ledger.review(change)
        self.assertEqual(first, self.ledger.project(self.view)["edges"][0]["review_id"])

    def test_offline_compound_runner_uses_approved_bytes_and_sealed_views(self):
        from scripts.project_compound_case import run
        complete = []
        for i, record in enumerate(self.sources):
            complete.append({
                **record,
                "title": "Synthetic GHSA fixture",
                "publisher": "Test only",
                "url": "https://example.org/fixture/" + str(i),
                "published_at": record["available_at"],
                "independence_group": "synthetic-group-" + str(i),
                "redistribution": "restricted",
                "selection_rationale": "Synthetic test fixture, not source approval",
            })
        sources = {
            "schema_version": "1.0", "dataset_id": "synthetic",
            "dataset_version": "fixture-v1", "sources": complete,
        }
        cases = {
            "schema_version": "1.0", "dataset_id": "synthetic",
            "dataset_version": "fixture-v1",
            "cases": [{
                "case_id": "case:fixture",
                "target_entity_id": "vulnerability:CVE-2024-21626",
                "selection_rationale": "Synthetic end-to-end compound case",
                "cutoff_at": "2024-02-01T00:00:00Z",
                "early_source_version_ids": [self.source_id],
                "background_source_version_ids": [],
                "later_reference_source_version_ids": [self.later_id],
            }],
        }
        claims_path = self.root / "claims.jsonl"
        claims_path.write_text(json.dumps(self.claim) + "\n", encoding="utf-8")
        result = run(sources, cases, "case:fixture", claims_path, self.root,
                     development_only=True)
        self.assertFalse(result["research_ready"])
        self.assertFalse(result["g1_ranker_input_eligible"])
        self.assertEqual(1, len(result["B0_compound_evidence"]["edges"]))
        self.assertEqual(1, len(result["G1_compound_evidence"]["edges"]))
        self.assertEqual("unreviewed", result["B0_compound_evidence"]["edges"][0][
            "semantic_review_status"])
        with self.assertRaises(ValueError):
            run(sources, cases, "case:fixture", claims_path, self.root)
        # Future label source never enters an early/inference claim file.
        later = self._claim(self._packet(self.later_raw, self.later_id))
        claims_path.write_text(json.dumps(later) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Disallowed historical source"):
            run(sources, cases, "case:fixture", claims_path, self.root,
                development_only=True)

    def test_incompatible_existing_tables_not_migrated(self):
        with closing(sqlite3.connect(":memory:")) as db:
            graph = EvidenceGraph(
                db, evidence_verifier=EvidenceVerifier(self.manifest, self.root)
            )
            graph.register_source_versions(self.manifest)
            db.execute("CREATE TABLE compound_sourced_claims_v1 (claim_id TEXT PRIMARY KEY)")
            with self.assertRaisesRegex(ValueError, "explicit migration"):
                CompoundSourcedClaimLedger(graph)
            self.assertEqual(1, len(db.execute(
                "PRAGMA table_info(compound_sourced_claims_v1)"
            ).fetchall()))


if __name__ == "__main__":
    unittest.main()
