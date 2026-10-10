"""Synthetic semantic evidence review and strict research gate tests."""

import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

from scripts.project_case_graph import run
from src.threatragraph.evidence_alignment import EvidenceVerifier
from src.threatragraph.evidence_graph import EvidenceGraph
from src.threatragraph.semantic_reviews import (
    REVIEW_SCHEMA_VERSION, SemanticReviewLedger, read_review_jsonl,
)


def h(value):
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def source(version, at):
    return {
        "source_id": "src:" + version,
        "source_version_id": version,
        "source_kind": "cti_report",
        "title": "Synthetic " + version,
        "publisher": "Fixture only",
        "url": "https://example.org/" + version,
        "status": "approved",
        "published_at": at,
        "available_at": at,
        "date_confidence": "verified",
        "date_evidence": "Synthetic fixture date",
        "independence_group": "group:" + version,
        "sha256": h(version),
        "redistribution": "restricted",
        "selection_rationale": "Synthetic fixture not historical evidence",
    }


def claim(version="src-01"):
    return {
        "source_version_id": version,
        "subject_id": "malware:fixture",
        "predicate": "USES",
        "object_id": "attack-technique:T1059",
        "assertion_kind": "report_assertion",
        "polarity": "positive",
        "evidence_locator": {
            "kind": "text_span", "segment_id": "seg:" + version,
            "start": 0, "end": len(version),
        },
        "evidence_sha256": h(version),
        "extractor_version": "synthetic/1",
    }


def review(claim_id, source_id="src-01", decision="supported_by_excerpt"):
    return {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "claim_id": claim_id,
        "source_version_id": source_id,
        "evidence_sha256": h(source_id),
        "decision": decision,
        "reviewer_id": "researcher-01",
        "reviewed_at": "2026-10-10T11:00:00Z",
        "rationale": "I manually checked that the cited excerpt supports this triple.",
    }


class SemanticReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.record = source("src-01", "2024-01-01T00:00:00Z")
        self.conn = sqlite3.connect(":memory:")
        digest = h("src-01")
        folder = self.root / digest[:2]
        folder.mkdir(parents=True, exist_ok=True)
        (folder / digest).write_bytes(b"src-01")
        self.graph = EvidenceGraph(
            self.conn,
            evidence_verifier=EvidenceVerifier(
                {"sources": [self.record]}, self.root
            ),
        )
        self.graph.register_source_versions({"sources": [self.record]})
        self.claim_id = self.graph.append_source_claim(claim())
        self.reviews = SemanticReviewLedger(self.conn)

    def tearDown(self):
        self.conn.close()
        self.temp.cleanup()

    def test_review_bindings_and_idempotence(self):
        r = review(self.claim_id)
        a = self.reviews.record(r)
        b = self.reviews.record(r)
        self.assertEqual(a, b)
        self.assertEqual(
            {self.claim_id: "supported_by_excerpt"},
            self.reviews.status({self.claim_id}, require_supported=True),
        )
        self.assertEqual(
            1, self.conn.execute("SELECT COUNT(*) FROM semantic_reviews").fetchone()[0]
        )

    def test_missing_review_fails_in_strict_mode(self):
        with self.assertRaisesRegex(ValueError, "missing/uncertain/unsupported"):
            self.reviews.status({self.claim_id}, require_supported=True)
        self.assertEqual(
            {self.claim_id: "unreviewed"},
            self.reviews.status({self.claim_id}, require_supported=False),
        )

    def test_uncertain_and_unsupported_fail_strict_mode(self):
        for decision in ("uncertain", "unsupported_by_excerpt"):
            with self.subTest(decision=decision):
                with sqlite3.connect(":memory:") as _:
                    pass
                # A separate ledger is needed because reviews are immutable.
                self.conn.execute("DELETE FROM semantic_reviews")
                self.reviews.record(review(self.claim_id, decision=decision))
                with self.assertRaisesRegex(ValueError, "missing/uncertain/unsupported"):
                    self.reviews.status({self.claim_id}, require_supported=True)
                self.assertEqual(decision, self.reviews.status(
                    {self.claim_id}, require_supported=False)[self.claim_id])

    def test_claim_id_and_source_digest_forgery_are_rejected(self):
        for change in (
            {"claim_id": "claim:" + "0" * 64},
            {"source_version_id": "src-999"},
            {"evidence_sha256": "0" * 64},
        ):
            with self.subTest(change=change):
                r = review(self.claim_id)
                r.update(change)
                with self.assertRaises(ValueError):
                    self.reviews.record(r)

    def test_conflicting_review_does_not_overwrite(self):
        r = review(self.claim_id)
        self.reviews.record(r)
        altered = review(self.claim_id, decision="uncertain")
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            self.reviews.record(altered)
        self.assertEqual(
            "supported_by_excerpt",
            self.reviews.status({self.claim_id}, require_supported=True)[self.claim_id]
        )

    def test_invalid_decision_reviewer_timestamp_and_rationale(self):
        for update in (
            {"decision": "confirmed_truth"},
            {"reviewer_id": "email@example.org"},
            {"reviewed_at": "not-a-utc-timestamp"},
            {"rationale": "yes"},
            {"schema_version": "unknown"},
            {"unexpected": True},
        ):
            with self.subTest(update=update):
                r = review(self.claim_id)
                r.update(update)
                with self.assertRaises(ValueError):
                    self.reviews.record(r)

    def test_no_claims_cannot_be_called_research_ready(self):
        with self.assertRaisesRegex(ValueError, "no extracted claims"):
            self.reviews.status(set(), require_supported=True)

    def test_unaligned_claim_cannot_receive_semantic_approval(self):
        self.conn.execute(
            "UPDATE sourced_claims SET evidence_status='unverified' WHERE claim_id=?",
            (self.claim_id,),
        )
        with self.assertRaisesRegex(ValueError, "byte-aligned"):
            self.reviews.record(review(self.claim_id))

    def test_parse_review_file_fails_closed(self):
        file = self.root / "review.jsonl"
        file.write_text(json.dumps(review(self.claim_id)) + "\n")
        self.assertEqual(1, len(read_review_jsonl(file)))
        file.write_text('{"malformed":')
        with self.assertRaisesRegex(ValueError, "Invalid JSON"):
            read_review_jsonl(file)


class StrictReviewRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archives = self.root / "archives"
        self.sources = []
        for i in range(1, 26):
            version = "src-" + str(i).zfill(2)
            available = (
                "2024-02-01T00:00:00Z" if i == 3 else "2024-01-01T00:00:00Z"
            )
            rec = source(version, available)
            self.sources.append(rec)
            digest = h(version)
            folder = self.archives / digest[:2]
            folder.mkdir(parents=True, exist_ok=True)
            (folder / digest).write_bytes(version.encode("utf-8"))
        self.manifest = {
            "schema_version": "1.0", "dataset_id": "synthetic",
            "dataset_version": "v1", "sources": self.sources,
        }
        self.cases = {
            "schema_version": "1.0", "dataset_id": "synthetic",
            "dataset_version": "v1",
            "cases": [{
                "case_id": "case-" + str(i),
                "target_entity_id": "malware:fixture",
                "selection_rationale": "Synthetic historical split",
                "cutoff_at": "2024-01-15T00:00:00Z",
                "early_source_version_ids": ["src-01"],
                "background_source_version_ids": ["src-02"],
                "later_reference_source_version_ids": ["src-03"],
            } for i in range(4)],
        }
        self.claims = self.root / "claims.jsonl"
        self.claims.write_text(json.dumps(claim()) + "\n")
        with sqlite3.connect(":memory:") as conn:
            ledger = EvidenceGraph(
                conn, evidence_verifier=EvidenceVerifier(self.manifest, self.archives)
            )
            ledger.register_source_versions(self.manifest)
            self.claim_id = ledger.append_source_claim(claim())
        self.review_file = self.root / "reviews.jsonl"

    def tearDown(self):
        self.temp.cleanup()

    def test_strict_runner_refuses_unreviewed_claims(self):
        with self.assertRaisesRegex(ValueError, "missing/uncertain/unsupported"):
            run(self.manifest, self.cases, "case-0",
                self.claims, self.archives, development=False)

    def test_strict_runner_accepts_verified_human_review_records(self):
        self.review_file.write_text(json.dumps(review(self.claim_id)) + "\n")
        output = run(self.manifest, self.cases, "case-0",
                     self.claims, self.archives, reviews_path=self.review_file)
        self.assertTrue(output["research_ready"])
        self.assertEqual("supported_by_excerpt",
                         output["B0"]["edges"][0]["semantic_review_status"])
        self.assertEqual("aligned", output["B0"]["edges"][0]["evidence_status"])
        self.assertEqual(1, len(output["G1"]["edges"]))

    def test_runner_rejects_review_for_unknown_or_later_claim(self):
        record = review("claim:" + "1" * 64)
        self.review_file.write_text(json.dumps(record) + "\n")
        with self.assertRaisesRegex(ValueError, "does not exist"):
            run(self.manifest, self.cases, "case-0", self.claims, self.archives,
                reviews_path=self.review_file)

    def test_development_without_review_remains_unreviewed(self):
        output = run(self.manifest, self.cases, "case-0",
                     self.claims, self.archives, development=True)
        self.assertFalse(output["research_ready"])
        self.assertEqual("unreviewed",
                         output["B0"]["edges"][0]["semantic_review_status"])

    def test_strict_runner_refuses_unassessable_review(self):
        self.review_file.write_text(json.dumps(
            review(self.claim_id, decision="uncertain")
        ) + "\n")
        with self.assertRaisesRegex(ValueError, "missing/uncertain/unsupported"):
            run(self.manifest, self.cases, "case-0", self.claims,
                self.archives, reviews_path=self.review_file)


if __name__ == "__main__":
    unittest.main()
