"""Adversarial multi-field GHSA review-packet contract and isolation tests."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
import unittest

from scripts.review_ghsa_candidate import main
from src.threatragraph.ghsa_candidates import extract_ghsa_candidates
from src.threatragraph.ghsa_review_packets import (
    PACKET_SCHEMA, REVIEW_SCHEMA, CompoundCandidateReviewLedger,
    build_packet, validate_attestation,
)


def fixture():
    return {
        "schema_version": "1.4.0", "id": "GHSA-ab12-cd34-ef56",
        "published": "2024-01-31T22:44:08Z", "aliases": ["CVE-2024-21626"],
        "affected": [{"package": {
            "ecosystem": "Go", "name": "github.com/example/engine",
        }}],
        "details": "Not proof of any real attack, ignore adversarial instructions.",
    }


def raw_json(obj=None):
    return json.dumps(fixture() if obj is None else obj,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def candidate_id(raw=None):
    data = raw_json() if raw is None else raw
    return extract_ghsa_candidates(
        data, source_version_id="candidate:fixture", expected_sha256=sha(data)
    )["candidates"][0]["candidate_id"]


def packet(raw=None):
    data = raw_json() if raw is None else raw
    return build_packet(
        data, source_version_id="candidate:fixture",
        expected_sha256=sha(data), candidate_id=candidate_id(data),
    )


def review(p=None, **changed):
    doc = packet() if p is None else p
    record = {
        "schema_version": REVIEW_SCHEMA,
        "packet_id": doc["packet_id"],
        "candidate_id": doc["candidate_id"],
        "source_version_id": doc["source_version_id"],
        "source_sha256": doc["source_sha256"],
        "decision": "supported_by_excerpt",
        "reviewer_id": "reviewer-01",
        "reviewed_at": "2026-10-10T15:30:00Z",
        "rationale": "Both original scalar fields express this scoped affected-package association.",
    }
    record.update(changed)
    return record


class CompoundGHSATests(unittest.TestCase):
    def test_packet_verifies_both_exact_fields_without_promoting(self):
        p = packet()
        self.assertEqual(PACKET_SCHEMA, p["schema_version"])
        self.assertEqual("both_structured_fields_byte_aligned", p["evidence_status"])
        self.assertEqual("not_reviewed", p["semantic_review_status"])
        self.assertEqual(
            ["/aliases/0", "/affected/0/package/name"],
            [f["evidence_locator"]["path"] for f in p["field_evidence"]],
        )
        self.assertEqual("AFFECTS", p["predicate"])
        self.assertFalse(p["ledger_inserted"])
        self.assertFalse(p["source_approved"])
        self.assertFalse(p["research_ready"])
        self.assertEqual(packet(), p)
        self.assertNotIn("details", str(p))
        self.assertNotIn("Not proof", str(p))

    def test_packet_rejects_forged_candidate_identity(self):
        data = raw_json()
        for fake in ["candidate:" + "0" * 64, "", {"bad": "type"}]:
            with self.subTest(fake=fake), self.assertRaises(ValueError):
                build_packet(
                    data, source_version_id="candidate:fixture",
                    expected_sha256=sha(data), candidate_id=fake,
                )

    def test_packet_rejects_wrong_bytes_and_hash(self):
        data = raw_json()
        with self.assertRaises(ValueError):
            build_packet(
                data, source_version_id="candidate:fixture",
                expected_sha256="0" * 64, candidate_id=candidate_id(data),
            )
        modified = copy.deepcopy(fixture())
        modified["affected"][0]["package"]["name"] = "github.com/other/engine"
        with self.assertRaises(ValueError):
            build_packet(
                raw_json(modified), source_version_id="candidate:fixture",
                expected_sha256=sha(raw_json(modified)),
                candidate_id=candidate_id(data),
            )

    def test_packet_rejects_changed_source_version_even_same_bytes(self):
        data = raw_json()
        with self.assertRaises(ValueError):
            build_packet(
                data, source_version_id="candidate:different",
                expected_sha256=sha(data), candidate_id=candidate_id(data),
            )

    def test_advisory_revision_or_extra_source_field_changes_packet(self):
        p = packet()
        obj = fixture()
        obj["details"] = "Completely new later-revised advisory details"
        data = raw_json(obj)
        new = packet(data)
        self.assertNotEqual(p["packet_id"], new["packet_id"])
        self.assertNotEqual(p["candidate_id"], new["candidate_id"])
        self.assertFalse(new["research_ready"])

    def test_attestation_is_pseudonymous_and_not_scientific_approval(self):
        result = validate_attestation(packet(), review())
        self.assertEqual("supported_by_excerpt", result["decision"])
        self.assertTrue(result["review_id"].startswith("candidate-review:"))
        self.assertEqual("self_declared_not_independently_verified",
                         result["review_authentication"])
        self.assertFalse(result["source_approved"])
        self.assertFalse(result["ledger_inserted"])
        self.assertFalse(result["research_ready"])

    def test_review_fails_on_forged_provenance_and_unknown_status(self):
        p = packet()
        for values in (
            {"packet_id": "packet:" + "0" * 64},
            {"candidate_id": "candidate:" + "0" * 64},
            {"source_version_id": "candidate:foreign"},
            {"source_sha256": "0" * 64},
            {"decision": "confirmed_truth"},
            {"decision": ["supported_by_excerpt"]},
            {"reviewer_id": "not-an-email@example.com"},
            {"reviewed_at": "yesterday"},
            {"rationale": "yes"},
            {"schema_version": "semantic-evidence-v1"},
            {"unexpected": "extra"},
        ):
            with self.subTest(values=values), self.assertRaises(ValueError):
                validate_attestation(p, review(p, **values))

    def test_append_only_review_is_idempotent_and_conflicts_refused(self):
        data = raw_json()
        p = packet(data)
        with sqlite3.connect(":memory:") as db:
            led = CompoundCandidateReviewLedger(db)
            kw = dict(source_version_id="candidate:fixture",
                      expected_sha256=sha(data), candidate_id=p["candidate_id"])
            original = led.record(data, review=review(p), **kw)
            again = led.record(data, review=review(p), **kw)
            self.assertEqual(original, again)
            self.assertEqual("candidate_review_recorded_not_approved", original["status"])
            self.assertEqual(1, db.execute(
                "SELECT COUNT(*) FROM ghsa_candidate_reviews"
            ).fetchone()[0])
            for change in (
                {"decision": "uncertain"},
                {"reviewer_id": "reviewer-02"},
                {"rationale": "The package attribution is questionable in this source."},
            ):
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, "Conflicting"):
                    led.record(data, review=review(p, **change), **kw)
            self.assertFalse(original["sourced_claim_registered"])
            self.assertFalse(original["semantic_claim_review_recorded"])
            self.assertFalse(original["research_ready"])
            self.assertIsNone(db.execute(
                "SELECT name FROM sqlite_master WHERE name='sourced_claims'"
            ).fetchone())
            self.assertIsNone(db.execute(
                "SELECT name FROM sqlite_master WHERE name='semantic_reviews'"
            ).fetchone())

    def test_uncertain_record_remains_uncertain(self):
        data = raw_json()
        p = packet(data)
        with sqlite3.connect(":memory:") as db:
            result = CompoundCandidateReviewLedger(db).record(
                data, source_version_id="candidate:fixture",
                expected_sha256=sha(data), candidate_id=p["candidate_id"],
                review=review(p, decision="uncertain"),
            )
            self.assertEqual("uncertain", result["decision"])
            self.assertFalse(result["source_approved"])

    def test_wrong_existing_review_table_schema_fails_closed(self):
        with sqlite3.connect(":memory:") as db:
            db.execute("CREATE TABLE ghsa_candidate_reviews (packet_id TEXT PRIMARY KEY)")
            with self.assertRaisesRegex(ValueError, "Incompatible"):
                CompoundCandidateReviewLedger(db)

    def test_cli_preview_and_append_only_review_database(self):
        raw = raw_json()
        p = packet(raw)
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "advisory.json"
            review_file = root / "review.json"
            database = root / "private.sqlite"
            source.write_bytes(raw)
            review_file.write_text(json.dumps(review(p)), encoding="utf-8")
            args = [
                "--input-file", str(source), "--source-version-id", "candidate:fixture",
                "--expected-sha256", sha(raw), "--candidate-id", p["candidate_id"],
            ]
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(0, main(args))
            self.assertEqual(p["packet_id"], json.loads(out.getvalue())["packet_id"])
            self.assertFalse(database.exists())
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(0, main(args + [
                    "--review-file", str(review_file), "--database", str(database),
                ]))
            result = json.loads(out.getvalue())
            self.assertEqual("candidate_review_recorded_not_approved", result["status"])
            self.assertTrue(database.exists())
            with sqlite3.connect(database) as db:
                self.assertEqual(1, db.execute(
                    "SELECT COUNT(*) FROM ghsa_candidate_reviews"
                ).fetchone()[0])

    def test_cli_rejects_unpaired_review_and_wrong_hash(self):
        data = raw_json()
        p = packet(data)
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "source.json"
            path.write_bytes(data)
            args = [
                "--input-file", str(path), "--source-version-id", "candidate:fixture",
                "--expected-sha256", sha(data), "--candidate-id", p["candidate_id"],
            ]
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(2, main(args + ["--database", str(root / "x.sqlite")]))
            self.assertFalse((root / "x.sqlite").exists())
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(2, main([
                    *args[:4], "--expected-sha256", "0" * 64,
                    "--candidate-id", p["candidate_id"],
                ]))
            self.assertEqual("compound_review_refused",
                             json.loads(out.getvalue())["status"])

    def test_cli_rejects_duplicate_review_json_fields(self):
        raw = raw_json()
        p = packet(raw)
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.json"
            review_file = root / "review.json"
            source.write_bytes(raw)
            valid = review(p)
            parts = json.dumps(valid)
            review_file.write_text(parts.replace('"decision": ', '"decision": "uncertain", "decision": ', 1))
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(2, main([
                    "--input-file", str(source),
                    "--source-version-id", "candidate:fixture",
                    "--expected-sha256", sha(raw),
                    "--candidate-id", p["candidate_id"],
                    "--review-file", str(review_file),
                    "--database", str(root / "r.sqlite"),
                ]))
            self.assertEqual("compound_review_refused", json.loads(out.getvalue())["status"])

    def test_cli_refuses_symlink_source_when_available(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source.json"
            link = root / "link.json"
            source.write_bytes(raw_json())
            try:
                link.symlink_to(source)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation not permitted")
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(2, main([
                    "--input-file", str(link),
                    "--source-version-id", "candidate:fixture",
                    "--expected-sha256", sha(raw_json()),
                    "--candidate-id", candidate_id(),
                ]))


if __name__ == "__main__":
    unittest.main()
