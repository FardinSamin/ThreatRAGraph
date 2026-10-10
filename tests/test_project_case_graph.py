"""End-to-end graph projection CLI fixtures, entirely synthetic and offline."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.project_case_graph import load_claims, run


def h(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sample_source(name, date, group):
    return {
        "source_id": "src:" + name, "source_version_id": name,
        "source_kind": "cti_report", "title": "Synthetic " + name,
        "publisher": "Test-only", "url": "https://example.org/" + name,
        "status": "approved", "published_at": date, "available_at": date,
        "date_confidence": "verified", "date_evidence": "Test-only fixture chronology",
        "independence_group": group, "sha256": h(name),
        "redistribution": "restricted", "selection_rationale": "Synthetic test",
    }


def data():
    src = {
        "schema_version": "1.0", "dataset_id": "fixture", "dataset_version": "v1",
        "sources": [
            sample_source("early", "2024-01-01T00:00:00Z", "one"),
            sample_source("background", "2023-12-01T00:00:00Z", "two"),
            sample_source("heldout", "2024-02-01T00:00:00Z", "three"),
        ],
    }
    cases = {
        "schema_version": "1.0", "dataset_id": "fixture", "dataset_version": "v1",
        "cases": [{
            "case_id": "case-test", "target_entity_id": "malware:early",
            "selection_rationale": "Synthetic fixture", "cutoff_at": "2024-01-15T00:00:00Z",
            "early_source_version_ids": ["early"],
            "background_source_version_ids": ["background"],
            "later_reference_source_version_ids": ["heldout"],
        }],
    }
    return src, cases


def claim(version):
    return {
        "source_version_id": version,
        "subject_id": "malware:" + version,
        "predicate": "USES", "object_id": "attack-technique:T1059",
        "assertion_kind": "report_assertion", "polarity": "positive",
        "evidence_locator": {
            "kind": "text_span", "segment_id": "seg:" + version,
            "start": 0, "end": 5
        },
        "evidence_sha256": h("quote" + version),
        "extractor_version": "synthetic-parser-v1",
    }


def fixture_archives(root):
    for name in ("early", "background", "heldout"):
        digest = h(name)
        directory = Path(root) / digest[:2]
        directory.mkdir(exist_ok=True, parents=True)
        (directory / digest).write_bytes(name.encode("utf-8"))


class CaseGraphRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archives = self.root / "archives"
        fixture_archives(self.archives)
        self.claims_file = self.root / "claims.jsonl"
        self.src, self.cases = data()
        self.claims_file.write_text(
            json.dumps(claim("early")) + "\n" +
            json.dumps(claim("background")) + "\n", encoding="utf-8"
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_development_graph_has_only_permitted_source_claims(self):
        output = run(
            self.src, self.cases, "case-test", self.claims_file,
            self.archives, development=True,
        )
        self.assertEqual("development_only", output["status"])
        self.assertFalse(output["research_ready"])
        self.assertEqual(1, len(output["B0"]["edges"]))
        self.assertEqual(2, len(output["G1"]["edges"]))
        self.assertNotIn("heldout", str(output))
        self.assertEqual("early", output["B0"]["edges"][0]["source_version_id"])

    def test_future_reference_claim_is_rejected_not_ignored(self):
        with self.claims_file.open("a") as file:
            file.write(json.dumps(claim("heldout")) + "\n")
        with self.assertRaisesRegex(ValueError, "Disallowed historical source"):
            run(self.src, self.cases, "case-test",
                self.claims_file, self.archives, development=True)

    def test_corrupted_raw_archive_fails_before_graph_build(self):
        digest = h("early")
        (self.archives / digest[:2] / digest).write_bytes(b"corrupted")
        with self.assertRaisesRegex(ValueError, "Source bytes not all verified"):
            run(self.src, self.cases, "case-test",
                self.claims_file, self.archives, development=True)

    def test_incomplete_real_corpus_refused_without_dev_flag(self):
        with self.assertRaisesRegex(ValueError, "manifest validation failed"):
            run(self.src, self.cases, "case-test",
                self.claims_file, self.archives, development=False)

    def test_unapproved_source_in_claims_refused(self):
        with self.claims_file.open("a") as file:
            file.write(json.dumps(claim("unknown-source")) + "\n")
        with self.assertRaises(ValueError):
            run(self.src, self.cases, "case-test",
                self.claims_file, self.archives, development=True)

    def test_oversized_claim_input_rejected(self):
        self.claims_file.write_bytes(b"a" * (5 * 1024 * 1024 + 1))
        with self.assertRaisesRegex(ValueError, "limit"):
            load_claims(self.claims_file, {"early"})

    def test_empty_claims_allowed_but_not_fabricated(self):
        self.claims_file.write_text("", encoding="utf-8")
        result = run(self.src, self.cases, "case-test",
                     self.claims_file, self.archives, development=True)
        self.assertEqual([], result["B0"]["edges"])
        self.assertEqual([], result["G1"]["edges"])


if __name__ == "__main__":
    unittest.main()
