"""Offline synthetic source-to-graph-to-B0/G1 orchestrator tests.

No real historical case is approved, evaluated or scored by these fixtures.
"""
import copy
import hashlib
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from scripts.freeze_case_snapshots import case_views, snapshot_sha256, write_immutable_view
from scripts.project_case_graph import run as project_case_graph
from scripts.run_offline_case_pipeline import main, run_offline_case
from src.threatragraph.evidence_graph import fingerprint
from src.threatragraph.feature_lineage import (
    ARTIFACT_KIND, CONTRACT_VERSION, EXTRACTION, IDENTITY_POLICY,
    graph_claim_set_sha256,
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def sha(value):
    return digest(value.encode("utf-8"))


def claim(version, subject, predicate, target):
    return {
        "source_version_id": version, "subject_id": subject,
        "predicate": predicate, "object_id": target,
        "assertion_kind": "report_assertion", "polarity": "positive",
        "evidence_locator": {
            "kind": "text_span", "segment_id": "seg:" + version,
            "start": 0, "end": 5,
        },
        "evidence_sha256": sha(version[:5]),
        "extractor_version": "synthetic-v1",
    }


def review(claim_record):
    canonical = {
        "schema_version": "1.0",
        **claim_record,
    }
    return {
        "schema_version": "semantic-evidence-v1",
        "claim_id": "claim:" + fingerprint(canonical),
        "source_version_id": claim_record["source_version_id"],
        "evidence_sha256": claim_record["evidence_sha256"],
        "decision": "supported_by_excerpt",
        "reviewer_id": "FixtureReviewer",
        "reviewed_at": "2024-01-10T00:00:00Z",
        "rationale": "Synthetic excerpt states the modeled relation",
    }


class OfflineCasePipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.archive = self.root / "archives"
        specs = [
            ("early", "2024-01-01T00:00:00Z", "early-publisher"),
            ("background-a", "2023-12-01T00:00:00Z", "background-a-group"),
            ("background-b", "2023-12-01T00:00:00Z", "background-b-group"),
            ("heldout", "2024-02-01T00:00:00Z", "later-publisher"),
        ]
        records = []
        for name, timestamp, group in specs:
            content = name.encode("utf-8")
            hashval = digest(content)
            folder = self.archive / hashval[:2]
            folder.mkdir(exist_ok=True, parents=True)
            (folder / hashval).write_bytes(content)
            records.append({
                "source_id": "src:" + name,
                "source_version_id": name,
                "source_kind": "cti_report", "title": "Synthetic " + name,
                "publisher": "Fixture", "url": "https://example.org/" + name,
                "status": "approved",
                "published_at": timestamp, "available_at": timestamp,
                "date_confidence": "verified",
                "date_evidence": "Synthetic fixture chronology only",
                "independence_group": group, "sha256": hashval,
                "redistribution": "restricted",
                "selection_rationale": "Synthetic case exercise only",
            })
        self.sources = {
            "schema_version": "1.0", "dataset_id": "fixture",
            "dataset_version": "v1", "sources": records,
        }
        self.cases = {
            "schema_version": "1.0", "dataset_id": "fixture",
            "dataset_version": "v1",
            "cases": [{
                "case_id": "case-a", "target_entity_id": "malware:early",
                "selection_rationale": "Synthetic parity exercise",
                "cutoff_at": "2024-01-15T00:00:00Z",
                "early_source_version_ids": ["early"],
                "background_source_version_ids": ["background-a", "background-b"],
                "later_reference_source_version_ids": ["heldout"],
            }],
        }
        self.claims = [
            claim("early", "malware:early", "USES", "attack-technique:T1059"),
            claim("background-a", "malware:peer", "USES",
                  "attack-technique:T1059"),
            claim("background-b", "malware:peer", "HAS_BEHAVIOR",
                  "attack-behavior:exec"),
        ]
        self.claim_path = self.root / "claims.jsonl"
        self.claim_path.write_text(
            "".join(json.dumps(item) + "\n" for item in self.claims),
            encoding="utf-8",
        )
        self.review_path = self.root / "reviews.jsonl"
        self.review_path.write_text(
            "".join(json.dumps(review(item)) + "\n" for item in self.claims),
            encoding="utf-8",
        )
        self.lock_file = self.root / "dependency-lock.txt"
        self.lock_file.write_bytes(b"synthetic pinned dependencies")
        self.views = case_views(self.sources, self.cases, "case-a")
        projected = project_case_graph(
            self.sources, self.cases, "case-a",
            self.claim_path, self.archive,
            development=True, reviews_path=self.review_path,
        )
        g1_graph = projected["G1"]
        known = {
            entry["source_version_id"]: entry
            for entry in self.views["G1"]["sources"]
        }
        self.lineage = {
            "schema_version": CONTRACT_VERSION,
            "artifact_kind": ARTIFACT_KIND,
            "case_id": "case-a",
            "cutoff_at": self.views["G1"]["cutoff_at"],
            "g1_source_view_sha256": fingerprint(self.views["G1"]),
            "g1_graph_sha256": graph_claim_set_sha256(g1_graph),
            "identity_policy": IDENTITY_POLICY,
            "claim_lineage": [
                {
                    "claim_id": edge["claim_id"],
                    "source_version_id": edge["source_version_id"],
                    "source_sha256": known[edge["source_version_id"]]["sha256"],
                    "source_available_at": known[edge["source_version_id"]]["available_at"],
                    "claim_evidence_sha256": edge["evidence_sha256"],
                    "subject_id": edge["subject_id"],
                    "predicate": edge["predicate"],
                    "object_id": edge["object_id"],
                    "feature_known_at": known[edge["source_version_id"]]["available_at"],
                    "derivation": EXTRACTION,
                }
                for edge in sorted(g1_graph["edges"], key=lambda edge: edge["claim_id"])
            ],
            "limitations": "Synthetic declared source time and review metadata only",
        }
        self.metadata = {
            "git_commit_sha": "a" * 40,
            "dependency_lock_sha256": digest(self.lock_file.read_bytes()),
            "source_manifest_sha256": fingerprint(self.sources),
            "case_manifest_sha256": fingerprint(self.cases),
            "review_set_sha256": digest(self.review_path.read_bytes()),
            "ontology_version": "v1",
            "extractor_version": "synthetic-v1",
            "ruleset_version": "no-mapping-v1",
            "random_seed": None,
        }
        self.config = {
            "top_k": 5, "min_overlap": 1,
            "min_background_groups": 2, "max_peers_per_feature": 10,
        }

    def tearDown(self):
        self.temp.cleanup()

    def build(self, *, sources=None, cases=None, lineage=None,
              metadata=None, claims_path=None, reviews_path=None,
              dependency_path=None):
        return run_offline_case(
            self.sources if sources is None else sources,
            self.cases if cases is None else cases,
            "case-a",
            self.claim_path if claims_path is None else claims_path,
            self.archive,
            self.lineage if lineage is None else lineage,
            self.metadata if metadata is None else metadata,
            self.config,
            dependency_lock_path=(self.lock_file if dependency_path is None
                                  else dependency_path),
            reviews_path=(self.review_path if reviews_path is None
                          else reviews_path),
            development_only=True,
        )

    def test_real_byte_backed_synthetic_end_to_end_one_prediction(self):
        run = self.build()
        self.assertEqual(1, len(run["b0_profile"]["facts"]))
        self.assertEqual(1, len(run["g1_profile"]["predictions"]))
        self.assertEqual("HAS_BEHAVIOR",
                         run["g1_profile"]["predictions"][0]["predicate"])
        self.assertEqual(run["b0_profile"]["facts"],
                         run["g1_profile"]["observed_early_facts"])
        self.assertFalse(run["pipeline_receipt"]["heldout_labels_opened"])
        self.assertFalse(run["pipeline_receipt"]["research_ready"])
        self.assertNotIn('"source_version_id": "heldout"', json.dumps(run))

    def test_deterministic_case_outputs_and_run_ids(self):
        self.assertEqual(self.build(), self.build())

    def test_tampered_archive_refused(self):
        item = self.sources["sources"][0]
        path = self.archive / item["sha256"][:2] / item["sha256"]
        path.write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "Source bytes"):
            self.build()

    def test_heldout_claim_input_refused_before_any_profile(self):
        self.claim_path.open("a", encoding="utf-8").write(
            json.dumps(claim("heldout", "malware:future", "USES",
                             "attack-technique:T1059")) + "\n"
        )
        with self.assertRaisesRegex(ValueError, "Disallowed historical source"):
            self.build()

    def test_smuggled_gold_context_in_claims_rejected(self):
        records = copy.deepcopy(self.claims)
        records[0]["gold_labels"] = {"future": "true"}
        self.claim_path.write_text(
            "".join(json.dumps(item) + "\n" for item in records),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "Unknown fields"):
            self.build()

    def test_duplicate_claim_json_keys_rejected(self):
        original = self.claim_path.read_text(encoding="utf-8")
        original = original.replace('"polarity": "positive"',
                                    '"polarity": "positive", "polarity": "positive"',
                                    1)
        self.claim_path.write_text(original, encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            self.build()

    def test_unreviewed_or_unlisted_feature_lineage_not_fabricated(self):
        altered = copy.deepcopy(self.lineage)
        altered["claim_lineage"] = altered["claim_lineage"][:-1]
        with self.assertRaisesRegex(ValueError, "One as-of lineage"):
            self.build(lineage=altered)

    def test_future_feature_known_at_refused(self):
        altered = copy.deepcopy(self.lineage)
        altered["claim_lineage"][0]["feature_known_at"] = "2026-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "historical source cutoff"):
            self.build(lineage=altered)

    def test_forged_local_case_manifest_hash_rejected(self):
        altered = copy.deepcopy(self.metadata)
        altered["case_manifest_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "local bytes"):
            self.build(metadata=altered)

    def test_modified_dependency_lock_rejected(self):
        self.lock_file.write_bytes(b"new unpinned version")
        with self.assertRaisesRegex(ValueError, "local bytes"):
            self.build()

    def test_modified_review_bytes_rejected(self):
        self.review_path.open("a", encoding="utf-8").write("\n")
        with self.assertRaisesRegex(ValueError, "local bytes"):
            self.build()

    def test_forbidden_gold_context_in_review_file_rejected(self):
        record = review(self.claims[0])
        record["later_answer"] = True
        self.review_path.write_text(json.dumps(record), encoding="utf-8")
        metadata = copy.deepcopy(self.metadata)
        metadata["review_set_sha256"] = digest(self.review_path.read_bytes())
        with self.assertRaisesRegex(ValueError, "Unknown fields"):
            self.build(metadata=metadata)

    def test_strict_pipeline_without_reviews_rejected(self):
        with self.assertRaisesRegex(ValueError, "requires separately"):
            run_offline_case(
                self.sources, self.cases, "case-a", self.claim_path,
                self.archive, self.lineage, self.metadata, self.config,
                dependency_lock_path=self.lock_file,
                reviews_path=None, development_only=False,
            )

    def test_content_addressed_paired_outputs_round_trip(self):
        result = self.build()
        with tempfile.TemporaryDirectory() as output:
            for artifact in result.values():
                expected = snapshot_sha256(artifact)
                actual, path, created = write_immutable_view(artifact, output)
                self.assertEqual(expected, actual)
                self.assertTrue(created)
                self.assertEqual(artifact,
                                 json.loads(path.read_text(encoding="utf-8")))

    def test_cli_preview_prints_only_receipts_not_archive_text(self):
        names = {
            "sources": self.sources, "cases": self.cases,
            "lineage": self.lineage, "metadata": self.metadata,
            "config": self.config,
        }
        for name, data in names.items():
            (self.root / (name + ".json")).write_text(
                json.dumps(data), encoding="utf-8"
            )
        args = [
            "--sources", str(self.root / "sources.json"),
            "--cases", str(self.root / "cases.json"),
            "--case-id", "case-a",
            "--claims", str(self.claim_path),
            "--archive-root", str(self.archive),
            "--feature-lineage", str(self.root / "lineage.json"),
            "--metadata", str(self.root / "metadata.json"),
            "--g1-config", str(self.root / "config.json"),
            "--dependency-lock", str(self.lock_file),
            "--reviews", str(self.review_path),
            "--development-only",
        ]
        output = StringIO()
        with redirect_stdout(output):
            status = main(args)
        self.assertEqual(0, status)
        result = json.loads(output.getvalue())
        self.assertEqual("offline_case_preview", result["status"])
        self.assertFalse(result["heldout_labels_opened"])
        self.assertFalse(result["research_ready"])
        self.assertNotIn("Synthetic fixture chronology", output.getvalue())

    def test_unapproved_corpus_cannot_become_strict_study(self):
        with self.assertRaisesRegex(ValueError, "manifest validation"):
            run_offline_case(
                self.sources, self.cases, "case-a", self.claim_path,
                self.archive, self.lineage, self.metadata, self.config,
                dependency_lock_path=self.lock_file,
                reviews_path=self.review_path, development_only=False,
            )


if __name__ == "__main__":
    unittest.main()
