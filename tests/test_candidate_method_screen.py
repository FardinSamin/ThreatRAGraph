"""Prospective SCARLETEEL campaign screen: real source leads, zero approvals."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.screen_candidate_method import SCREEN_VERSION, assess_screen, main

ROOT = Path(__file__).resolve().parents[1]


class ProspectiveCaseScreenTests(unittest.TestCase):
    def setUp(self):
        self.screen = json.loads(
            (ROOT / "datasets/case_screenings/scarleteel.json").read_text(encoding="utf-8")
        )
        self.sources = json.loads(
            (ROOT / "datasets/manifests/pilot.json").read_text(encoding="utf-8")
        )

    def test_real_candidate_registry_screen_is_not_case_approval(self):
        result = assess_screen(self.screen, self.sources)
        self.assertEqual(SCREEN_VERSION, result["schema_version"])
        self.assertTrue(result["g1_v2_subject_type_and_early_predicate_plausible"])
        self.assertEqual(1, result["provisional_early_feature_count"])
        self.assertEqual(2, result["declared_background_publisher_groups"])
        self.assertFalse(result["two_group_same_type_peer_claim_support_verified"])
        self.assertFalse(result["g1_evaluation_eligible"])
        self.assertFalse(result["original_source_bytes_and_dates_approved"])
        self.assertFalse(result["case_approved"])
        self.assertFalse(result["research_ready"])
        self.assertEqual(0, result["screened_source_versions_approved"])
        self.assertEqual(0, result["experimental_predictions"])
        self.assertTrue(result["independent_blinded_later_labeling_required"])
        self.assertEqual(30, len(self.sources["sources"]))
        self.assertFalse(any(s["status"] == "approved" for s in self.sources["sources"]))

    def test_registered_early_source_has_no_fabricated_approval_metadata(self):
        early = set(self.screen["early_source_version_ids"])
        items = [s for s in self.sources["sources"]
                 if s["source_version_id"] in early]
        self.assertEqual(1, len(items))
        self.assertEqual("candidate", items[0]["status"])
        self.assertIsNone(items[0]["available_at"])
        self.assertIsNone(items[0]["sha256"])
        self.assertEqual("unknown", items[0]["date_confidence"])

    def test_screen_refuses_any_claim_to_research_approval(self):
        for key in ("case_approved", "research_ready",
                    "same_type_background_peers_verified",
                    "two_group_peer_relation_support_verified"):
            screen = copy.deepcopy(self.screen)
            screen[key] = True
            with self.subTest(key=key), self.assertRaises(ValueError):
                assess_screen(screen, self.sources)

    def test_bad_ontology_subject_and_predicate_cannot_make_false_fit(self):
        for key, value in (
            ("target_entity_id", "vulnerability:CVE-2024-21626"),
            ("target_entity_id", "malware:SCARLETEEL"),
            ("target_entity_id", "campaign:SCARLETEEL:fake"),
        ):
            screen = copy.deepcopy(self.screen)
            screen[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                assess_screen(screen, self.sources)
        for key, value in (
            ("predicate", "AFFECTS"), ("predicate", "TARGETS"),
            ("subject_id", "malware:fixture"),
            ("object_id", "vulnerability:CVE-2024-21626"),
            ("source_version_id", self.screen["later_reference_source_version_ids"][0]),
            ("evidence_byte_aligned", True), ("semantic_reviewed", True),
        ):
            screen = copy.deepcopy(self.screen)
            screen["early_feature_candidates"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                assess_screen(screen, self.sources)

    def test_future_reference_not_accepted_as_initial_source(self):
        s = copy.deepcopy(self.screen)
        s["early_source_version_ids"] = self.screen["later_reference_source_version_ids"]
        with self.assertRaisesRegex(ValueError, "multiple roles"):
            assess_screen(s, self.sources)

    def test_repeated_source_in_partitions_fails(self):
        s = copy.deepcopy(self.screen)
        s["background_source_version_ids"][0] = s["early_source_version_ids"][0]
        with self.assertRaisesRegex(ValueError, "multiple roles"):
            assess_screen(s, self.sources)

    def test_background_mirrors_do_not_count_as_independent(self):
        manifest = copy.deepcopy(self.sources)
        bg0, bg1 = self.screen["background_source_version_ids"]
        for record in manifest["sources"]:
            if record["source_version_id"] == bg1:
                record["independence_group"] = next(
                    s["independence_group"] for s in manifest["sources"]
                    if s["source_version_id"] == bg0
                )
        with self.assertRaisesRegex(ValueError, "two independent"):
            assess_screen(self.screen, manifest)

    def test_contemporaneous_derived_reporting_must_share_early_group(self):
        manifest = copy.deepcopy(self.sources)
        corroboration = self.screen["date_corroboration_source_version_ids"][0]
        for record in manifest["sources"]:
            if record["source_version_id"] == corroboration:
                record["independence_group"] = "invented-independent-publisher"
        with self.assertRaisesRegex(ValueError, "derivative"):
            assess_screen(self.screen, manifest)

    def test_candidate_source_cannot_be_promoted_without_real_approval(self):
        source = self.screen["early_source_version_ids"][0]
        for key, value in (
            ("status", "approved"), ("available_at", "2023-02-28T16:00:00Z"),
            ("sha256", "f" * 64), ("date_confidence", "verified"),
        ):
            manifest = copy.deepcopy(self.sources)
            for rec in manifest["sources"]:
                if rec["source_version_id"] == source:
                    rec[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                assess_screen(self.screen, manifest)

    def test_screen_does_not_include_later_body_or_prediction_labels(self):
        for extra in ("later_report_text", "gold_labels", "predictions",
                      "approved_candidate_edges"):
            altered = copy.deepcopy(self.screen)
            altered[extra] = ["future-derived"]
            with self.subTest(extra=extra), self.assertRaisesRegex(
                ValueError, "unsupported or missing fields"
            ):
                assess_screen(altered, self.sources)

    def test_unbounded_or_missing_feature_refused(self):
        for features in ([], self.screen["early_feature_candidates"] * 13):
            screen = copy.deepcopy(self.screen)
            screen["early_feature_candidates"] = features
            with self.assertRaises(ValueError):
                assess_screen(screen, self.sources)

    def test_unknown_source_and_extra_partition_fields_refused(self):
        s = copy.deepcopy(self.screen)
        s["background_source_version_ids"][0] = "candidate:unknown:unfrozen"
        with self.assertRaisesRegex(ValueError, "does not exist"):
            assess_screen(s, self.sources)
        s = copy.deepcopy(self.screen)
        s["schema_version"] = "future"
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            assess_screen(s, self.sources)

    def test_later_preview_exposure_requires_externally_blind_labeler(self):
        s = copy.deepcopy(self.screen)
        s["later_reference_preview_exposure"] = "none_reported"
        result = assess_screen(s, self.sources)
        self.assertFalse(result["independent_blinded_later_labeling_required"])
        self.assertFalse(result["research_ready"])
        s["later_reference_preview_exposure"] = "later_facts_preselected"
        with self.assertRaises(ValueError):
            assess_screen(s, self.sources)

    def test_cli_candidate_screen_ok_but_research_false(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(0, main([
                "--screen", str(ROOT / "datasets/case_screenings/scarleteel.json"),
                "--manifest", str(ROOT / "datasets/manifests/pilot.json"),
            ]))
        result = json.loads(out.getvalue())
        self.assertFalse(result["research_ready"])
        self.assertFalse(result["g1_evaluation_eligible"])

    def test_cli_blocks_duplicate_keys_and_symlink_screen(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            bad = root / "screen.json"
            bad.write_text('{"schema_version": "a", "schema_version": "b"}')
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(2, main([
                    "--screen", str(bad),
                    "--manifest", str(ROOT / "datasets/manifests/pilot.json"),
                ]))
            self.assertEqual("prospective_case_screen_refused",
                             json.loads(out.getvalue())["status"])
            link = root / "linked.json"
            try:
                link.symlink_to(ROOT / "datasets/case_screenings/scarleteel.json")
            except (OSError, NotImplementedError):
                return
            with redirect_stdout(io.StringIO()):
                self.assertEqual(2, main([
                    "--screen", str(link),
                    "--manifest", str(ROOT / "datasets/manifests/pilot.json"),
                ]))


if __name__ == "__main__":
    unittest.main()
