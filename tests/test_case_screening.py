"""P1a evidence-screen invariants: real publication references, no source approval."""
import copy
from pathlib import Path
import unittest

from scripts.validate_case_screening import load_json, validate_screening

ROOT = Path(__file__).resolve().parents[1]


class CaseScreeningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.screen = load_json(ROOT / "datasets/research/p1a_leaky_vessels_screening.json")
        cls.sources = load_json(ROOT / "datasets/manifests/pilot.json")
        cls.cases = load_json(ROOT / "datasets/cases/pilot.json")

    def valid(self, screen=None, sources=None, cases=None):
        return validate_screening(
            copy.deepcopy(self.screen if screen is None else screen),
            copy.deepcopy(self.sources if sources is None else sources),
            copy.deepcopy(self.cases if cases is None else cases),
        )

    def test_actual_observed_candidate_metadata_valid_but_never_approved(self):
        result = self.valid()
        self.assertEqual("valid_candidate_screen_only", result["status"])
        self.assertFalse(result["research_ready"])
        self.assertEqual(0, result["approved_case_count"])
        self.assertEqual(0, result["approved_source_count"])
        self.assertEqual(6, result["candidate_records_reviewed"])
        self.assertEqual(2, result["role_counts"]["early"])
        self.assertEqual(1, result["role_counts"]["background"])
        self.assertEqual(1, result["role_counts"]["later"])
        self.assertGreater(result["remaining_blockers"], 0)

    def test_proposed_cutoff_not_convertible_to_unapproved_case_manifest(self):
        s = copy.deepcopy(self.screen)
        s["status"] = "approved"
        with self.assertRaisesRegex(ValueError, "cannot certify"):
            self.valid(screen=s)
        s = copy.deepcopy(self.screen)
        s["cutoff_status"] = "verified"
        with self.assertRaisesRegex(ValueError, "unverified"):
            self.valid(screen=s)
        cases = copy.deepcopy(self.cases)
        cases["cases"].append({"case_id": self.screen["case_candidate_id"]})
        with self.assertRaisesRegex(ValueError, "must not be an executable"):
            self.valid(cases=cases)

    def test_no_self_approval_or_fabricated_sha256(self):
        for field, val in [
            ("approved", True),
            ("archived_sha256", "0" * 64),
            ("verified_available_at", "2024-01-31T20:06:08Z"),
            ("rights_review", "allowed"),
        ]:
            s = copy.deepcopy(self.screen)
            s["sources"][0][field] = val
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "cannot be presented"
            ):
                self.valid(screen=s)
        s = copy.deepcopy(self.screen)
        s["approval_state"]["reviewer_signoff"] = "self-certified"
        with self.assertRaisesRegex(ValueError, "researcher approval"):
            self.valid(screen=s)

    def test_unapproved_pilot_registry_cannot_be_silently_promoted(self):
        for field, value in [
            ("status", "approved"),
            ("sha256", "0" * 64),
            ("available_at", "2024-01-31T20:06:08Z"),
            ("date_confidence", "verified"),
        ]:
            sources = copy.deepcopy(self.sources)
            record = next(x for x in sources["sources"]
                          if x["source_version_id"] == self.screen["sources"][0]["source_version_id"])
            record[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "cannot be presented"
            ):
                self.valid(sources=sources)

    def test_pre_disclosure_tag_date_not_equal_public_release(self):
        ref = self.screen["git_provenance_anchor"]
        self.assertEqual("2024-01-23T13:13:42Z", ref["annotated_tag_tagger_at"])
        self.assertEqual("2024-01-31T20:06:08Z",
                         ref["github_release_published_at_observed"])
        self.assertIsNone(next(x for x in self.screen["sources"]
            if x["source_version_id"] == "candidate:runc-maintainer-release:unfrozen"
        )["verified_available_at"])
        s = copy.deepcopy(self.screen)
        s["git_provenance_anchor"]["git_annotated_tag_oid_prefix"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "12 hexadecimal"):
            self.valid(screen=s)

    def test_future_reference_cannot_be_earlier_than_cutoff(self):
        s = copy.deepcopy(self.screen)
        s["proposed_cutoff_at"] = "2024-02-06T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "not after cutoff"):
            self.valid(screen=s)
        s = copy.deepcopy(self.screen)
        r = next(x for x in s["sources"] if x["proposed_role"] == "later")
        r["observed_publication_date"] = "2024-01-31"
        with self.assertRaisesRegex(ValueError, "not after cutoff"):
            self.valid(screen=s)

    def test_background_not_after_cutoff(self):
        s = copy.deepcopy(self.screen)
        x = next(x for x in s["sources"] if x["proposed_role"] == "background")
        x["observed_publication_date"] = "2025-02-11"
        with self.assertRaisesRegex(ValueError, "not demonstrably before cutoff"):
            self.valid(screen=s)

    def test_syndication_group_cannot_cross_early_later_partitions(self):
        s = copy.deepcopy(self.screen)
        later = next(x for x in s["sources"] if x["proposed_role"] == "later")
        early = next(x for x in s["sources"] if x["proposed_role"] == "early")
        later["independence_group"] = early["independence_group"]
        sources = copy.deepcopy(self.sources)
        row = next(x for x in sources["sources"]
                   if x["source_version_id"] == later["source_version_id"])
        row["independence_group"] = early["independence_group"]
        with self.assertRaisesRegex(ValueError, "crosses research partitions"):
            self.valid(screen=s, sources=sources)

    def test_same_publisher_deep_dive_intentionally_excluded(self):
        s = copy.deepcopy(self.screen)
        deep = next(x for x in s["sources"]
                    if x["source_version_id"] == "candidate:runc-snyk-deep:unfrozen")
        self.assertEqual("excluded", deep["proposed_role"])
        deep["proposed_role"] = "later"
        with self.assertRaisesRegex(ValueError, "crosses research partitions"):
            self.valid(screen=s)

    def test_wrong_registry_version_and_source_url_rejected(self):
        s = copy.deepcopy(self.screen)
        s["registry_dataset_version"] = "2.0"
        with self.assertRaisesRegex(ValueError, "manifest version mismatch"):
            self.valid(screen=s)
        s = copy.deepcopy(self.screen)
        s["sources"][0]["url"] = "https://example.org/changed"
        with self.assertRaisesRegex(ValueError, "differs"):
            self.valid(screen=s)

    def test_fabricated_timestamp_calendar_date_refused(self):
        s = copy.deepcopy(self.screen)
        s["sources"][0]["observed_publication_date"] = "2024-02-30"
        with self.assertRaisesRegex(ValueError, "calendar"):
            self.valid(screen=s)
        s = copy.deepcopy(self.screen)
        s["sources"][0]["published_timestamp_observation"] = "2024-01-30T20:00:00Z"
        with self.assertRaisesRegex(ValueError, "conflicts"):
            self.valid(screen=s)

    def test_role_and_source_bounds(self):
        s = copy.deepcopy(self.screen)
        s["sources"][0]["proposed_role"] = "verified_early"
        with self.assertRaisesRegex(ValueError, "Unsupported screening role"):
            self.valid(screen=s)
        s = copy.deepcopy(self.screen)
        s["sources"] = []
        with self.assertRaisesRegex(ValueError, "bounded set"):
            self.valid(screen=s)


if __name__ == "__main__":
    unittest.main()
