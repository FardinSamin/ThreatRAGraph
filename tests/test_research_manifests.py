"""Synthetic, offline, deterministic tests of CTI historical manifest validation."""

import copy
import hashlib
import unittest

from scripts.validate_research_manifests import validate


def source(version, date, group):
    return {
        "source_id": "src:" + version,
        "source_version_id": version,
        "source_kind": "cti_report",
        "title": "Synthetic " + version,
        "publisher": "Synthetic fixtures only",
        "url": "https://example.org/" + version,
        "status": "approved",
        "published_at": date,
        "available_at": date,
        "date_confidence": "verified",
        "date_evidence": "Synthetic fixture timestamp",
        "independence_group": group,
        "sha256": hashlib.sha256(version.encode("utf-8")).hexdigest(),
        "redistribution": "restricted",
        "selection_rationale": "Artificial unit-test fixture",
    }


def study():
    sources = {
        "schema_version": "1.0",
        "dataset_id": "fixture",
        "dataset_version": "1.0.0",
        "sources": [
            source("early", "2024-01-01T00:00:00Z", "pub-a"),
            source("background", "2023-12-01T00:00:00Z", "pub-b"),
            source("later", "2024-02-01T00:00:00Z", "pub-c"),
        ],
    }
    cases = {
        "schema_version": "1.0",
        "dataset_id": "fixture",
        "dataset_version": "1.0.0",
        "cases": [{
            "case_id": "case-001",
            "target_entity_id": "malware:synthetic",
            "selection_rationale": "Case chronology verification fixture",
            "cutoff_at": "2024-01-15T00:00:00Z",
            "early_source_version_ids": ["early"],
            "background_source_version_ids": ["background"],
            "later_reference_source_version_ids": ["later"],
        }],
    }
    return sources, cases


class ResearchManifestTests(unittest.TestCase):
    def test_draft_empty_accepted_but_not_research_ready(self):
        a, b = study()
        a["sources"] = []
        b["cases"] = []
        errors, warnings, counts = validate(a, b)
        self.assertFalse(errors)
        self.assertEqual(2, len(warnings))
        self.assertEqual(0, counts["approved_sources"])
        strict_errors, _, _ = validate(a, b, strict=True)
        self.assertTrue(any("25" in x for x in strict_errors))
        self.assertTrue(any("4" in x for x in strict_errors))

    def test_valid_historical_partitions(self):
        errors, warnings, counts = validate(*study())
        self.assertEqual([], errors)
        self.assertEqual([], warnings)
        self.assertEqual(3, counts["approved_sources"])
        self.assertEqual(1, counts["cases"])

    def test_post_cutoff_early_source_is_blocked(self):
        sources, cases = study()
        sources["sources"][0]["available_at"] = "2024-01-20T00:00:00Z"
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("post-cutoff leakage" in x for x in errors))

    def test_future_background_is_blocked(self):
        sources, cases = study()
        sources["sources"][1]["available_at"] = "2024-01-20T00:00:00Z"
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("post-cutoff leakage" in x for x in errors))

    def test_reference_must_be_later_than_cutoff(self):
        sources, cases = study()
        sources["sources"][2]["available_at"] = "2024-01-01T00:00:00Z"
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("not after cutoff" in x for x in errors))

    def test_cross_partition_reuse_is_rejected(self):
        sources, cases = study()
        cases["cases"][0]["background_source_version_ids"] = ["early"]
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("repeated" in x for x in errors))

    def test_cross_partition_report_mirrors_are_flagged(self):
        sources, cases = study()
        sources["sources"][1]["independence_group"] = "pub-a"
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("independence group" in x for x in errors))

    def test_unverified_early_source_cannot_be_used(self):
        sources, cases = study()
        sources["sources"][0]["date_confidence"] = "approximate"
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("unverified" in x for x in errors))

    def test_invalid_hash_and_timestamp_are_rejected(self):
        sources, cases = study()
        sources["sources"][0]["sha256"] = "123"
        cases["cases"][0]["cutoff_at"] = "2024-01-15"
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("SHA-256" in x for x in errors))
        self.assertTrue(any("UTC timestamp" in x for x in errors))

    def test_broken_dataset_version_is_rejected(self):
        sources, cases = study()
        cases["dataset_version"] = "different"
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("must match" in x for x in errors))

    def test_invalid_values_do_not_crash(self):
        sources, cases = study()
        sources["sources"][0]["source_kind"] = ["not-a-kind"]
        sources["sources"][0]["status"] = {"bad": 1}
        sources["sources"][0]["url"] = "https://[bad"
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("unsupported value" in x for x in errors))
        self.assertTrue(any("status" in x for x in errors))
        self.assertTrue(any("https" in x for x in errors))

    def test_duplicate_source_versions_are_rejected(self):
        sources, cases = study()
        sources["sources"].append(copy.deepcopy(sources["sources"][0]))
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("duplicate" in x for x in errors))

    def test_same_content_across_split_is_blocked_even_with_different_groups(self):
        sources, cases = study()
        sources["sources"][2]["sha256"] = sources["sources"][0]["sha256"]
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("identical source content digest" in e for e in errors))

    def test_unknown_id_is_rejected(self):
        sources, cases = study()
        cases["cases"][0]["early_source_version_ids"] = ["nonexistent"]
        errors, _, _ = validate(sources, cases)
        self.assertTrue(any("unknown source version" in x for x in errors))


if __name__ == "__main__":
    unittest.main()
