"""Synthetic-only B0/G1 output parity and isolation regressions."""
import copy
import unittest

from src.threatragraph.evidence_graph import fingerprint
from src.threatragraph.paired_profile_audit import audit_paired_profiles


def _seal(value):
    value["profile_id"] = "profile:" + fingerprint(value)
    return value


def fixture():
    fact = {
        "subject_id": "malware:new", "predicate": "USES",
        "object_id": "attack-technique:T1059",
        "status": "asserted_in_early_reports",
        "source_version_ids": ["source-early"],
        "supporting_claim_ids": ["claim:" + "a" * 64],
        "evidence_sha256s": ["b" * 64],
        "score": None, "confidence": None,
    }
    b0 = _seal({
        "schema_version": "1.0", "method": "B0",
        "profile_kind": "cold_start_report_only",
        "dataset_id": "synthetic", "dataset_version": "v1",
        "case_id": "test-case", "target_entity_id": "malware:new",
        "cutoff_at": "2024-01-01T00:00:00Z",
        "source_view_sha256": "c" * 64,
        "early_source_version_ids": ["source-early"],
        "facts": [fact], "predictions": [], "research_ready": False,
    })
    proposal = {
        "subject_id": "malware:new", "predicate": "HAS_BEHAVIOR",
        "object_id": "attack-behavior:execution",
        "status": "provisional_graph_analogy_not_sourced_fact",
        "score_kind": "uncalibrated_jaccard_not_probability",
        "ranking_score": 0.5,
        "historical_independence_groups": ["history-a", "history-b"],
        "matching_features": [{"feature": "uses"}],
        "proposed_relation_historical_support": [{"claim_id": "claim-1"}],
    }
    g1 = _seal({
        "schema_version": "1.0", "method": "G1",
        "profile_kind": "graph_assisted_provisional_hypotheses",
        "dataset_id": "synthetic", "dataset_version": "v1",
        "case_id": "test-case", "target_entity_id": "malware:new",
        "cutoff_at": "2024-01-01T00:00:00Z",
        "b0_profile_id": b0["profile_id"],
        "b0_source_view_sha256": b0["source_view_sha256"],
        "g1_source_view_sha256": "d" * 64,
        "feature_lineage_sha256": "e" * 64,
        "early_source_version_ids": ["source-early"],
        "observed_early_facts": [copy.deepcopy(fact)],
        "predictions": [proposal],
        "abstention": {"abstained": False, "reason": None},
        "configuration": {"top_k": 5}, "research_ready": False,
    })
    return b0, g1


def reseal(value):
    value.pop("profile_id", None)
    return _seal(value)


class PairedProfileAuditTests(unittest.TestCase):
    def test_valid_synthetic_pair_is_parity_only_not_study(self):
        a, b = fixture()
        result = audit_paired_profiles(a, b)
        self.assertEqual("paired_profile_output_parity_audit",
                         result["artifact_kind"])
        self.assertEqual(1, result["observed_early_fact_count"])
        self.assertEqual(1, result["g1_provisional_prediction_count"])
        self.assertTrue(result["early_output_parity_verified"])
        self.assertFalse(result["heldout_labels_accessed"])
        self.assertFalse(result["research_ready"])
        self.assertEqual(result, audit_paired_profiles(a, b))

    def test_tampered_profile_content_is_refused(self):
        a, b = fixture()
        b["predictions"][0]["ranking_score"] = 1.0
        with self.assertRaisesRegex(ValueError, "claimed digest"):
            audit_paired_profiles(a, b)

    def test_different_b0_early_sources_refused_even_if_resigned(self):
        a, b = fixture()
        b["early_source_version_ids"] = ["future"]
        reseal(b)
        with self.assertRaisesRegex(ValueError, "source-version IDs"):
            audit_paired_profiles(a, b)

    def test_different_early_facts_refused_even_if_resigned(self):
        a, b = fixture()
        b["observed_early_facts"] = []
        reseal(b)
        with self.assertRaisesRegex(ValueError, "early facts differ"):
            audit_paired_profiles(a, b)

    def test_b0_inference_refused(self):
        a, b = fixture()
        a["predictions"] = [{"future": True}]
        reseal(a)
        b["b0_profile_id"] = a["profile_id"]
        reseal(b)
        with self.assertRaisesRegex(ValueError, "B0 must never"):
            audit_paired_profiles(a, b)

    def test_heldout_context_refused_even_when_hashes_match(self):
        a, b = fixture()
        a["gold_labels"] = ["heldout-answer"]
        reseal(a)
        b["b0_profile_id"] = a["profile_id"]
        reseal(b)
        with self.assertRaisesRegex(ValueError, "Held-out"):
            audit_paired_profiles(a, b)

    def test_already_observed_prediction_refused(self):
        a, b = fixture()
        b["predictions"][0]["predicate"] = "USES"
        b["predictions"][0]["object_id"] = "attack-technique:T1059"
        reseal(b)
        with self.assertRaisesRegex(ValueError, "already-observed"):
            audit_paired_profiles(a, b)

    def test_unsupported_prediction_status_refused(self):
        a, b = fixture()
        b["predictions"][0]["status"] = "confirmed"
        reseal(b)
        with self.assertRaisesRegex(ValueError, "uncalibrated hypotheses"):
            audit_paired_profiles(a, b)

    def test_insufficient_independent_support_refused(self):
        a, b = fixture()
        b["predictions"][0]["historical_independence_groups"] = ["history-a"]
        reseal(b)
        with self.assertRaisesRegex(ValueError, "source paths"):
            audit_paired_profiles(a, b)

    def test_no_proposals_requires_abstention(self):
        a, b = fixture()
        b["predictions"] = []
        reseal(b)
        with self.assertRaisesRegex(ValueError, "abstention"):
            audit_paired_profiles(a, b)
        b["abstention"] = {"abstained": True, "reason": "no candidate"}
        reseal(b)
        result = audit_paired_profiles(a, b)
        self.assertEqual(0, result["g1_provisional_prediction_count"])

    def test_g1_not_bound_to_exact_baseline_refused(self):
        a, b = fixture()
        b["b0_profile_id"] = "profile:" + "f" * 64
        reseal(b)
        with self.assertRaisesRegex(ValueError, "exact B0"):
            audit_paired_profiles(a, b)

    def test_g1_source_view_digest_mismatch_refused(self):
        a, b = fixture()
        b["b0_source_view_sha256"] = "f" * 64
        reseal(b)
        with self.assertRaisesRegex(ValueError, "source-view digest"):
            audit_paired_profiles(a, b)


if __name__ == "__main__":
    unittest.main()
