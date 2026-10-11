"""Synthetic candidate held-out adjudications; no real corpus or gold labels."""
import copy
import json
import tempfile
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import unittest

from scripts.evaluate_frozen_paired_run import _load, main
from src.threatragraph.evidence_graph import fingerprint
from src.threatragraph.heldout_evaluation import (
    aggregate_candidate_evaluations, score_frozen_pair,
    seal_reference_partition, validate_frozen_pair,
)
from src.threatragraph.paired_profile_audit import audit_paired_profiles


def sign(value, key, prefix):
    value[key] = prefix + fingerprint(value)
    return value


def fixture():
    early = {
        "subject_id": "malware:new", "predicate": "USES",
        "object_id": "attack-technique:T1059",
        "status": "asserted_in_early_reports",
        "source_version_ids": ["source-early"],
        "supporting_claim_ids": ["claim:" + "a" * 64],
        "evidence_sha256s": ["b" * 64], "score": None,
        "confidence": None,
    }
    b0 = sign({
        "schema_version": "1.0", "method": "B0",
        "profile_kind": "cold_start_report_only",
        "dataset_id": "synthetic", "dataset_version": "v1",
        "case_id": "case-a", "target_entity_id": "malware:new",
        "cutoff_at": "2024-01-01T00:00:00Z",
        "source_view_sha256": "c" * 64,
        "early_source_version_ids": ["source-early"],
        "facts": [early], "predictions": [],
        "research_ready": False,
    }, "profile_id", "profile:")
    proposal = {
        "subject_id": "malware:new", "predicate": "HAS_BEHAVIOR",
        "object_id": "attack-behavior:execution",
        "status": "provisional_graph_analogy_not_sourced_fact",
        "score_kind": "uncalibrated_jaccard_not_probability",
        "ranking_score": 0.5,
        "historical_independence_groups": ["history-a", "history-b"],
        "matching_features": [{"feature": "USES"}],
        "proposed_relation_historical_support": [{"claim_id": "claim-3"}],
    }
    g1 = sign({
        "schema_version": "1.0", "method": "G1",
        "profile_kind": "graph_assisted_provisional_hypotheses",
        "dataset_id": b0["dataset_id"], "dataset_version": b0["dataset_version"],
        "case_id": b0["case_id"], "target_entity_id": b0["target_entity_id"],
        "cutoff_at": b0["cutoff_at"], "b0_profile_id": b0["profile_id"],
        "b0_source_view_sha256": b0["source_view_sha256"],
        "g1_source_view_sha256": "d" * 64,
        "feature_lineage_sha256": "e" * 64,
        "early_source_version_ids": ["source-early"],
        "observed_early_facts": [copy.deepcopy(early)],
        "predictions": [proposal],
        "configuration": {"top_k": 5},
        "abstention": {"abstained": False, "reason": None},
        "research_ready": False,
    }, "profile_id", "profile:")
    audit = audit_paired_profiles(b0, g1)
    lock = sign({
        "schema_version": "1.0",
        "artifact_kind": "paired_run_engineering_lock",
        "lock_version": "paired-run-engineering-lock-v1",
        "case_id": b0["case_id"], "target_entity_id": b0["target_entity_id"],
        "cutoff_at": b0["cutoff_at"], "dataset_id": b0["dataset_id"],
        "dataset_version": b0["dataset_version"],
        "b0_profile_id": b0["profile_id"], "g1_profile_id": g1["profile_id"],
        "paired_audit_id": audit["audit_id"],
        "early_source_version_ids": ["source-early"],
        "observed_fact_count": 1, "provisional_prediction_count": 1,
        "g1_algorithm_config": {"top_k": 5},
        "input_artifact_sha256": {k: "f" * 64 for k in
                                   ("b0_view", "b0_graph", "g1_view",
                                    "g1_graph", "feature_lineage")},
        "gold_labels_read": False,
        "predictions_sealed_before_gold_access": True,
        "independent_study_approval": "not_verified",
        "empirical_evaluation": "not_performed",
        "research_ready": False,
    }, "run_id", "run:")

    def label(predicate, obj, verdict):
        return {
            "subject_id": "malware:new",
            "predicate": predicate, "object_id": obj,
            "decision": verdict, "source_version_ids": ["later-2024"],
            "reviewer_ids": ["reviewer-a", "reviewer-b"],
            "rationale": "Synthetic example, not independently authenticated",
        }

    ref = seal_reference_partition({
        "schema_version": "1.0",
        "artifact_kind": "heldout_reference_adjudications",
        "case_id": b0["case_id"], "target_entity_id": b0["target_entity_id"],
        "cutoff_at": b0["cutoff_at"],
        "reference_window_end_at": "2024-06-01T00:00:00Z",
        "review_protocol_version": "synthetic-v1",
        "review_status": "candidate_unapproved",
        "sources": [{
            "source_version_id": "later-2024",
            "available_at": "2024-03-01T00:00:00Z",
            "sha256": "1" * 64, "independence_group": "later-source",
        }],
        "adjudications": [
            label("HAS_BEHAVIOR", "attack-behavior:execution", "contradicted"),
            label("USES", "attack-technique:T1059", "supported"),
            label("USES", "attack-technique:T1105", "supported"),
        ],
    })
    return b0, g1, audit, lock, ref


def repack(ref):
    item = copy.deepcopy(ref)
    item.pop("partition_id")
    return seal_reference_partition(item)


class HeldoutCandidateScoringTests(unittest.TestCase):
    def test_explicit_supported_contradicted_and_coverage(self):
        out = score_frozen_pair(*fixture())
        self.assertEqual(1, out["methods"]["B0_observed"]["supported_count"])
        self.assertEqual(1, out["methods"]["G1_novel_proposals"]["contradicted_count"])
        self.assertEqual(2, out["methods"]["G1_combined_profile"]["assessable_denominator"])
        self.assertEqual(0.5, out["methods"]["G1_combined_profile"]["assessable_precision"])
        self.assertEqual({"matched": 1, "denominator": 2, "fraction": 0.5},
                         out["supported_reference_coverage"]["B0"])
        self.assertFalse(out["research_ready"])

    def test_unmentioned_prediction_is_never_automatically_false(self):
        a, b, c, d, ref = fixture()
        ref["adjudications"] = [
            x for x in ref["adjudications"] if x["predicate"] == "USES"
        ]
        out = score_frozen_pair(a, b, c, d, repack(ref))
        row = out["methods"]["G1_novel_proposals"]
        self.assertEqual(0, row["contradicted_count"])
        self.assertEqual(1, row["not_assessable_count"])
        self.assertIsNone(row["assessable_precision"])
        self.assertEqual("unlabeled_not_assessable_no_negative_imputation",
                         row["rows"][0]["decision_origin"])

    def test_explicit_not_assessable_does_not_reduce_precision(self):
        a, b, c, d, ref = fixture()
        ref["adjudications"][0]["decision"] = "not_assessable"
        row = score_frozen_pair(a, b, c, d, repack(ref))["methods"]["G1_novel_proposals"]
        self.assertEqual(1, row["not_assessable_count"])
        self.assertEqual(0, row["assessable_denominator"])
        self.assertEqual("explicit_heldout_adjudication", row["rows"][0]["decision_origin"])

    def test_duplicate_and_out_of_scope_excluded(self):
        for decision in ("duplicate", "out_of_scope"):
            a, b, c, d, ref = fixture()
            ref["adjudications"][0]["decision"] = decision
            row = score_frozen_pair(a, b, c, d, repack(ref))["methods"]["G1_novel_proposals"]
            self.assertEqual(1, row[decision + "_count"])
            self.assertEqual(0, row["assessable_denominator"])

    def test_reference_partition_hash_detects_changed_decision(self):
        a, b, c, d, ref = fixture()
        ref["adjudications"][0]["decision"] = "supported"
        with self.assertRaisesRegex(ValueError, "digest"):
            score_frozen_pair(a, b, c, d, ref)

    def test_reference_source_must_be_post_cutoff_within_window(self):
        for timestamp in ("2023-12-30T00:00:00Z", "2024-07-01T00:00:00Z"):
            *_, ref = fixture()
            ref["sources"][0]["available_at"] = timestamp
            with self.assertRaisesRegex(ValueError, "later than cutoff"):
                repack(ref)

    def test_different_reference_case_rejected(self):
        a, b, c, d, ref = fixture()
        ref["case_id"] = "another-case"
        with self.assertRaisesRegex(ValueError, "different case"):
            score_frozen_pair(a, b, c, d, repack(ref))

    def test_duplicate_reference_triple_refused(self):
        *_, ref = fixture()
        ref["adjudications"].append(copy.deepcopy(ref["adjudications"][-1]))
        with self.assertRaisesRegex(ValueError, "Duplicate relation"):
            repack(ref)

    def test_unsorted_adjudications_refused(self):
        *_, ref = fixture()
        ref["adjudications"].reverse()
        with self.assertRaisesRegex(ValueError, "canonical triple ordering"):
            repack(ref)

    def test_assessable_decision_requires_later_source(self):
        *_, ref = fixture()
        ref["adjudications"][0]["source_version_ids"] = []
        with self.assertRaisesRegex(ValueError, "explicit later reference"):
            repack(ref)

    def test_two_distinct_declared_reviewers_required(self):
        *_, ref = fixture()
        ref["adjudications"][0]["reviewer_ids"] = ["reviewer-a", "reviewer-a"]
        with self.assertRaisesRegex(ValueError, "distinct declared reviewers"):
            repack(ref)

    def test_unrecognized_decision_refused(self):
        *_, ref = fixture()
        ref["adjudications"][0]["decision"] = "true_without_review"
        with self.assertRaisesRegex(ValueError, "Unsupported held-out"):
            repack(ref)

    def test_run_lock_fingerprint_tampering_refused(self):
        a, b, c, d, ref = fixture()
        d["b0_profile_id"] = "profile:" + "1" * 64
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            score_frozen_pair(a, b, c, d, ref)

    def test_early_profile_cannot_contain_gold(self):
        a, b, c, d, ref = fixture()
        b["heldout_labels"] = ref
        b.pop("profile_id")
        sign(b, "profile_id", "profile:")
        with self.assertRaisesRegex(ValueError, "Held-out"):
            score_frozen_pair(a, b, c, d, ref)

    def test_profile_changed_after_freeze_rejected(self):
        a, b, c, d, ref = fixture()
        b["predictions"][0]["ranking_score"] = 0.99
        with self.assertRaisesRegex(ValueError, "claimed digest"):
            score_frozen_pair(a, b, c, d, ref)

    def test_audit_mismatch_refused(self):
        a, b, c, d, _ = fixture()
        c["case_id"] = "other"
        with self.assertRaisesRegex(ValueError, "paired audit"):
            validate_frozen_pair(a, b, c, d)

    def test_aggregate_reports_micro_precision_without_significance(self):
        case = score_frozen_pair(*fixture())
        out = aggregate_candidate_evaluations([case])
        self.assertEqual(1, out["case_count"])
        self.assertEqual(0.5, out["methods"]["G1_combined_profile"]["micro_assessable_precision"])
        self.assertFalse(out["inferential_significance_claimed"])

    def test_aggregate_duplicate_case_refused(self):
        case = score_frozen_pair(*fixture())
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            aggregate_candidate_evaluations([case, copy.deepcopy(case)])

    def test_aggregate_tampered_case_refused(self):
        case = score_frozen_pair(*fixture())
        case["methods"]["G1_novel_proposals"]["contradicted_count"] = 99
        with self.assertRaisesRegex(ValueError, "Tampered"):
            aggregate_candidate_evaluations([case])

    def test_repeat_scoring_is_deterministic(self):
        self.assertEqual(score_frozen_pair(*fixture()), score_frozen_pair(*fixture()))

    def test_duplicate_input_json_fields_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            file = Path(tmp) / "reference.json"
            file.write_text('{"case_id":"a","case_id":"b"}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
                _load(str(file))

    def test_cli_rejects_bad_profiles_before_parsing_gold(self):
        with tempfile.TemporaryDirectory() as tmp:
            a, b, audit, lock, _ = fixture()
            a["profile_id"] = "profile:" + "0" * 64
            root = Path(tmp)
            for name, content in (
                ("b0.json", a), ("g1.json", b), ("audit.json", audit),
                ("lock.json", lock),
            ):
                (root / name).write_text(json.dumps(content), encoding="utf-8")
            (root / "reference.json").write_text("invalid JSON", encoding="utf-8")
            args = [
                "--b0-profile", str(root / "b0.json"),
                "--g1-profile", str(root / "g1.json"),
                "--paired-audit", str(root / "audit.json"),
                "--run-lock", str(root / "lock.json"),
                "--reference-partition", str(root / "reference.json"),
            ]
            out = StringIO()
            with redirect_stdout(out):
                rc = main(args)
            self.assertEqual(2, rc)
            self.assertIn("heldout_evaluation_refused", out.getvalue())


if __name__ == "__main__":
    unittest.main()
