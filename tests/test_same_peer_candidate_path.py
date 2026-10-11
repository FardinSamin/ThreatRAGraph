"""Fail-closed two-group source-path screening tests (synthetic mutations only)."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.screen_same_peer_candidate_path import VERSION, assess_chain, main

ROOT = Path(__file__).resolve().parents[1]


class KissadogOriginalResearchChainTests(unittest.TestCase):
    def setUp(self):
        self.screen = json.loads(
            (ROOT / "datasets/case_screenings/scarleteel_kissadog_chain_v1.json")
            .read_text(encoding="utf-8")
        )
        self.manifest = json.loads(
            (ROOT / "datasets/manifests/pilot.json").read_text(encoding="utf-8")
        )

    def test_real_named_campaign_two_original_researcher_group_prospect_not_approved(self):
        result = assess_chain(self.screen, self.manifest)
        self.assertEqual(VERSION, result["schema_version"])
        self.assertEqual("campaign:SCARLETEEL", result["target_entity_id"])
        self.assertEqual("campaign:Kiss-a-dog", result["historical_peer_id"])
        self.assertEqual(2, result["prospective_per_peer_matching_plus_relation_groups"])
        self.assertEqual({"predicate": "USES", "object_id": "tool:xmrig"},
                         result["prospective_shared_feature"])
        self.assertEqual({"predicate": "USES", "object_id": "tool:xhide"},
                         result["prospective_additional_peer_relation"])
        self.assertTrue(result["exact_same_peer_path_shape_plausible"])
        for key in (
            "source_independence_verified", "actual_primary_2022_source_bytes_approved",
            "candidate_claims_byte_aligned_and_reviewed",
            "historical_source_availability_verified", "later_labels_blinded_and_reconciled",
            "case_approved", "g1_evaluation_eligible", "research_ready",
        ):
            with self.subTest(key=key):
                self.assertFalse(result[key])
        self.assertEqual(0, result["scored_g1_predictions"])
        self.assertTrue(result["independent_blinded_later_labeling_required"])
        self.assertEqual(30, len(self.manifest["sources"]))
        self.assertFalse(any(x["status"] == "approved" for x in self.manifest["sources"]))

    def test_refuse_wrong_peer_or_campaign_actor_alias_swap(self):
        for key, value in (
            ("historical_peer_id", "threat-actor:TeamTNT"),
            ("historical_peer_id", "campaign:Chimaera"),
            ("target_entity_id", "vulnerability:CVE-2024-21626"),
            ("target_entity_id", "campaign:Kiss-a-dog"),
        ):
            modified = copy.deepcopy(self.screen)
            modified[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                assess_chain(modified, self.manifest)

    def test_cross_type_relation_and_future_feature_poisoning(self):
        for change in (
            {"subject_id": "threat-actor:TeamTNT"},
            {"predicate": "TARGETS"},
            {"object_id": "tool:generic-miner"},
            {"object_id": "attack-technique:T1496"},
        ):
            modified = copy.deepcopy(self.screen)
            modified["historical_matching_feature_support"][1].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                assess_chain(modified, self.manifest)

    def test_proposal_must_be_actual_different_xhide_relation(self):
        for change in (
            {"object_id": "tool:xmrig"},
            {"object_id": "tool:diamorphine"},
            {"predicate": "HAS_BEHAVIOR"},
            {"subject_id": "campaign:Chimaera"},
            {"source_version_id": "candidate:kissadog-crowdstrike-20221026:unfrozen"},
        ):
            modified = copy.deepcopy(self.screen)
            modified["historical_proposed_relation_support"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                assess_chain(modified, self.manifest)

    def test_two_source_groups_cannot_be_manufactured_using_same_source_twice(self):
        modified = copy.deepcopy(self.screen)
        modified["historical_matching_feature_support"][1]["source_version_id"] = (
            modified["historical_matching_feature_support"][0]["source_version_id"]
        )
        with self.assertRaisesRegex(ValueError, "Duplicate matching"):
            assess_chain(modified, self.manifest)

    def test_two_different_campaigns_do_not_aggregate_as_one_historical_peer(self):
        modified = copy.deepcopy(self.screen)
        modified["historical_matching_feature_support"][1]["subject_id"] = "campaign:Chimaera"
        with self.assertRaisesRegex(ValueError, "subject"):
            assess_chain(modified, self.manifest)

    def test_two_declared_groups_must_be_independent_and_disjoint_early(self):
        for swap in ("crowdstrike", "early"):
            modified = copy.deepcopy(self.manifest)
            records = {r["source_version_id"]: r for r in modified["sources"]}
            cado = records["candidate:kissadog-cado-202212:unfrozen"]
            original = records[
                "candidate:kissadog-crowdstrike-20221026:unfrozen"
                if swap == "crowdstrike"
                else "candidate:scarleteel-sysdig-20230228:unfrozen"
            ]
            cado["independence_group"] = original["independence_group"]
            with self.subTest(swap=swap), self.assertRaisesRegex(ValueError, "overlap"):
                assess_chain(self.screen, modified)

    def test_manifest_cannot_claim_date_byte_rights_or_source_approval(self):
        for field, value in (
            ("status", "approved"),
            ("available_at", "2022-12-23T11:42:26Z"),
            ("published_at", "2022-12-23T00:00:00Z"),
            ("sha256", "a" * 64),
            ("date_confidence", "verified"),
            ("redistribution", "allowed"),
        ):
            modified = copy.deepcopy(self.manifest)
            cado = next(x for x in modified["sources"] if
                        x["source_version_id"] == "candidate:kissadog-cado-202212:unfrozen")
            cado[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "unapproved"):
                assess_chain(self.screen, modified)

    def test_forged_review_or_clandestine_later_answer_fields_refused(self):
        for field in ("evidence_byte_aligned", "semantic_reviewed"):
            modified = copy.deepcopy(self.screen)
            modified["historical_proposed_relation_support"][0][field] = True
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "reviewed"):
                assess_chain(modified, self.manifest)
        for field in ("gold_answer", "later_feature_truth", "prediction_score"):
            modified = copy.deepcopy(self.screen)
            modified[field] = "forged"
            with self.subTest(field=field), self.assertRaises(ValueError):
                assess_chain(modified, self.manifest)

    def test_independence_and_readiness_promotion_flags_stay_false(self):
        for field in (
            "source_original_bytes_approved", "date_and_rights_reviewed",
            "same_peer_chain_semantically_reviewed", "novel_target_relation_verified",
            "case_approved", "research_ready",
        ):
            modified = copy.deepcopy(self.screen)
            modified[field] = True
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "self-approve"):
                assess_chain(modified, self.manifest)

    def test_cannot_hide_later_summary_exposure_or_change_cutoff(self):
        modified = copy.deepcopy(self.screen)
        modified["later_reference_preview_exposure"] = "none_reported"
        with self.assertRaisesRegex(ValueError, "exposure"):
            assess_chain(modified, self.manifest)
        for cutoff in ("2023-02-28T00:00:00Z", "2023-07-11T00:00:00Z"):
            modified = copy.deepcopy(self.screen)
            modified["proposed_cutoff_at"] = cutoff
            with self.subTest(cutoff=cutoff), self.assertRaises(ValueError):
                assess_chain(modified, self.manifest)

    def test_exact_candidate_roles_no_later_reference_swap(self):
        modified = copy.deepcopy(self.screen)
        modified["historical_proposed_relation_support"][0]["source_version_id"] = (
            "candidate:scarleteel-sysdig-20230711:unfrozen"
        )
        with self.assertRaises(ValueError):
            assess_chain(modified, self.manifest)

    def test_cli_real_metadata_never_claims_g1_outcome(self):
        with redirect_stdout(io.StringIO()) as output:
            status = main([])
        self.assertEqual(0, status)
        r = json.loads(output.getvalue())
        self.assertEqual(2, r["prospective_per_peer_matching_plus_relation_groups"])
        self.assertFalse(r["g1_evaluation_eligible"])

    def test_cli_duplicate_json_keys_and_symlink_fail(self):
        with TemporaryDirectory() as td:
            path = Path(td) / "screen.json"
            path.write_text('{"schema_version":"a","schema_version":"b"}', encoding="utf-8")
            with redirect_stdout(io.StringIO()) as output:
                self.assertEqual(2, main(["--screen", str(path)]))
            self.assertEqual("same_peer_candidate_chain_refused",
                             json.loads(output.getvalue())["status"])
            target = Path(td) / "target.json"
            target.write_text(json.dumps(self.screen), encoding="utf-8")
            link = Path(td) / "link.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                return
            with redirect_stdout(io.StringIO()):
                self.assertEqual(2, main(["--screen", str(link)]))


if __name__ == "__main__":
    unittest.main()
