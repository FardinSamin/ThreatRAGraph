"""G1-v2 prospective campaign peer screening remains candidate-only and fail-closed."""
import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.screen_candidate_method import SCREEN_VERSION_V2, assess_screen, main

ROOT = Path(__file__).resolve().parents[1]


class ExactCampaignPeerProspectTests(unittest.TestCase):
    def setUp(self):
        self.screen = json.loads(
            (ROOT / "datasets/case_screenings/scarleteel_peers_v2.json").read_text(
                encoding="utf-8"
            )
        )
        self.registry = json.loads(
            (ROOT / "datasets/manifests/pilot.json").read_text(encoding="utf-8")
        )

    def test_both_independently_authored_named_campaign_leads_are_unapproved(self):
        result = assess_screen(self.screen, self.registry)
        self.assertEqual(SCREEN_VERSION_V2, result["schema_version"])
        self.assertEqual("campaign:SCARLETEEL", result["target_entity_id"])
        self.assertEqual(2, result["unverified_explicit_same_type_peer_candidates"])
        self.assertEqual(2, result["declared_background_publisher_groups"])
        self.assertFalse(result["same_type_peer_verified"])
        self.assertFalse(result["two_group_same_type_peer_claim_support_verified"])
        self.assertFalse(result["case_approved"])
        self.assertFalse(result["g1_evaluation_eligible"])
        self.assertFalse(result["research_ready"])
        self.assertTrue(result["independent_blinded_later_labeling_required"])
        self.assertEqual(
            {"campaign:Chimaera", "campaign:Kiss-a-dog"},
            {p["subject_id"] for p in self.screen["background_peer_candidates"]}
        )
        self.assertEqual({("USES", "tool:xmrig")}, {
            (p["predicate"], p["object_id"])
            for p in self.screen["background_peer_candidates"]
        })
        self.assertEqual(29, len(self.registry["sources"]))
        self.assertFalse(any(s["status"] == "approved" for s in self.registry["sources"]))

    def test_forged_peer_review_or_byte_alignment_refused(self):
        for key in ("evidence_byte_aligned", "semantic_reviewed"):
            case = copy.deepcopy(self.screen)
            case["background_peer_candidates"][0][key] = True
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "aligned or reviewed"):
                assess_screen(case, self.registry)

    def test_renamed_actor_as_campaign_or_vulnerability_refused(self):
        for subject in (
            "threat-actor:TeamTNT",
            "vulnerability:CVE-2024-21626",
            "malware:TeamTNT",
            "campaign:SCARLETEEL",
            "campaign:Kiss-a-dog",
        ):
            case = copy.deepcopy(self.screen)
            case["background_peer_candidates"][0]["subject_id"] = subject
            with self.subTest(subject=subject), self.assertRaises(ValueError):
                assess_screen(case, self.registry)

    def test_peer_exact_tool_feature_is_required_not_generic_cryptomining(self):
        for key, value in (
            ("predicate", "TARGETS"), ("predicate", "HAS_BEHAVIOR"),
            ("object_id", "tool:generic-miner"),
            ("object_id", "attack-technique:T1496"),
        ):
            case = copy.deepcopy(self.screen)
            case["background_peer_candidates"][1][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                assess_screen(case, self.registry)

    def test_peer_cannot_use_early_or_later_reference_source(self):
        for sid in (
            self.screen["early_source_version_ids"][0],
            self.screen["later_reference_source_version_ids"][0],
            self.screen["date_corroboration_source_version_ids"][0],
        ):
            case = copy.deepcopy(self.screen)
            case["background_peer_candidates"][1]["source_version_id"] = sid
            with self.subTest(source=sid), self.assertRaises(ValueError):
                assess_screen(case, self.registry)

    def test_single_research_group_cannot_fake_two_independent_publishers(self):
        case = copy.deepcopy(self.screen)
        case["background_peer_candidates"][1]["source_version_id"] = (
            case["background_peer_candidates"][0]["source_version_id"]
        )
        with self.assertRaisesRegex(ValueError, "groups must be distinct"):
            assess_screen(case, self.registry)

    def test_peer_cannot_add_unknown_fields_or_later_gold_label(self):
        for field in ("gold_label", "novel_later_prediction", "publication_verified"):
            case = copy.deepcopy(self.screen)
            case["background_peer_candidates"][0][field] = "invented"
            with self.subTest(field=field), self.assertRaises(ValueError):
                assess_screen(case, self.registry)

    def test_publisher_identity_does_not_auto_approve_source_date(self):
        sid = self.screen["background_source_version_ids"][0]
        for field, value in (
            ("status", "approved"),
            ("sha256", "0" * 64),
            ("available_at", "2021-09-08T00:00:00Z"),
            ("date_confidence", "verified"),
        ):
            registry = copy.deepcopy(self.registry)
            for source in registry["sources"]:
                if source["source_version_id"] == sid:
                    source[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                assess_screen(self.screen, registry)

    def test_source_groups_collision_and_target_scope_fail(self):
        registry = copy.deepcopy(self.registry)
        sid = self.screen["background_source_version_ids"][0]
        early = self.screen["early_source_version_ids"][0]
        early_group = next(s["independence_group"] for s in registry["sources"]
                           if s["source_version_id"] == early)
        for record in registry["sources"]:
            if record["source_version_id"] == sid:
                record["independence_group"] = early_group
        with self.assertRaises(ValueError):
            assess_screen(self.screen, registry)

    def test_peer_evidence_missing_or_too_many_fails(self):
        for peers in ([], self.screen["background_peer_candidates"][:1],
                      self.screen["background_peer_candidates"] * 7):
            case = copy.deepcopy(self.screen)
            case["background_peer_candidates"] = peers
            with self.subTest(count=len(peers)), self.assertRaises(ValueError):
                assess_screen(case, self.registry)

    def test_peer_no_invented_readiness_even_with_two_named_campaigns(self):
        for field in ("research_ready", "case_approved",
                      "same_type_background_peers_verified",
                      "two_group_peer_relation_support_verified"):
            case = copy.deepcopy(self.screen)
            case[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                assess_screen(case, self.registry)

    def test_preview_contamination_remains_disclosed(self):
        out = assess_screen(self.screen, self.registry)
        self.assertEqual("search_result_summary_exposed",
                         out["external_later_summary_exposure"])
        self.assertTrue(out["independent_blinded_later_labeling_required"])
        self.assertEqual(0, out["experimental_predictions"])

    def test_cli_default_v2_reports_unverified(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(0, main([]))
        response = json.loads(out.getvalue())
        self.assertEqual(SCREEN_VERSION_V2, response["schema_version"])
        self.assertEqual(2, response["unverified_explicit_same_type_peer_candidates"])
        self.assertFalse(response["research_ready"])

    def test_cli_rejects_duplicate_peer_fields(self):
        with TemporaryDirectory() as tmp:
            p = Path(tmp) / "screen.json"
            original = json.dumps(self.screen)
            p.write_text(original.replace('"subject_id":', '"subject_id": "campaign:forged", "subject_id":', 1))
            with redirect_stdout(io.StringIO()) as buff:
                self.assertEqual(2, main(["--screen", str(p)]))
            self.assertEqual("prospective_case_screen_refused",
                             json.loads(buff.getvalue())["status"])


if __name__ == "__main__":
    unittest.main()
