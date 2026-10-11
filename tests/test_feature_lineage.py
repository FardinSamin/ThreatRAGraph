"""M5.2 adversarial synthetic as-of feature/alias lineage acceptance checks."""
import copy
import unittest

from src.threatragraph.feature_lineage import validate_asof_lineage
from test_similarity_g1 import fixtures, feature_lineage, profile


class AsOfFeatureLineageTests(unittest.TestCase):
    def setUp(self):
        self.b0, self.b0_graph, self.g1, self.g1_graph = fixtures()
        self.lineage = feature_lineage(self.g1, self.g1_graph)

    def validate(self, rec=None, g1=None, graph=None):
        return validate_asof_lineage(
            self.lineage if rec is None else rec,
            self.g1 if g1 is None else g1,
            self.g1_graph if graph is None else graph,
        )

    def test_all_claims_have_bound_source_lineage(self):
        result = self.validate()
        self.assertEqual(3, result["validated_claim_lineage_count"])
        self.assertFalse(result["research_ready"])
        self.assertFalse(result["alias_mapping_permitted"])
        self.assertFalse(result["external_taxonomy_lookup_permitted"])
        self.assertFalse(result["source_available_at_is_independently_verified"])
        p = profile((self.b0, self.b0_graph, self.g1, self.g1_graph),
                    feature_lineage=copy.deepcopy(self.lineage))
        self.assertEqual(result["lineage_sha256"], p["feature_lineage_sha256"])
        self.assertEqual(1, len(p["predictions"]))
        self.assertFalse(p["research_ready"])

    def test_missing_lineage_cannot_be_used_by_g1(self):
        with self.assertRaises(TypeError):
            from src.threatragraph.similarity_g1 import build_g1_profile
            build_g1_profile(self.b0, self.b0_graph, self.g1, self.g1_graph)

    def test_missing_and_duplicate_claim_lines_are_rejected(self):
        s = copy.deepcopy(self.lineage)
        s["claim_lineage"].pop()
        with self.assertRaisesRegex(ValueError, "One as-of lineage"):
            self.validate(s)
        s = copy.deepcopy(self.lineage)
        s["claim_lineage"][0] = copy.deepcopy(s["claim_lineage"][1])
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.validate(s)

    def test_undocumented_or_future_alias_mapping_is_rejected(self):
        for change in (
            {"identity_policy": "alias_lookup_current"},
            {"alias_map_version": "2026-10"},
            {"external_taxonomy_snapshot": "current"},
        ):
            s = copy.deepcopy(self.lineage)
            s.update(change)
            with self.subTest(change=change), self.assertRaisesRegex(
                ValueError, "policy|exact v1"):
                self.validate(s)

    def test_post_cutoff_feature_derivation_is_rejected(self):
        for date in ("2026-10-10T00:00:00Z", "2024-02-02T00:00:00Z"):
            s = copy.deepcopy(self.lineage)
            s["claim_lineage"][0]["feature_known_at"] = date
            with self.subTest(date=date), self.assertRaisesRegex(
                ValueError, "Feature availability"):
                self.validate(s)

    def test_feature_date_must_equal_eligible_source_availability(self):
        s = copy.deepcopy(self.lineage)
        s["claim_lineage"][0]["feature_known_at"] = "2018-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "Feature availability"):
            self.validate(s)

    def test_external_attck_or_falco_enrichment_refused(self):
        for derivation in (
            "modern_attack_taxonomy_lookup",
            "post_cutoff_falco_rule_revision",
            "semantic_alias_normalization",
            "pretrained_embedding_enrichment",
        ):
            s = copy.deepcopy(self.lineage)
            s["claim_lineage"][0]["derivation"] = derivation
            with self.subTest(derivation=derivation), self.assertRaisesRegex(
                ValueError, "taxonomy|Alias"):
                self.validate(s)

    def test_wrong_source_hash_or_claim_quote_digest_rejected(self):
        for field, replacement in (
            ("source_sha256", "0" * 64),
            ("claim_evidence_sha256", "0" * 64),
            ("source_version_id", "later-heldout"),
        ):
            s = copy.deepcopy(self.lineage)
            s["claim_lineage"][0][field] = replacement
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "exact evidence"):
                self.validate(s)

    def test_swapped_taxonomy_identifier_or_changed_predicate_rejected(self):
        for field, value in (
            ("object_id", "attack-technique:T9999"),
            ("subject_id", "malware:injected"),
            ("predicate", "EXPLOITS"),
        ):
            s = copy.deepcopy(self.lineage)
            s["claim_lineage"][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "exact evidence"):
                self.validate(s)

    def test_changed_graph_edge_requires_new_reviewed_lineage(self):
        g = copy.deepcopy(self.g1_graph)
        g["edges"][0]["evidence_sha256"] = "1" * 64
        with self.assertRaisesRegex(ValueError, "historical graph/view hashes"):
            self.validate(graph=g)

    def test_changed_case_cutoff_or_source_view_requires_new_lineage(self):
        for field, value in (
            ("case_id", "other"),
            ("cutoff_at", "2024-01-31T00:00:00Z"),
        ):
            s = copy.deepcopy(self.lineage)
            s[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(
                ValueError, "case/cutoff"):
                self.validate(s)
        s = copy.deepcopy(self.lineage)
        s["g1_source_view_sha256"] = "9" * 64
        with self.assertRaisesRegex(ValueError, "graph/view hashes"):
            self.validate(s)

    def test_extra_claim_lineage_fields_are_rejected(self):
        s = copy.deepcopy(self.lineage)
        s["claim_lineage"][0]["heldout_answer"] = "candidate winner"
        with self.assertRaisesRegex(ValueError, "foreign fields"):
            self.validate(s)

    def test_duplicate_or_unordered_claim_identifiers_rejected(self):
        s = copy.deepcopy(self.lineage)
        s["claim_lineage"].reverse()
        with self.assertRaisesRegex(ValueError, "canonical claim-id ordering"):
            self.validate(s)

    def test_permuting_graph_edges_does_not_change_profile_hash(self):
        original = profile()
        altered = copy.deepcopy(self.g1_graph)
        altered["edges"].reverse()
        with_reordered = feature_lineage(self.g1, altered)
        result = profile(
            (self.b0, self.b0_graph, self.g1, altered),
            feature_lineage=with_reordered,
        )
        self.assertEqual(original["profile_id"], result["profile_id"])
        self.assertEqual(original["feature_lineage_sha256"],
                         result["feature_lineage_sha256"])

    def test_untrusted_self_declaration_does_not_grant_independent_approval(self):
        s = copy.deepcopy(self.lineage)
        s["limitations"] = "I personally reviewed this, trust me"
        result = self.validate(s)
        self.assertFalse(result["authenticated_source_and_reviewer_attestation"])
        self.assertFalse(result["source_available_at_is_independently_verified"])
        self.assertFalse(result["research_ready"])


if __name__ == "__main__":
    unittest.main()
