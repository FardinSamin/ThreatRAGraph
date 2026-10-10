"""Synthetic M5 graph-analogy and historical isolation regression tests."""
import copy
import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

from scripts.profile_g1 import main
from src.threatragraph.evidence_graph import fingerprint
from src.threatragraph.similarity_g1 import build_g1_profile


def h(value):
    return hashlib.sha256(value.encode()).hexdigest()


def src(name, role, group, available="2024-01-01T00:00:00Z"):
    return {
        "role": role, "source_version_id": name, "sha256": h(name),
        "available_at": available, "independence_group": group,
    }


def edge(i, source, subject, predicate, obj, *, polarity="positive",
         review="supported_by_excerpt", kind="report_assertion", status="aligned"):
    return {
        "claim_id": "claim:" + h(f"claim-{i}"),
        "source_version_id": source,
        "subject_id": subject, "predicate": predicate, "object_id": obj,
        "assertion_kind": kind, "polarity": polarity,
        "evidence_locator": {"kind": "text_span", "segment_id": f"seg:{source}",
                             "start": 0, "end": 8},
        "evidence_sha256": h(f"quote-{i}"),
        "extractor_version": "fixture/1",
        "evidence_status": status,
        "semantic_review_status": review,
    }


def view(method, sources):
    return {
        "schema_version": "1.0", "artifact_kind": "historical_source_input",
        "dataset_id": "synthetic", "dataset_version": "v1",
        "case_id": "test-case", "target_entity_id": "malware:new",
        "cutoff_at": "2024-02-01T00:00:00Z",
        "scope_warning": "Synthetic-only test, not approved real historical sources",
        "method": method, "sources": sources,
    }


def graph(v, edges):
    return {
        "schema_version": "1.0", "artifact_kind": "historical_sourced_graph",
        "case_id": v["case_id"], "method": v["method"],
        "cutoff_at": v["cutoff_at"], "source_view_sha256": fingerprint(v),
        "nodes": sorted({n for e in edges for n in (e["subject_id"], e["object_id"])}),
        "edges": edges,
        "caveat": "synthetic claims with reviewer stubs, not externally verified",
    }


def fixtures():
    early = src("early", "early", "reporters")
    background1 = src("back-one", "background", "independent-history-A",
                      "2019-03-01T00:00:00Z")
    background2 = src("back-two", "background", "independent-history-B",
                      "2022-04-01T00:00:00Z")
    b0 = view("B0_sparse_report_only", [early])
    g1 = view("G1_early_plus_historical_background", [copy.deepcopy(early), background1, background2])
    target = edge(1, "early", "malware:new", "USES", "attack-technique:T1059")
    overlap = edge(2, "back-one", "malware:older", "USES", "attack-technique:T1059")
    candidate = edge(3, "back-two", "malware:older", "HAS_BEHAVIOR",
                     "attack-behavior:exec-sequence")
    return b0, graph(b0, [target]), g1, graph(g1, [copy.deepcopy(target), overlap, candidate])


def profile(params=None, **kw):
    args = tuple(copy.deepcopy(x) for x in (fixtures() if params is None else params))
    return build_g1_profile(*args, **kw)


class G1SimilarityTests(unittest.TestCase):
    def test_valid_g1_emits_separate_provisional_prediction(self):
        result = profile()
        self.assertEqual("G1", result["method"])
        self.assertFalse(result["research_ready"])
        self.assertEqual(1, len(result["observed_early_facts"]))
        self.assertEqual(1, len(result["predictions"]))
        p = result["predictions"][0]
        self.assertEqual("malware:new", p["subject_id"])
        self.assertEqual("HAS_BEHAVIOR", p["predicate"])
        self.assertEqual("attack-behavior:exec-sequence", p["object_id"])
        self.assertEqual("provisional_graph_analogy_not_sourced_fact", p["status"])
        self.assertEqual(0.5, p["ranking_score"])
        self.assertEqual("uncalibrated_jaccard_not_probability", p["score_kind"])
        self.assertEqual(["independent-history-A", "independent-history-B"],
                         p["historical_independence_groups"])
        shared = p["matching_features"][0]
        self.assertEqual("early", shared["early_support"][0]["source_version_id"])
        self.assertEqual("back-one", shared["historical_support"][0]["source_version_id"])
        self.assertEqual("back-two", p["proposed_relation_historical_support"][0]["source_version_id"])
        self.assertFalse(result["abstention"]["abstained"])

    def test_order_independence_of_evidence_claims(self):
        b0, bg0, g1, gg = fixtures()
        a = profile((b0, bg0, g1, gg))
        gg["edges"] = list(reversed(gg["edges"]))
        b = profile((b0, bg0, g1, gg))
        self.assertEqual(a, b)
        self.assertEqual(a["profile_id"], b["profile_id"])

    def test_b0_g1_early_source_mismatch_rejected(self):
        b0, bg0, g1, gg = fixtures()
        g1["sources"][0]["sha256"] = h("tampered")
        gg = graph(g1, gg["edges"])
        with self.assertRaisesRegex(ValueError, "source metadata differs"):
            profile((b0, bg0, g1, gg))

    def test_b0_g1_early_claim_mismatch_rejected(self):
        b0, bg0, g1, gg = fixtures()
        gg["edges"][0]["evidence_sha256"] = h("tampered quotation")
        with self.assertRaisesRegex(ValueError, "early reviewed claims differ"):
            profile((b0, bg0, g1, graph(g1, gg["edges"])))

    def test_future_source_cannot_pass_as_background(self):
        b0, bg0, g1, gg = fixtures()
        g1["sources"][1]["available_at"] = "2024-03-01T00:00:00Z"
        gg = graph(g1, gg["edges"])
        with self.assertRaisesRegex(ValueError, "post-cutoff"):
            profile((b0, bg0, g1, gg))

    def test_target_specific_background_leak_rejected(self):
        b0, bg0, g1, gg = fixtures()
        gg["edges"].append(edge(4, "back-one", "malware:new",
                                "USES", "attack-technique:T1059"))
        with self.assertRaisesRegex(ValueError, "Target-specific"):
            profile((b0, bg0, g1, graph(g1, gg["edges"])))

    def test_background_mirrored_early_group_refused(self):
        b0, bg0, g1, gg = fixtures()
        g1["sources"][1]["independence_group"] = "reporters"
        with self.assertRaisesRegex(ValueError, "Correlated"):
            profile((b0, bg0, g1, graph(g1, gg["edges"])))

    def test_single_independent_group_abstains(self):
        b0, bg0, g1, gg = fixtures()
        g1["sources"][2]["independence_group"] = "independent-history-A"
        res = profile((b0, bg0, g1, graph(g1, gg["edges"])))
        self.assertEqual([], res["predictions"])
        self.assertTrue(res["abstention"]["abstained"])
        self.assertGreater(res["diagnostics"]["weak_independence_rejections"], 0)

    def test_rule_semantics_cannot_infer_executed_behavior(self):
        b0, bg0, g1, gg = fixtures()
        gg["edges"][-1]["assertion_kind"] = "rule_semantics"
        res = profile((b0, bg0, g1, graph(g1, gg["edges"])))
        self.assertEqual([], res["predictions"])
        self.assertTrue(res["abstention"]["abstained"])

    def test_unreviewed_background_fails_strict_development_abstains(self):
        b0, bg0, g1, gg = fixtures()
        gg["edges"][-1]["semantic_review_status"] = "unreviewed"
        g = graph(g1, gg["edges"])
        with self.assertRaisesRegex(ValueError, "reviewed historical claims"):
            profile((b0, bg0, g1, g))
        res = profile((b0, bg0, g1, g), development_only=True)
        self.assertEqual([], res["predictions"])
        self.assertFalse(res["research_ready"])

    def test_unaligned_background_fails_in_all_modes(self):
        b0, bg0, g1, gg = fixtures()
        gg["edges"][-1]["evidence_status"] = "unverified"
        for dev in (False, True):
            with self.subTest(dev=dev), self.assertRaisesRegex(ValueError, "unaligned"):
                profile((b0, bg0, g1, graph(g1, gg["edges"])), development_only=dev)

    def test_negative_or_uncertain_early_relation_blocks_prediction(self):
        for polarity in ("negative", "uncertain", "positive"):
            b0, bg0, g1, gg = fixtures()
            extra = edge(4, "early", "malware:new", "HAS_BEHAVIOR",
                         "attack-behavior:exec-sequence", polarity=polarity)
            bg0 = graph(b0, bg0["edges"] + [extra])
            gg = graph(g1, gg["edges"] + [extra])
            res = profile((b0, bg0, g1, gg))
            self.assertEqual([], res["predictions"], polarity)

    def test_future_g1_label_and_source_claim_are_rejected(self):
        b0, bg0, g1, gg = fixtures()
        gg["outcome_labels"] = {"future": True}
        with self.assertRaisesRegex(ValueError, "contract fields"):
            profile((b0, bg0, g1, gg))
        gg.pop("outcome_labels")
        gg["edges"].append(edge(5, "heldout", "malware:older",
                                "USES", "attack-technique:T1059"))
        with self.assertRaisesRegex(ValueError, "future source"):
            profile((b0, bg0, g1, graph(g1, gg["edges"])))

    def test_popularity_cap_discards_non_discriminating_features(self):
        b0, bg0, g1, gg = fixtures()
        gg["edges"].append(edge(4, "back-two", "malware:another",
                                "USES", "attack-technique:T1059"))
        g = graph(g1, gg["edges"])
        res = profile((b0, bg0, g1, g), max_peers_per_feature=1)
        self.assertEqual([], res["predictions"])
        self.assertEqual(1, res["diagnostics"]["popular_target_features_discarded"])

    def test_unknown_alias_and_different_entity_type_do_not_match(self):
        b0, bg0, g1, gg = fixtures()
        gg["edges"][1]["subject_id"] = "malware:older-alias"
        gg["edges"][2]["subject_id"] = "malware:older"
        res = profile((b0, bg0, g1, graph(g1, gg["edges"])))
        self.assertEqual([], res["predictions"])

    def test_absent_early_target_feature_causes_abstention(self):
        b0, bg0, g1, gg = fixtures()
        bg0["edges"][0]["subject_id"] = "malware:not-the-target"
        gg["edges"][0]["subject_id"] = "malware:not-the-target"
        res = profile((b0, graph(b0, bg0["edges"]), g1, graph(g1, gg["edges"])))
        self.assertEqual([], res["predictions"])
        self.assertEqual("no_reviewed_early_target_features", res["abstention"]["reason"])

    def test_invalid_controls_and_boolean_top_k_rejected(self):
        for kwargs in (
            {"top_k": True}, {"top_k": 0}, {"top_k": 100},
            {"min_overlap": 0}, {"min_background_groups": 1},
            {"max_peers_per_feature": 0}, {"development_only": "yes"}
        ):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(ValueError, "configuration"):
                profile(**kwargs)

    def test_offline_cli_success_and_refusal(self):
        b0, bg0, g1, gg = fixtures()
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            for name, value in zip(("b0v", "b0g", "g1v", "g1g"), (b0, bg0, g1, gg)):
                (base / (name + ".json")).write_text(json.dumps(value), encoding="utf-8")
            argv = [
                "--b0-view", str(base / "b0v.json"),
                "--b0-graph", str(base / "b0g.json"),
                "--g1-view", str(base / "g1v.json"),
                "--g1-graph", str(base / "g1g.json")
            ]
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(0, main(argv))
            self.assertEqual(1, len(json.loads(out.getvalue())["predictions"]))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(2, main(argv + ["--top-k", "0"]))


if __name__ == "__main__":
    unittest.main()
