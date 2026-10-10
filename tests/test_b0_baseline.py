"""B0 cold-start baseline isolation and abstention tests, synthetic only."""

import copy
import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import sqlite3
import tempfile
import unittest

from scripts.profile_b0 import main
from scripts.project_case_graph import run as project_case_graph
from scripts.freeze_case_snapshots import case_views
from src.threatragraph.baseline_b0 import build_b0_profile
from src.threatragraph.evidence_alignment import EvidenceVerifier
from src.threatragraph.evidence_graph import EvidenceGraph, fingerprint
from src.threatragraph.semantic_reviews import REVIEW_SCHEMA_VERSION


def h(text):
    return hashlib.sha256(
        text.encode("utf-8") if isinstance(text, str) else text
    ).hexdigest()


def view(early=("src-early",)):
    return {
        "schema_version": "1.0",
        "artifact_kind": "historical_source_input",
        "dataset_id": "fixture",
        "dataset_version": "v1",
        "case_id": "case-a",
        "target_entity_id": "malware:sample",
        "cutoff_at": "2024-01-15T00:00:00Z",
        "scope_warning": "Synthetic unit-test input, not real chronology",
        "method": "B0_sparse_report_only",
        "sources": [
            {
                "role": "early", "source_version_id": version,
                "sha256": h(version),
                "available_at": "2024-01-01T00:00:00Z",
                "independence_group": "group:" + version,
            }
            for version in early
        ],
    }


def edge(n=1, source="src-early", subject="malware:sample",
         predicate="USES", obj="attack-technique:T1059",
         polarity="positive", evidence_status="aligned",
         review="supported_by_excerpt"):
    return {
        "claim_id": "claim:" + h("claim" + str(n)),
        "source_version_id": source,
        "subject_id": subject,
        "predicate": predicate,
        "object_id": obj,
        "assertion_kind": "report_assertion",
        "polarity": polarity,
        "evidence_locator": {
            "kind": "text_span", "segment_id": "seg:" + source,
            "start": 0, "end": 5,
        },
        "evidence_sha256": h("evidence" + str(n)),
        "extractor_version": "fixture/1.0",
        "evidence_status": evidence_status,
        "semantic_review_status": review,
    }


def graph_for(v, edges):
    return {
        "schema_version": "1.0",
        "artifact_kind": "historical_sourced_graph",
        "case_id": v["case_id"],
        "method": v["method"],
        "cutoff_at": v["cutoff_at"],
        "source_view_sha256": fingerprint(v),
        "nodes": sorted({
            x for e in edges for x in (e["subject_id"], e["object_id"])
        }),
        "edges": edges,
        "caveat": "Source asserted, not independent truth",
    }


class BaselineTests(unittest.TestCase):
    def test_approved_target_assertion_produces_observed_fact_no_prediction(self):
        v = view()
        result = build_b0_profile(v, graph_for(v, [edge()]))
        self.assertEqual("B0", result["method"])
        self.assertFalse(result["research_ready"])
        self.assertTrue(result["readiness"]["structural_checks_passed"])
        self.assertEqual("strict_structural", result["readiness"]["validation_mode"])
        self.assertEqual("not_verified", result["readiness"]["independent_study_approval"])
        self.assertEqual(1, len(result["facts"]))
        self.assertEqual("asserted_in_early_reports", result["facts"][0]["status"])
        self.assertEqual(["src-early"], result["facts"][0]["source_version_ids"])
        self.assertEqual([edge()["claim_id"]],
                         result["facts"][0]["supporting_claim_ids"])
        self.assertIsNone(result["facts"][0]["confidence"])
        self.assertIsNone(result["facts"][0]["score"])
        self.assertEqual([], result["predictions"])
        self.assertFalse(result["abstention"]["abstained"])

    def test_multi_report_same_fact_keeps_independent_provenance(self):
        v = view(("src-early", "src-second"))
        facts = build_b0_profile(v, graph_for(v, [
            edge(1), edge(2, source="src-second")
        ]))["facts"]
        self.assertEqual(1, len(facts))
        self.assertEqual(["src-early", "src-second"], facts[0]["source_version_ids"])
        self.assertEqual(2, len(facts[0]["supporting_claim_ids"]))
        self.assertIsNone(facts[0]["score"])

    def test_byte_stable_profiles_ignore_input_edge_order(self):
        v = view(("src-early", "src-second"))
        a = edge(1)
        b = edge(2, source="src-second", predicate="HAS_BEHAVIOR",
                 obj="attack-behavior:process-start")
        first = build_b0_profile(v, graph_for(v, [a, b]))
        second = build_b0_profile(v, graph_for(v, [b, a]))
        self.assertEqual(first, second)
        self.assertEqual(first["profile_id"], second["profile_id"])

    def test_conflicting_target_assertions_abstain(self):
        v = view()
        positive = edge(1)
        negative = edge(2, polarity="negative")
        result = build_b0_profile(v, graph_for(v, [positive, negative]))
        self.assertEqual([], result["facts"])
        self.assertTrue(result["abstention"]["abstained"])
        self.assertEqual("conflicting_source_assertions",
                         result["abstention"]["reason"])
        self.assertEqual(1, result["diagnostics"]["conflicting_target_triples"])

    def test_negative_only_is_not_inverted_into_a_predicted_positive(self):
        v = view()
        result = build_b0_profile(v, graph_for(v, [edge(1, polarity="negative")]))
        self.assertEqual([], result["facts"])
        self.assertEqual([], result["predictions"])
        self.assertTrue(result["abstention"]["abstained"])

    def test_uncertain_polarity_never_becomes_observed(self):
        v = view()
        result = build_b0_profile(v, graph_for(v, [edge(1, polarity="uncertain")]))
        self.assertEqual([], result["facts"])
        self.assertEqual(1, result["diagnostics"]["ignored_uncertain_claims"])

    def test_missing_target_and_alias_guess_are_not_inferred(self):
        v = view()
        result = build_b0_profile(v, graph_for(v, [
            edge(1, subject="malware:similar_name"),
            edge(2, subject="malware:sample-v2"),
        ]))
        self.assertEqual([], result["facts"])
        self.assertEqual(2, result["diagnostics"]["ignored_non_target_claims"])
        self.assertTrue(result["abstention"]["abstained"])

    def test_graph_neighbors_not_traversed_to_infer_second_hop(self):
        v = view()
        e1 = edge(1, obj="malware:other")
        e2 = edge(2, subject="malware:other", obj="attack-technique:T1047")
        result = build_b0_profile(v, graph_for(v, [e1, e2]))
        self.assertEqual(1, len(result["facts"]))
        self.assertEqual("malware:other", result["facts"][0]["object_id"])
        self.assertNotIn("T1047", json.dumps(result))

    def test_g1_graph_method_is_explicitly_refused(self):
        v = view()
        graph = graph_for(v, [edge()])
        graph["method"] = "G1_early_plus_historical_background"
        with self.assertRaisesRegex(ValueError, "B0 graph"):
            build_b0_profile(v, graph)

    def test_g1_source_view_explicitly_refused(self):
        v = view()
        v["method"] = "G1_early_plus_historical_background"
        with self.assertRaisesRegex(ValueError, "B0 source view"):
            build_b0_profile(v, graph_for(v, [edge()]))

    def test_background_and_later_source_roles_rejected(self):
        for forbidden_role in ("background", "later"):
            with self.subTest(role=forbidden_role):
                v = view()
                v["sources"][0]["role"] = forbidden_role
                with self.assertRaisesRegex(ValueError, "background or held-out"):
                    build_b0_profile(v, graph_for(v, [edge()]))

    def test_postcutoff_source_refused(self):
        v = view()
        v["sources"][0]["available_at"] = "2024-02-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "post-cutoff"):
            build_b0_profile(v, graph_for(v, [edge()]))

    def test_future_source_claim_injection_refused(self):
        v = view()
        bad = edge(2, source="heldout-later-report")
        with self.assertRaisesRegex(ValueError, "non-early"):
            build_b0_profile(v, graph_for(v, [edge(1), bad]))

    def test_reference_labels_and_later_sources_cannot_enter_schema(self):
        v = view()
        v["later_reference_source_version_ids"] = ["heldout-future"]
        with self.assertRaises(ValueError):
            build_b0_profile(v, graph_for(v, [edge()]))
        v = view()
        graph = graph_for(v, [edge()])
        graph["outcome_labels"] = {"secret": "post-cutoff"}
        with self.assertRaises(ValueError):
            build_b0_profile(v, graph)

    def test_tampered_input_graph_digest_refused(self):
        v = view()
        g = graph_for(v, [edge()])
        g["source_view_sha256"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "exact B0 source-view"):
            build_b0_profile(v, g)

    def test_duplicate_claim_id_rejected(self):
        v = view()
        with self.assertRaisesRegex(ValueError, "duplicate B0"):
            build_b0_profile(v, graph_for(v, [edge(), edge()]))

    def test_unverified_evidence_is_refused_even_in_development(self):
        v = view()
        with self.assertRaisesRegex(ValueError, "unaligned"):
            build_b0_profile(v, graph_for(v, [
                edge(evidence_status="unverified")
            ]), development_only=True)

    def test_unreviewed_strict_refused_but_dev_abstains_and_discloses(self):
        v = view()
        g = graph_for(v, [edge(review="unreviewed")])
        with self.assertRaisesRegex(ValueError, "semantic review"):
            build_b0_profile(v, g)
        dev = build_b0_profile(v, g, development_only=True)
        self.assertFalse(dev["research_ready"])
        self.assertTrue(dev["abstention"]["abstained"])
        self.assertEqual([], dev["facts"])
        self.assertEqual(1, dev["diagnostics"]["ignored_unreviewed_claims"])

    def test_unsupported_and_uncertain_reviews_strict_refused(self):
        v = view()
        for state in ("unsupported_by_excerpt", "uncertain"):
            with self.subTest(state=state):
                with self.assertRaisesRegex(ValueError, "semantic review"):
                    build_b0_profile(v, graph_for(v, [edge(review=state)]))

    def test_fake_prediction_edge_cannot_be_sourced_baseline(self):
        v = view()
        e = edge()
        e["assertion_kind"] = "predicted"
        with self.assertRaises(ValueError):
            build_b0_profile(v, graph_for(v, [e]))

    def test_empty_edges_is_an_explicit_abstention(self):
        v = view()
        result = build_b0_profile(v, graph_for(v, []))
        self.assertEqual([], result["facts"])
        self.assertTrue(result["abstention"]["abstained"])
        self.assertEqual([], result["predictions"])

    def test_node_injection_and_metadata_mismatch_are_rejected(self):
        v = view()
        g = graph_for(v, [edge()])
        g["nodes"].append("threat-actor:heldout")
        with self.assertRaisesRegex(ValueError, "nodes"):
            build_b0_profile(v, g)
        g = graph_for(v, [edge()])
        g["case_id"] = "different"
        with self.assertRaisesRegex(ValueError, "case_id"):
            build_b0_profile(v, g)

    def test_cli_reads_only_explicit_b0_inputs(self):
        v = view()
        g = graph_for(v, [edge()])
        with tempfile.TemporaryDirectory() as td:
            vp = Path(td) / "b0_view.json"
            gp = Path(td) / "b0_graph.json"
            vp.write_text(json.dumps(v), encoding="utf-8")
            gp.write_text(json.dumps(g), encoding="utf-8")
            result = io.StringIO()
            with redirect_stdout(result):
                rc = main(["--b0-view", str(vp), "--b0-graph", str(gp)])
            self.assertEqual(0, rc)
            parsed = json.loads(result.getvalue())
            self.assertEqual("B0", parsed["method"])
            self.assertNotIn("G1", result.getvalue())
            self.assertNotIn("later_reference", result.getvalue())


def fixture_source(version, at, group):
    return {
        "source_id": "src:" + version, "source_version_id": version,
        "source_kind": "cti_report", "title": "Synthetic " + version,
        "publisher": "Unit tests", "url": "https://example.org/" + version,
        "status": "approved", "published_at": at, "available_at": at,
        "date_confidence": "verified", "date_evidence": "Synthetic only",
        "independence_group": group, "sha256": h(version),
        "redistribution": "restricted", "selection_rationale": "Fixture not real CTI",
    }


class EndToEndBaselineTest(unittest.TestCase):
    def test_baseline_uses_only_b0_projection_from_reviewed_case_run(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root)
            raw_sources = [
                fixture_source("early", "2024-01-01T00:00:00Z", "a"),
                fixture_source("background", "2023-01-01T00:00:00Z", "b"),
                fixture_source("heldout", "2024-02-01T00:00:00Z", "c"),
            ]
            sources = {
                "schema_version": "1.0", "dataset_id": "fixture",
                "dataset_version": "v1", "sources": raw_sources,
            }
            cases = {
                "schema_version": "1.0", "dataset_id": "fixture",
                "dataset_version": "v1", "cases": [{
                    "case_id": "case-a",
                    "target_entity_id": "malware:early",
                    "selection_rationale": "Synthetic historical case",
                    "cutoff_at": "2024-01-15T00:00:00Z",
                    "early_source_version_ids": ["early"],
                    "background_source_version_ids": ["background"],
                    "later_reference_source_version_ids": ["heldout"],
                }],
            }
            archives = path / "archives"
            for source in raw_sources:
                raw = source["source_version_id"].encode("utf-8")
                digest = h(raw)
                directory = archives / digest[:2]
                directory.mkdir(parents=True, exist_ok=True)
                (directory / digest).write_bytes(raw)
            claim = {
                "source_version_id": "early",
                "subject_id": "malware:early", "predicate": "USES",
                "object_id": "attack-technique:T1059",
                "assertion_kind": "report_assertion",
                "polarity": "positive",
                "evidence_locator": {
                    "kind": "text_span", "segment_id": "seg:early",
                    "start": 0, "end": 5,
                },
                "evidence_sha256": h("early"),
                "extractor_version": "fixture/1",
            }
            with sqlite3.connect(":memory:") as con:
                ledger = EvidenceGraph(
                    con, evidence_verifier=EvidenceVerifier(sources, archives)
                )
                ledger.register_source_versions(sources)
                claim_id = ledger.append_source_claim(claim)
            review = {
                "schema_version": REVIEW_SCHEMA_VERSION,
                "claim_id": claim_id, "source_version_id": "early",
                "evidence_sha256": h("early"),
                "decision": "supported_by_excerpt", "reviewer_id": "tester-01",
                "reviewed_at": "2026-10-10T12:00:00Z",
                "rationale": "This is only a test's declared reviewer decision.",
            }
            claim_path, review_path = path / "claims.jsonl", path / "reviews.jsonl"
            claim_path.write_text(json.dumps(claim) + "\n", encoding="utf-8")
            review_path.write_text(json.dumps(review) + "\n", encoding="utf-8")
            graph_result = project_case_graph(
                sources, cases, "case-a", claim_path, archives,
                development=True, reviews_path=review_path,
            )
            b0_view = case_views(sources, cases, "case-a")["B0"]
            profile = build_b0_profile(
                b0_view, graph_result["B0"], development_only=True
            )
            self.assertEqual(1, len(profile["facts"]))
            self.assertEqual("malware:early", profile["facts"][0]["subject_id"])
            self.assertEqual(["early"], profile["facts"][0]["source_version_ids"])
            self.assertFalse(profile["research_ready"])
            self.assertNotIn("background", json.dumps(profile))
            self.assertNotIn("heldout", json.dumps(profile))
            self.assertEqual([], profile["predictions"])


if __name__ == "__main__":
    unittest.main()
