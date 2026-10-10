"""Standard-library tests for typed, provenance-aware historical graph views.

Synthetic sources and arbitrary hashes here are fixtures, not real historical CTI.
"""
import copy
import hashlib
from pathlib import Path
import sqlite3
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from threatragraph.evidence_graph import (
    EvidenceGraph, validate_triple, validate_locator,
)
from scripts.freeze_case_snapshots import case_views


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def source(version, at, group):
    return {
        "source_id": "src:" + version,
        "source_version_id": version,
        "source_kind": "cti_report",
        "title": "Synthetic " + version,
        "publisher": "Fake test publisher",
        "url": "https://example.org/" + version,
        "status": "approved",
        "published_at": at,
        "available_at": at,
        "date_confidence": "verified",
        "date_evidence": "Synthetic-only timestamp",
        "independence_group": group,
        "sha256": digest(version),
        "redistribution": "restricted",
        "selection_rationale": "Synthetic test data",
    }


def manifests():
    sources = {
        "schema_version": "1.0", "dataset_id": "synthetic",
        "dataset_version": "1", "sources": [
            source("early", "2024-01-01T00:00:00Z", "group-one"),
            source("historical", "2023-05-01T00:00:00Z", "group-two"),
            source("heldout", "2024-02-01T00:00:00Z", "group-three"),
            {**source("unapproved", "2023-01-01T00:00:00Z", "group-four"),
             "status": "candidate", "date_confidence": "unknown",
             "sha256": None, "available_at": None},
        ],
    }
    cases = {
        "schema_version": "1.0", "dataset_id": "synthetic",
        "dataset_version": "1", "cases": [{
            "case_id": "demo-case",
            "target_entity_id": "malware:unknown",
            "selection_rationale": "Unit test only",
            "cutoff_at": "2024-01-15T00:00:00Z",
            "early_source_version_ids": ["early"],
            "background_source_version_ids": ["historical"],
            "later_reference_source_version_ids": ["heldout"],
        }],
    }
    return sources, cases


def claim(version, subject="malware:unknown", predicate="USES",
          target="attack-technique:T1059", **overrides):
    obj = {
        "source_version_id": version,
        "subject_id": subject,
        "predicate": predicate,
        "object_id": target,
        "assertion_kind": "report_assertion",
        "polarity": "positive",
        "evidence_locator": {"kind": "text_span", "segment_id": "seg:" + version,
                             "start": 5, "end": 17},
        "evidence_sha256": digest("test quote " + version),
        "extractor_version": "fixtures/1.0",
    }
    obj.update(overrides)
    return obj


class EvidenceGraphTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.graph = EvidenceGraph(self.conn)
        self.sources, self.cases = manifests()
        self.graph.register_source_versions(self.sources)
        self.views = case_views(self.sources, self.cases, "demo-case")

    def tearDown(self):
        self.conn.close()

    def test_early_and_background_source_split(self):
        first = self.graph.append_source_claim(claim("early"))
        second = self.graph.append_source_claim(
            claim("historical", subject="malware:historical")
        )
        hidden = self.graph.append_source_claim(
            claim("heldout", subject="malware:unknown", predicate="EXPLOITS",
                  target="vulnerability:CVE-2024-9999")
        )
        b0 = self.graph.project(self.views["B0"])
        g1 = self.graph.project(self.views["G1"])
        self.assertEqual({first}, {e["claim_id"] for e in b0["edges"]})
        self.assertEqual({first, second}, {e["claim_id"] for e in g1["edges"]})
        self.assertNotIn(hidden, {e["claim_id"] for e in g1["edges"]})
        self.assertNotIn("heldout", str(g1))
        self.assertNotIn("CVE-2024-9999", str(g1))

    def test_multiedges_preserve_both_independent_evidence_paths(self):
        a = self.graph.append_source_claim(claim("early"))
        b = self.graph.append_source_claim(claim("historical"))
        g1 = self.graph.project(self.views["G1"])
        self.assertEqual(2, len(g1["edges"]))
        self.assertNotEqual(a, b)
        self.assertEqual({"early", "historical"},
                         {e["source_version_id"] for e in g1["edges"]})
        self.assertEqual(2, len(self.graph.neighborhood(g1, "malware:unknown")))

    def test_same_claim_is_idempotent(self):
        a = self.graph.append_source_claim(claim("early"))
        b = self.graph.append_source_claim(claim("early"))
        self.assertEqual(a, b)
        self.assertEqual(1, len(self.graph.project(self.views["B0"])["edges"]))

    def test_distinct_evidence_locator_yields_distinct_claim_id(self):
        a = self.graph.append_source_claim(claim("early"))
        extra = {"kind": "text_span", "segment_id": "seg:early",
                 "start": 18, "end": 24}
        b = self.graph.append_source_claim(
            claim("early", evidence_locator=extra)
        )
        self.assertNotEqual(a, b)
        self.assertEqual(2, len(self.graph.project(self.views["B0"])["edges"]))

    def test_claim_fails_for_unapproved_or_unregistered_source(self):
        with self.assertRaises(ValueError):
            self.graph.append_source_claim(claim("unapproved"))
        with self.assertRaises(ValueError):
            self.graph.append_source_claim(claim("source-not-known"))

    def test_claim_kind_predicted_is_forbidden(self):
        with self.assertRaises(ValueError):
            self.graph.append_source_claim(
                claim("early", assertion_kind="predicted")
            )

    def test_wrong_subject_object_type_is_rejected(self):
        with self.assertRaises(ValueError):
            self.graph.append_source_claim(
                claim("early", subject="vulnerability:CVE-2024-1",
                      predicate="USES", target="attack-technique:T1059")
            )
        with self.assertRaises(ValueError):
            validate_triple("malware:a", "INVENTED_PREDICATE", "tool:b")

    def test_falco_syscall_rule_semantics_is_not_incident_observation(self):
        self.graph.append_source_claim(
            claim("historical", subject="falco-rule:exec-shell",
                  predicate="INVOLVES_SYSCALL", target="system-call:execve",
                  assertion_kind="rule_semantics",
                  evidence_locator={"kind": "yaml_path", "path": "/rules/0/condition"})
        )
        g1 = self.graph.project(self.views["G1"])
        self.assertEqual("rule_semantics", g1["edges"][0]["assertion_kind"])

    def test_invalid_locator_rejected(self):
        for locator in (
            {"kind": "text_span", "segment_id": "a", "start": -2, "end": 10},
            {"kind": "text_span", "segment_id": "a", "start": True, "end": 10},
            {"kind": "text_span", "segment_id": "a", "start": 8, "end": 8},
            {"kind": "yaml_path", "path": "relative/path"},
            {"kind": "python_script", "path": "/evil"},
            {"kind": ["not-hashable"], "path": "/evil"},
        ):
            with self.subTest(locator=locator):
                with self.assertRaises(ValueError):
                    validate_locator(locator)

    def test_source_version_metadata_immutable(self):
        self.assertEqual(0, self.graph.register_source_versions(self.sources))
        tampered = copy.deepcopy(self.sources)
        tampered["sources"][0]["sha256"] = digest("tampered source")
        with self.assertRaises(ValueError):
            self.graph.register_source_versions(tampered)

    def test_postcutoff_source_rejected_even_if_role_forged(self):
        view = copy.deepcopy(self.views["G1"])
        view["sources"].append({
            "role": "background",
            "source_version_id": "heldout",
            "sha256": digest("heldout"),
            "available_at": "2024-02-01T00:00:00Z",
            "independence_group": "group-three",
        })
        with self.assertRaises(ValueError):
            self.graph.project(view)

    def test_mismatched_hash_and_date_rejected(self):
        original = self.views["B0"]
        for key, value in [
            ("sha256", "0" * 64),
            ("available_at", "2024-01-02T00:00:00Z"),
        ]:
            view = copy.deepcopy(original)
            view["sources"][0][key] = value
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    self.graph.project(view)

    def test_invalid_view_or_later_role_rejected(self):
        for altered in (
            {"artifact_kind": "non-historical"},
            {"method": "G1_early_plus_historical_background",
             "sources": [dict(self.views["B0"]["sources"][0], role="later")]},
        ):
            view = copy.deepcopy(self.views["B0"])
            view.update(altered)
            with self.assertRaises(ValueError):
                self.graph.project(view)

    def test_negative_polarity_is_preserved_not_silently_truth(self):
        self.graph.append_source_claim(claim("early", polarity="negative"))
        edges = self.graph.project(self.views["B0"])["edges"]
        self.assertEqual("negative", edges[0]["polarity"])
        self.assertIn("not independently verified", self.graph.project(self.views["B0"])["caveat"])

    def test_projection_is_deterministic_and_single_source(self):
        self.graph.append_source_claim(claim("historical"))
        self.graph.append_source_claim(claim("early"))
        a = self.graph.project(self.views["G1"])
        b = self.graph.project(self.views["G1"])
        self.assertEqual(a, b)
        self.assertEqual(["early", "historical"],
                         sorted(e["source_version_id"] for e in a["edges"]))


if __name__ == "__main__":
    unittest.main()
