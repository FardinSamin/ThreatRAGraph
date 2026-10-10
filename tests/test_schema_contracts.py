"""Synthetic v1 artifact contracts and fail-closed SQLite migration boundaries."""
import copy
import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest

from src.threatragraph.contracts import (
    validate_graph_projection, validate_source_view,
)
from src.threatragraph.evidence_graph import EvidenceGraph, fingerprint
from src.threatragraph.semantic_reviews import SemanticReviewLedger
from src.threatragraph.sqlite_schema import check_schema, LEDGER_VERSION


def sha(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def fixture():
    view = {
        "schema_version": "1.0", "artifact_kind": "historical_source_input",
        "dataset_id": "synthetic", "dataset_version": "v1",
        "case_id": "case-fixture", "target_entity_id": "malware:test",
        "cutoff_at": "2024-01-15T00:00:00Z",
        "scope_warning": "Synthetic source-level case view; not approved research",
        "method": "B0_sparse_report_only",
        "sources": [{
            "role": "early", "source_version_id": "early",
            "sha256": sha("source"), "available_at": "2024-01-01T00:00:00Z",
            "independence_group": "fixture-group",
        }],
    }
    graph = {
        "schema_version": "1.0", "artifact_kind": "historical_sourced_graph",
        "case_id": view["case_id"], "method": view["method"],
        "cutoff_at": view["cutoff_at"], "source_view_sha256": fingerprint(view),
        "nodes": ["attack-technique:T1059", "malware:test"],
        "edges": [{
            "claim_id": "claim:" + sha("synthetic claim 1"),
            "source_version_id": "early", "subject_id": "malware:test",
            "predicate": "USES", "object_id": "attack-technique:T1059",
            "assertion_kind": "report_assertion", "polarity": "positive",
            "evidence_locator": {
                "kind": "text_span", "segment_id": "seg:early",
                "start": 0, "end": 3,
            },
            "evidence_sha256": sha("abc"),
            "extractor_version": "test/1", "evidence_status": "aligned",
            "semantic_review_status": "supported_by_excerpt",
        }],
        "caveat": "Synthetic, not independent historical or factual proof",
    }
    return view, graph


class ArtifactContractTests(unittest.TestCase):
    def setUp(self):
        self.view, self.graph = fixture()

    def test_valid_v1_source_and_reviewed_graph(self):
        self.assertEqual({"early"}, validate_source_view(self.view))
        validate_graph_projection(self.graph, self.view, reviewed=True)

    def test_pinned_version_and_foreign_labels_fail_closed(self):
        for bad in (
            {"schema_version": "2.0"},
            {"later_reference_source_version_ids": ["future"]},
            {"outcome_labels": {"reference": "never feed B0"}},
            {"sources": [{**self.view["sources"][0], "role": "heldout"}]},
            {"sources": [{**self.view["sources"][0], "available_at": "2024-02-01T00:00:00Z"}]},
            {"sources": [{**self.view["sources"][0], "role": []}]},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                validate_source_view(dict(self.view, **bad))

    def test_graph_rejects_unknown_fields_and_future_ids(self):
        view, graph = fixture()
        for altered in (
            {"schema_version": "2.0"},
            {"outcome_labels": {"later": "unsafe"}},
            {"source_view_sha256": sha("tampered")},
            {"nodes": ["malware:test", "attack-technique:T1059"]},
            {"edges": [dict(graph["edges"][0], source_version_id="heldout")]},
            {"edges": [dict(graph["edges"][0], future_label="future")]},
        ):
            with self.subTest(altered=altered), self.assertRaises(ValueError):
                validate_graph_projection(dict(graph, **altered), view, reviewed=True)

    def test_rejects_invalid_claim_and_locator_and_review_decision(self):
        for changes in (
            {"claim_id": "claim:fake"},
            {"assertion_kind": "predicted"},
            {"polarity": ["positive"]},
            {"evidence_status": {"status": "aligned"}},
            {"semantic_review_status": ["supported_by_excerpt"]},
            {"evidence_locator": {"kind": "text_span", "segment_id": "seg:early", "start": True, "end": 5}},
            {"evidence_sha256": "not-a-sha"},
        ):
            graph = copy.deepcopy(self.graph)
            graph["edges"][0].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_graph_projection(graph, self.view, reviewed=True)

    def test_rejects_review_metadata_on_unreviewed_core_projection(self):
        with self.assertRaises(ValueError):
            validate_graph_projection(self.graph, self.view, reviewed=False)
        core = copy.deepcopy(self.graph)
        del core["edges"][0]["semantic_review_status"]
        validate_graph_projection(core, self.view, reviewed=False)

    def test_empty_core_projection_has_no_fabricated_nodes(self):
        core = copy.deepcopy(self.graph)
        core["edges"] = []
        core["nodes"] = []
        validate_graph_projection(core, self.view, reviewed=True)
        core["nodes"] = ["malware:future"]
        with self.assertRaises(ValueError):
            validate_graph_projection(core, self.view, reviewed=True)


class SqliteSchemaMigrationSafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.dbfile = Path(self.temp.name) / "case-ledger.sqlite"

    def tearDown(self):
        self.temp.cleanup()

    def test_new_and_reopened_sqlite_v1_is_idempotent(self):
        with sqlite3.connect(self.dbfile) as conn:
            EvidenceGraph(conn)
            SemanticReviewLedger(conn)
            self.assertEqual(LEDGER_VERSION, conn.execute("PRAGMA user_version").fetchone()[0])
        with sqlite3.connect(self.dbfile) as conn:
            EvidenceGraph(conn)
            SemanticReviewLedger(conn)
            check_schema(conn, ("source_versions", "sourced_claims", "semantic_reviews"))

    def test_legacy_missing_evidence_status_is_rejected_without_rewrite(self):
        with sqlite3.connect(self.dbfile) as conn:
            EvidenceGraph(conn)
            conn.execute("DROP TABLE sourced_claims")
            conn.execute("""CREATE TABLE sourced_claims (
                claim_id TEXT PRIMARY KEY, source_version_id TEXT NOT NULL,
                subject_id TEXT NOT NULL, predicate TEXT NOT NULL,
                object_id TEXT NOT NULL, assertion_kind TEXT NOT NULL,
                polarity TEXT NOT NULL, evidence_locator TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL, extractor_version TEXT NOT NULL
            )""")
            original = [row[1] for row in conn.execute("PRAGMA table_info(sourced_claims)")]
            with self.assertRaisesRegex(ValueError, "Incompatible sourced_claims"):
                EvidenceGraph(conn)
            after = [row[1] for row in conn.execute("PRAGMA table_info(sourced_claims)")]
            self.assertEqual(original, after)
            self.assertNotIn("evidence_status", after)

    def test_future_sqlite_schema_version_is_rejected(self):
        with sqlite3.connect(self.dbfile) as conn:
            EvidenceGraph(conn)
            conn.execute("PRAGMA user_version = 99")
            with self.assertRaisesRegex(ValueError, "Unsupported SQLite schema version"):
                EvidenceGraph(conn)

    def test_partially_constructed_core_is_refused(self):
        with sqlite3.connect(self.dbfile) as conn:
            conn.execute("CREATE TABLE source_versions (source_version_id TEXT PRIMARY KEY)")
            original = set(row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ))
            with self.assertRaises(ValueError):
                EvidenceGraph(conn)
            after = set(row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ))
            self.assertEqual(original, after)

    def test_incompatible_existing_review_table_is_not_silently_migrated(self):
        with sqlite3.connect(self.dbfile) as conn:
            EvidenceGraph(conn)
            conn.execute("CREATE TABLE semantic_reviews (review_id TEXT PRIMARY KEY)")
            with self.assertRaisesRegex(ValueError, "Incompatible semantic_reviews"):
                SemanticReviewLedger(conn)
            self.assertEqual(1, len(list(conn.execute("PRAGMA table_info(semantic_reviews)"))))


if __name__ == "__main__":
    unittest.main()
