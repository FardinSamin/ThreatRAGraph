"""Synthetic-only metadata exchange round-trip and refusal cases."""
import copy
import hashlib
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from scripts.exchange_graph_bundle import _read_text, main
from src.threatragraph.evidence_graph import fingerprint
from src.threatragraph.portable_exchange import (
    bundle_json, create_bundle, export_claims_csv, parse_bundle_json,
    verify_bundle, verify_claims_csv,
)


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def fixture(*, reviewed=True, edge_count=1):
    view = {
        "schema_version": "1.0",
        "artifact_kind": "historical_source_input",
        "dataset_id": "synthetic",
        "dataset_version": "v1",
        "case_id": "case-1",
        "target_entity_id": "malware:sample",
        "cutoff_at": "2024-01-01T00:00:00Z",
        "scope_warning": "Synthetic candidate-only data",
        "method": "B0_sparse_report_only",
        "sources": [{
            "role": "early",
            "source_version_id": "source-early",
            "sha256": digest("synthetic source bytes"),
            "available_at": "2023-12-01T00:00:00Z",
            "independence_group": "publisher-a",
        }],
    }
    edges = []
    for number in range(edge_count):
        claim = {
            "claim_id": "claim:" + digest("claim-" + str(number)),
            "source_version_id": "source-early",
            "subject_id": "malware:sample",
            "predicate": "USES",
            "object_id": "attack-technique:T1059",
            "assertion_kind": "report_assertion",
            "polarity": "positive",
            "evidence_locator": {
                "kind": "text_span", "segment_id": "seg:early",
                "start": number, "end": number + 1,
            },
            "evidence_sha256": digest("evidence-" + str(number)),
            "extractor_version": "synthetic-v1",
            "evidence_status": "aligned",
        }
        if reviewed:
            claim["semantic_review_status"] = "supported_by_excerpt"
        edges.append(claim)
    graph = {
        "schema_version": "1.0",
        "artifact_kind": "historical_sourced_graph",
        "case_id": view["case_id"],
        "method": view["method"],
        "cutoff_at": view["cutoff_at"],
        "source_view_sha256": fingerprint(view),
        "nodes": (["attack-technique:T1059", "malware:sample"]
                  if edges else []),
        "edges": edges,
        "caveat": "Synthetic source assertions, not independently true",
    }
    return view, graph


def bundle(*, reviewed=True, edge_count=1):
    v, g = fixture(reviewed=reviewed, edge_count=edge_count)
    return create_bundle(v, g, reviewed=reviewed)


class PortableGraphExchangeTests(unittest.TestCase):
    def test_reviewed_json_and_csv_round_trip(self):
        original = bundle()
        imported = parse_bundle_json(bundle_json(original))
        self.assertEqual(original, imported)
        content = export_claims_csv(imported)
        report = verify_claims_csv(content, imported)
        self.assertTrue(report["csv_matches_bundle"])
        self.assertEqual(1, report["csv_claim_count"])
        self.assertFalse(report["research_ready"])

    def test_unreviewed_graph_stays_unreviewed(self):
        original = bundle(reviewed=False)
        content = export_claims_csv(original)
        receipt = verify_claims_csv(content, original)
        self.assertEqual(1, receipt["claim_count"])
        self.assertFalse(receipt["reviewer_identities_verified"])

    def test_same_bundle_id_for_reordered_view_fields(self):
        v, g = fixture()
        altered = dict(reversed(list(v.items())))
        a = create_bundle(v, g, reviewed=True)
        b = create_bundle(altered, g, reviewed=True)
        self.assertEqual(a["bundle_id"], b["bundle_id"])

    def test_tampered_source_evidence_refused_even_if_bundle_id_rehashed(self):
        value = bundle()
        value["sourced_graph"]["edges"][0]["evidence_sha256"] = digest("bad")
        value["bundle_id"] = "bundle:" + fingerprint({
            k: v for k, v in value.items() if k != "bundle_id"
        })
        with self.assertRaisesRegex(ValueError, "differ from sealed"):
            verify_bundle(value)

    def test_forbidden_future_label_field_refused(self):
        value = bundle()
        value["gold_labels"] = ["future answer"]
        with self.assertRaisesRegex(ValueError, "Exact v1"):
            verify_bundle(value)

    def test_future_dated_source_is_refused_even_with_matching_graph_digest(self):
        view, graph = fixture()
        view["sources"][0]["available_at"] = "2024-02-01T00:00:00Z"
        graph["source_view_sha256"] = fingerprint(view)
        with self.assertRaisesRegex(ValueError, "post-cutoff"):
            create_bundle(view, graph, reviewed=True)

    def test_modified_imported_csv_row_refused(self):
        value = bundle()
        content = export_claims_csv(value).replace("T1059", "T1105")
        with self.assertRaisesRegex(ValueError, "differ from exact"):
            verify_claims_csv(content, value)

    def test_modified_locator_refused(self):
        value = bundle()
        content = export_claims_csv(value).replace("seg:early", "seg:later")
        with self.assertRaisesRegex(ValueError, "differ from exact"):
            verify_claims_csv(content, value)

    def test_duplicate_claim_ids_refused(self):
        view, graph = fixture(edge_count=2)
        graph["edges"][1]["claim_id"] = graph["edges"][0]["claim_id"]
        with self.assertRaisesRegex(ValueError, "duplicate"):
            create_bundle(view, graph, reviewed=True)

    def test_review_state_cannot_be_invented(self):
        view, graph = fixture(reviewed=False)
        with self.assertRaises(ValueError):
            create_bundle(view, graph, reviewed=True)

    def test_unknown_contract_version_refused(self):
        value = bundle()
        value["contract_version"] = "unapproved-v2"
        value["bundle_id"] = "bundle:" + fingerprint({
            k: v for k, v in value.items() if k != "bundle_id"
        })
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            verify_bundle(value)

    def test_csv_spreadsheet_formula_prefix_is_refused(self):
        view, graph = fixture()
        graph["edges"][0]["extractor_version"] = "=HYPERLINK(1)"
        candidate = create_bundle(view, graph, reviewed=True)
        with self.assertRaisesRegex(ValueError, "Unsafe"):
            export_claims_csv(candidate)

    def test_empty_graph_has_only_csv_header(self):
        value = bundle(edge_count=0)
        content = export_claims_csv(value)
        self.assertEqual(1, len(content.splitlines()))
        self.assertEqual(0, verify_claims_csv(content, value)["csv_claim_count"])

    def test_duplicate_json_field_refused(self):
        content = bundle_json(bundle())
        first = '"schema_version":"1.0"'
        self.assertIn(first, content)
        content = content.replace(first, first + "," + first, 1)
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            parse_bundle_json(content)

    def test_extra_csv_column_refused(self):
        value = bundle()
        content = export_claims_csv(value)
        first, rest = content.split("\n", 1)
        with self.assertRaisesRegex(ValueError, "field names"):
            verify_claims_csv(first + ',"future_answer"' + "\n" + rest, value)

    def test_export_write_then_verify_cli_without_original_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            view, graph = fixture()
            view_path = root / "view.json"
            graph_path = root / "graph.json"
            view_path.write_text(json.dumps(view), encoding="utf-8")
            graph_path.write_text(json.dumps(graph), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = main([
                    "--mode", "export", "--view", str(view_path),
                    "--graph", str(graph_path), "--reviewed", "--write",
                    "--output-dir", str(root / "out"),
                ])
            self.assertEqual(0, status)
            info = json.loads(output.getvalue())
            self.assertEqual("portable_export_written", info["status"])
            verify_output = StringIO()
            with redirect_stdout(verify_output):
                status = main([
                    "--mode", "verify", "--bundle", info["bundle_path"],
                    "--csv", info["csv_path"],
                ])
            self.assertEqual(0, status)
            self.assertTrue(json.loads(verify_output.getvalue())["csv_verified"])

    def test_import_refuses_symlinked_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            original = Path(tmp) / "original.json"
            link = Path(tmp) / "linked.json"
            original.write_text("{}", encoding="utf-8")
            try:
                link.symlink_to(original)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink unavailable on this platform")
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                _read_text(link)


if __name__ == "__main__":
    unittest.main()
