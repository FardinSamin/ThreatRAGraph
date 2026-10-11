"""Synthetic-only cross-component sidecar handoff; not historical validation."""
import copy
import hashlib
import json
import os
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from scripts.audit_independent_sidecars import main
from src.threatragraph.alias_history import create_history
from src.threatragraph.evidence_graph import fingerprint
from src.threatragraph.portable_exchange import create_bundle, export_claims_csv
from src.threatragraph.sidecar_reconciliation import reconcile_sidecars


def fixture():
    early = {
        "role": "early", "source_version_id": "early-one",
        "sha256": "a" * 64,
        "available_at": "2022-12-01T00:00:00Z",
        "independence_group": "early-publisher",
    }
    historical = {
        "role": "background", "source_version_id": "historical-one",
        "sha256": "b" * 64,
        "available_at": "2022-10-01T00:00:00Z",
        "independence_group": "historical-publisher",
    }
    base = {
        "schema_version": "1.0",
        "artifact_kind": "historical_source_input",
        "dataset_id": "synthetic", "dataset_version": "v1",
        "case_id": "candidate-a", "target_entity_id": "malware:target",
        "cutoff_at": "2023-01-01T00:00:00Z",
        "scope_warning": "Synthetic only; no independently approved sources",
    }
    b0_view = {**base, "method": "B0_sparse_report_only",
               "sources": [early]}
    g1_view = {**base, "method": "G1_early_plus_historical_background",
               "sources": [copy.deepcopy(early), historical]}
    first = {
        "claim_id": "claim:" + "1" * 64,
        "source_version_id": "early-one",
        "subject_id": "malware:target", "predicate": "USES",
        "object_id": "attack-technique:T1059",
        "assertion_kind": "report_assertion", "polarity": "positive",
        "evidence_locator": {
            "kind": "text_span", "segment_id": "early-source",
            "start": 0, "end": 5,
        },
        "evidence_sha256": "2" * 64,
        "extractor_version": "synthetic-v1",
        "evidence_status": "aligned",
        "semantic_review_status": "supported_by_excerpt",
    }
    second = {
        **first, "claim_id": "claim:" + "3" * 64,
        "source_version_id": "historical-one",
        "subject_id": "malware:peer",
        "evidence_sha256": "4" * 64,
        "evidence_locator": {
            "kind": "text_span", "segment_id": "historical-source",
            "start": 2, "end": 9,
        },
    }

    def graph(view, edges):
        nodes = sorted({v for e in edges
                        for v in (e["subject_id"], e["object_id"])})
        return {
            "schema_version": "1.0",
            "artifact_kind": "historical_sourced_graph",
            "case_id": view["case_id"], "method": view["method"],
            "cutoff_at": view["cutoff_at"],
            "source_view_sha256": fingerprint(view),
            "nodes": nodes, "edges": edges,
            "caveat": "Synthetic review status only",
        }

    b0_graph = graph(b0_view, [first])
    g1_graph = graph(g1_view, [copy.deepcopy(first), second])
    b0_bundle = create_bundle(b0_view, b0_graph, reviewed=True)
    g1_bundle = create_bundle(g1_view, g1_graph, reviewed=True)
    history = create_history(b0_view, [{
        "alias_id": "malware:earlier-name",
        "canonical_candidate_id": "malware:target",
        "source_version_id": "early-one", "source_sha256": "a" * 64,
        "first_known_at": "2022-12-01T00:00:00Z",
        "evidence_sha256": "5" * 64,
        "reviewer_id_declared": "synthetic-reviewer",
        "decision": "candidate_supported",
    }])
    return b0_view, b0_graph, g1_view, g1_graph, b0_bundle, g1_bundle, history


class SidecarReconciliationTests(unittest.TestCase):
    def test_exact_frozen_views_and_sidecars_agree_without_mutating_inputs(self):
        inputs = fixture()
        original = copy.deepcopy(inputs)
        result = reconcile_sidecars(*inputs[:6], alias_history=inputs[6])
        self.assertEqual(inputs, original)
        self.assertEqual("candidate-a", result["case_id"])
        self.assertEqual(1, result["alias_names_inspected"])
        self.assertFalse(result["automatic_alias_rewrites"])
        self.assertFalse(result["g1_feature_lineage_modified"])
        self.assertFalse(result["heldout_labels_read"])
        self.assertFalse(result["research_ready"])
        self.assertEqual(result,
                         reconcile_sidecars(*inputs[:6], alias_history=inputs[6]))

    def test_without_alias_candidates_does_not_infer_any(self):
        result = reconcile_sidecars(*fixture()[:6])
        self.assertIsNone(result["alias_history_id"])
        self.assertEqual(0, result["alias_names_inspected"])

    def test_rejects_g1_exchange_bundle_from_a_different_graph(self):
        values = list(fixture())
        values[5] = copy.deepcopy(values[4])
        with self.assertRaisesRegex(ValueError, "Portable G1 evidence sidecar drift"):
            reconcile_sidecars(*values[:6])

    def test_rejects_valid_but_altered_portable_b0_graph(self):
        values = list(fixture())
        altered = copy.deepcopy(values[1])
        altered["edges"][0]["evidence_sha256"] = "f" * 64
        values[4] = create_bundle(values[0], altered, reviewed=True)
        with self.assertRaisesRegex(ValueError, "Portable B0 evidence sidecar drift"):
            reconcile_sidecars(*values[:6])

    def test_rejects_future_alias_when_rehashed(self):
        values = list(fixture())
        hist = values[6]
        hist["entries"][0]["first_known_at"] = "2025-01-01T00:00:00Z"
        hist.pop("history_id")
        hist["history_id"] = "alias-history:" + fingerprint(hist)
        with self.assertRaisesRegex(ValueError, "Future or retrospectively"):
            reconcile_sidecars(*values[:6], alias_history=hist)

    def test_rejects_wrong_case_alias_history(self):
        values = list(fixture())
        hist = values[6]
        hist["case_id"] = "candidate-b"
        hist.pop("history_id")
        hist["history_id"] = "alias-history:" + fingerprint(hist)
        with self.assertRaisesRegex(ValueError, "does not match"):
            reconcile_sidecars(*values[:6], alias_history=hist)

    def test_early_source_drift_rejected_even_with_consistent_bundle(self):
        values = list(fixture())
        g1view = copy.deepcopy(values[2])
        g1view["sources"][0]["independence_group"] = "other-publisher"
        graph = copy.deepcopy(values[3])
        graph["source_view_sha256"] = fingerprint(g1view)
        values[2] = g1view
        values[3] = graph
        values[5] = create_bundle(g1view, graph, reviewed=True)
        with self.assertRaisesRegex(ValueError, "early sources differ"):
            reconcile_sidecars(*values[:6])

    def test_unreviewed_sidecar_cannot_be_mistaken_for_reviewed_graph(self):
        values = list(fixture())
        unreviewed = copy.deepcopy(values[1])
        for edge in unreviewed["edges"]:
            del edge["semantic_review_status"]
        values[4] = create_bundle(values[0], unreviewed, reviewed=False)
        with self.assertRaisesRegex(ValueError, "Portable B0 evidence sidecar drift"):
            reconcile_sidecars(*values[:6])

    def test_unaligned_graph_cannot_pass_export_sidecar_audit(self):
        values = list(fixture())
        graph = copy.deepcopy(values[1])
        graph["edges"][0]["evidence_status"] = "unverified"
        values[1] = graph
        values[4] = create_bundle(values[0], graph, reviewed=True)
        with self.assertRaisesRegex(ValueError, "Unaligned or unsupported"):
            reconcile_sidecars(*values[:6])

    def test_unreviewed_semantic_evidence_cannot_pass_reconciliation(self):
        values = list(fixture())
        graph = copy.deepcopy(values[3])
        graph["edges"][1]["semantic_review_status"] = "unreviewed"
        values[3] = graph
        values[5] = create_bundle(values[2], graph, reviewed=True)
        with self.assertRaisesRegex(ValueError, "Unaligned or unsupported"):
            reconcile_sidecars(*values[:6])

    def test_background_cannot_share_early_publisher_group(self):
        values = list(fixture())
        view = copy.deepcopy(values[2])
        view["sources"][1]["independence_group"] = "early-publisher"
        graph = copy.deepcopy(values[3])
        graph["source_view_sha256"] = fingerprint(view)
        values[2], values[3] = view, graph
        values[5] = create_bundle(view, graph, reviewed=True)
        with self.assertRaisesRegex(ValueError, "shares an early publisher"):
            reconcile_sidecars(*values[:6])

    def test_background_target_specific_evidence_is_refused(self):
        values = list(fixture())
        graph = copy.deepcopy(values[3])
        graph["edges"][1]["subject_id"] = "malware:target"
        graph["nodes"] = sorted({
            field for e in graph["edges"]
            for field in (e["subject_id"], e["object_id"])
        })
        values[3] = graph
        values[5] = create_bundle(values[2], graph, reviewed=True)
        with self.assertRaisesRegex(ValueError, "Target-specific"):
            reconcile_sidecars(*values[:6])

    def test_contradictory_alias_evidence_is_reported_as_conflict(self):
        values = list(fixture())
        original = copy.deepcopy(values[6]["entries"][0])
        rebuttal = dict(original, evidence_sha256="6" * 64,
                        decision="candidate_rejected")
        values[6] = create_history(values[0], [original, rebuttal])
        result = reconcile_sidecars(*values[:6], alias_history=values[6])
        self.assertEqual(1, result["alias_names_inspected"])
        self.assertEqual(1, result["ambiguous_alias_names"])
        self.assertFalse(result["automatic_alias_rewrites"])

    def test_both_exact_csv_witnesses_are_verified(self):
        values = fixture()
        csv_b0 = export_claims_csv(values[4])
        csv_g1 = export_claims_csv(values[5])
        result = reconcile_sidecars(
            *values[:6], b0_csv=csv_b0, g1_csv=csv_g1
        )
        self.assertTrue(result["csv_witnesses_verified"])
        self.assertEqual(
            hashlib.sha256(csv_b0.encode("utf-8")).hexdigest(),
            result["b0_csv_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(csv_g1.encode("utf-8")).hexdigest(),
            result["g1_csv_sha256"],
        )
        self.assertFalse(result["research_ready"])

    def test_no_csv_witnesses_never_claim_csv_validation(self):
        result = reconcile_sidecars(*fixture()[:6])
        self.assertFalse(result["csv_witnesses_verified"])
        self.assertIsNone(result["b0_csv_sha256"])
        self.assertIsNone(result["g1_csv_sha256"])

    def test_one_sided_csv_witness_is_refused(self):
        values = fixture()
        csv = export_claims_csv(values[4])
        with self.assertRaisesRegex(ValueError, "supplied together"):
            reconcile_sidecars(*values[:6], b0_csv=csv)
        with self.assertRaisesRegex(ValueError, "supplied together"):
            reconcile_sidecars(*values[:6], g1_csv=csv)

    def test_modified_b0_csv_claim_refused(self):
        values = fixture()
        csv0 = export_claims_csv(values[4]).replace("T1059", "T1105")
        csv1 = export_claims_csv(values[5])
        with self.assertRaisesRegex(ValueError, "differ from exact"):
            reconcile_sidecars(*values[:6], b0_csv=csv0, g1_csv=csv1)

    def test_modified_g1_csv_claim_refused(self):
        values = fixture()
        csv0 = export_claims_csv(values[4])
        csv1 = export_claims_csv(values[5]).replace(
            "historical-one", "future-version", 1
        )
        with self.assertRaisesRegex(ValueError, "differ from exact"):
            reconcile_sidecars(*values[:6], b0_csv=csv0, g1_csv=csv1)

    def test_noncanonical_blank_csv_line_refused(self):
        values = fixture()
        csv0 = export_claims_csv(values[4]) + "\n"
        csv1 = export_claims_csv(values[5])
        with self.assertRaisesRegex(ValueError, "canonical v1"):
            reconcile_sidecars(*values[:6], b0_csv=csv0, g1_csv=csv1)

    def test_cli_accepts_both_csv_witnesses_without_writing(self):
        values = fixture()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fields = (
                "b0-view", "b0-graph", "g1-view", "g1-graph",
                "b0-bundle", "g1-bundle",
            )
            arguments = []
            for field, value in zip(fields, values[:6]):
                path = root / (field + ".json")
                path.write_text(json.dumps(value), encoding="utf-8")
                arguments += ["--" + field, str(path)]
            for name, value in (
                ("b0-csv", export_claims_csv(values[4])),
                ("g1-csv", export_claims_csv(values[5])),
            ):
                path = root / (name + ".csv")
                path.write_text(value, encoding="utf-8")
                arguments += ["--" + name, str(path)]
            text = StringIO()
            with redirect_stdout(text):
                status = main(arguments)
            self.assertEqual(0, status)
            result = json.loads(text.getvalue())
            self.assertTrue(result["receipt"]["csv_witnesses_verified"])
            self.assertFalse(result["receipt"]["research_ready"])

    def test_cli_refuses_single_csv_path_before_opening_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = str(Path(directory) / "not-present.json")
            argv = [
                "--b0-view", missing, "--b0-graph", missing,
                "--g1-view", missing, "--g1-graph", missing,
                "--b0-bundle", missing, "--g1-bundle", missing,
                "--b0-csv", missing,
            ]
            text = StringIO()
            with redirect_stdout(text):
                status = main(argv)
            self.assertEqual(2, status)
            self.assertEqual("ValueError",
                             json.loads(text.getvalue())["reason_category"])

    def test_cli_refuses_symlinked_parent_of_b0_view(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir()
            path = real / "view.json"
            path.write_text("{}", encoding="utf-8")
            linked = root / "linked"
            try:
                linked.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Directory symlinks not available")
            others = []
            for i in range(5):
                p = root / ("other-" + str(i) + ".json")
                p.write_text("{}", encoding="utf-8")
                others.append(str(p))
            fields = ("b0-view", "b0-graph", "g1-view", "g1-graph",
                      "b0-bundle", "g1-bundle")
            argv = []
            for key, name in zip(fields, [str(linked / "view.json"), *others]):
                argv.extend(["--" + key, name])
            text = StringIO()
            with redirect_stdout(text):
                status = main(argv)
            self.assertEqual(2, status)
            self.assertEqual("ValueError",
                             json.loads(text.getvalue())["reason_category"])

    def test_cli_refuses_hardlinked_distinct_argument_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for i in range(6):
                path = root / ("part-" + str(i) + ".json")
                path.write_text("{}", encoding="utf-8")
                paths.append(path)
            paths[-1].unlink()
            try:
                os.link(paths[-2], paths[-1])
            except OSError:
                self.skipTest("Hardlinks not available")
            fields = ("b0-view", "b0-graph", "g1-view", "g1-graph",
                      "b0-bundle", "g1-bundle")
            argv = []
            for key, path in zip(fields, paths):
                argv.extend(["--" + key, str(path)])
            text = StringIO()
            with redirect_stdout(text):
                status = main(argv)
            self.assertEqual(2, status)
            self.assertEqual("ValueError",
                             json.loads(text.getvalue())["reason_category"])

    def test_cli_refuses_nonfinite_nested_json_before_graph_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = []
            for i in range(6):
                path = root / ("part-" + str(i) + ".json")
                path.write_text("{}", encoding="utf-8")
                paths.append(path)
            paths[0].write_text('{"nested":{"future":Infinity}}',
                                encoding="utf-8")
            fields = ("b0-view", "b0-graph", "g1-view", "g1-graph",
                      "b0-bundle", "g1-bundle")
            argv = []
            for key, path in zip(fields, paths):
                argv.extend(["--" + key, str(path)])
            text = StringIO()
            with redirect_stdout(text):
                status = main(argv)
            self.assertEqual(2, status)
            self.assertEqual("ValueError",
                             json.loads(text.getvalue())["reason_category"])

    def test_cli_read_only_candidate_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            values = fixture()
            fields = (
                "b0-view", "b0-graph", "g1-view", "g1-graph",
                "b0-bundle", "g1-bundle", "alias-history",
            )
            args = []
            for field, value in zip(fields, values):
                path = root / (field + ".json")
                path.write_text(json.dumps(value), encoding="utf-8")
                args += ["--" + field, str(path)]
            output = StringIO()
            with redirect_stdout(output):
                exit_code = main(args)
            self.assertEqual(0, exit_code)
            report = json.loads(output.getvalue())
            self.assertEqual("candidate_sidecars_structurally_consistent",
                             report["status"])
            self.assertFalse(report["research_ready"])
            self.assertFalse(report["receipt"]["automatic_alias_rewrites"])


if __name__ == "__main__":
    unittest.main()
