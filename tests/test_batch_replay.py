"""Synthetic-only structural replay tests, not a real evaluation or source audit."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.freeze_case_snapshots import canonical_bytes, snapshot_sha256, write_immutable_view
from scripts.run_offline_case_batch import ARTIFACT_NAMES, _receipt
from src.threatragraph.batch_replay import _read_canonical, _root_directory, replay_batch
from src.threatragraph.evidence_graph import fingerprint
from src.threatragraph.feature_lineage import (
    ARTIFACT_KIND, CONTRACT_VERSION, EXTRACTION, IDENTITY_POLICY,
    graph_claim_set_sha256,
)
from src.threatragraph.paired_run_freeze import build_paired_run


def sha(s):
    return hashlib.sha256(s.encode()).hexdigest()


def _source(name, role, group):
    return {
        "role": role, "source_version_id": name, "sha256": sha(name),
        "available_at": "2022-01-01T00:00:00Z",
        "independence_group": group,
    }


def _view(case, method, sources):
    return {
        "schema_version": "1.0", "artifact_kind": "historical_source_input",
        "dataset_id": "synthetic", "dataset_version": "v1",
        "case_id": case, "target_entity_id": "malware:new",
        "cutoff_at": "2023-01-01T00:00:00Z",
        "scope_warning": "Synthetic fixture, not real chronology",
        "method": method, "sources": sources,
    }


def _edge(n, version, subject, relation, obj):
    return {
        "claim_id": "claim:" + sha(n),
        "source_version_id": version, "subject_id": subject,
        "predicate": relation, "object_id": obj,
        "assertion_kind": "report_assertion", "polarity": "positive",
        "evidence_locator": {
            "kind": "text_span", "segment_id": "seg:" + version,
            "start": 0, "end": 8,
        },
        "evidence_sha256": sha(n + "-quoted"),
        "extractor_version": "fixture-1", "evidence_status": "aligned",
        "semantic_review_status": "supported_by_excerpt",
    }


def _graph(view, edges):
    return {
        "schema_version": "1.0", "artifact_kind": "historical_sourced_graph",
        "case_id": view["case_id"], "method": view["method"],
        "cutoff_at": view["cutoff_at"], "source_view_sha256": fingerprint(view),
        "nodes": sorted({node for e in edges
                         for node in (e["subject_id"], e["object_id"])}),
        "edges": edges, "caveat": "Synthetic evidence only",
    }


def sample_outputs(case):
    early = _source("early", "early", "early-group")
    back_a = _source("old-a", "background", "bg-group-a")
    back_b = _source("old-b", "background", "bg-group-b")
    b0v = _view(case, "B0_sparse_report_only", [early])
    g1v = _view(case, "G1_early_plus_historical_background",
                [copy.deepcopy(early), back_a, back_b])
    a = _edge("a", "early", "malware:new", "USES",
              "attack-technique:T1059")
    b = _edge("b", "old-a", "malware:old", "USES",
              "attack-technique:T1059")
    c = _edge("c", "old-b", "malware:old", "HAS_BEHAVIOR",
              "attack-behavior:exec-sequence")
    bg, gg = _graph(b0v, [a]), _graph(g1v, [a, b, c])
    sources = {s["source_version_id"]: s for s in g1v["sources"]}
    lineage = {
        "schema_version": CONTRACT_VERSION,
        "artifact_kind": ARTIFACT_KIND,
        "case_id": case, "cutoff_at": g1v["cutoff_at"],
        "g1_source_view_sha256": fingerprint(g1v),
        "g1_graph_sha256": graph_claim_set_sha256(gg),
        "identity_policy": IDENTITY_POLICY,
        "claim_lineage": [
            {
                "claim_id": e["claim_id"],
                "source_version_id": e["source_version_id"],
                "source_sha256": sources[e["source_version_id"]]["sha256"],
                "source_available_at": sources[e["source_version_id"]]["available_at"],
                "claim_evidence_sha256": e["evidence_sha256"],
                "subject_id": e["subject_id"], "predicate": e["predicate"],
                "object_id": e["object_id"],
                "feature_known_at": sources[e["source_version_id"]]["available_at"],
                "derivation": EXTRACTION,
            }
            for e in sorted(gg["edges"], key=lambda item: item["claim_id"])
        ],
        "limitations": "Synthetic declared source dates only",
    }
    metadata = {
        "git_commit_sha": "a" * 40,
        "dependency_lock_sha256": "b" * 64,
        "source_manifest_sha256": "c" * 64,
        "case_manifest_sha256": "d" * 64,
        "review_set_sha256": "e" * 64,
        "ontology_version": "v1", "extractor_version": "fixture-1",
        "ruleset_version": "no-enrichment-v1", "random_seed": None,
    }
    config = {
        "top_k": 5, "min_overlap": 1,
        "min_background_groups": 2, "max_peers_per_feature": 10,
    }
    run = build_paired_run(b0v, bg, g1v, gg, lineage,
                           metadata=metadata, g1_config=config)
    receipt = {
        "schema_version": "1.0",
        "artifact_kind": "offline_unscored_case_pipeline_receipt",
        "pipeline_version": "offline-source-to-paired-v1",
        "case_id": case, "cutoff_at": b0v["cutoff_at"],
        "run_id": run["run_lock"]["run_id"],
        "paired_audit_id": run["paired_audit"]["audit_id"],
        "b0_profile_id": run["b0_profile"]["profile_id"],
        "g1_profile_id": run["g1_profile"]["profile_id"],
        "input_file_sha256": {
            "claims_jsonl": "f" * 64,
            "semantic_reviews_jsonl": metadata["review_set_sha256"],
            "dependencies": metadata["dependency_lock_sha256"],
        },
        "source_manifest_sha256": metadata["source_manifest_sha256"],
        "case_manifest_sha256": metadata["case_manifest_sha256"],
        "feature_lineage_sha256": fingerprint(lineage),
        "graph_sha256": {"B0": fingerprint(bg), "G1": fingerprint(gg)},
        "early_source_version_ids": run["paired_audit"]["early_source_version_ids"],
        "raw_claim_records": 3, "semantic_review_records": 3,
        "source_archive_bytes_checked_by_projection": True,
        "historical_publication_dates_independently_authenticated": False,
        "semantic_reviewer_identities_independently_authenticated": False,
        "original_source_rights_independently_approved": False,
        "heldout_labels_opened": False,
        "empirical_evaluation": "not_performed",
        "research_ready": False,
    }
    receipt["pipeline_id"] = "pipeline:" + fingerprint(receipt)
    return {
        "b0_view": b0v, "b0_graph": bg, "g1_view": g1v, "g1_graph": gg,
        "feature_lineage": lineage,
        **run, "pipeline_receipt": receipt,
    }


def reseal_case_links(outputs):
    """Deliberately simulate a fully rehashed but internally inconsistent export."""
    from src.threatragraph.paired_profile_audit import audit_paired_profiles
    b0, g1 = outputs["b0_profile"], outputs["g1_profile"]
    b0.pop("profile_id", None)
    b0["profile_id"] = "profile:" + fingerprint(b0)
    g1["b0_profile_id"] = b0["profile_id"]
    g1["observed_early_facts"] = copy.deepcopy(b0["facts"])
    g1.pop("profile_id", None)
    g1["profile_id"] = "profile:" + fingerprint(g1)
    outputs["paired_audit"] = audit_paired_profiles(b0, g1)
    lock = outputs["run_lock"]
    lock["b0_profile_id"] = b0["profile_id"]
    lock["g1_profile_id"] = g1["profile_id"]
    lock["paired_audit_id"] = outputs["paired_audit"]["audit_id"]
    lock.pop("run_id", None)
    lock["run_id"] = "run:" + fingerprint(lock)
    receipt = outputs["pipeline_receipt"]
    receipt["b0_profile_id"] = b0["profile_id"]
    receipt["g1_profile_id"] = g1["profile_id"]
    receipt["paired_audit_id"] = outputs["paired_audit"]["audit_id"]
    receipt["run_id"] = lock["run_id"]
    receipt.pop("pipeline_id", None)
    receipt["pipeline_id"] = "pipeline:" + fingerprint(receipt)
    return outputs


class FrozenBatchReplayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.saved = {}
        self.batch_sha = self.build(["case-a", "case-b"])

    def tearDown(self):
        self.temp.cleanup()

    def build(self, cases):
        outputs = [sample_outputs(cid) for cid in cases]
        plan = {"dataset_id": "synthetic", "dataset_version": "v1",
                "cases": [{"case_id": cid} for cid in cases]}
        receipt = _receipt(outputs, plan)
        for output in outputs:
            for name in ARTIFACT_NAMES:
                digest, path, _ = write_immutable_view(output[name], self.root)
                self.saved[(output["pipeline_receipt"]["case_id"], name)] = path
        digest, path, _ = write_immutable_view(receipt, self.root)
        self.batch_file = path
        return digest

    def test_two_real_synthetic_profile_runs_replay_structurally(self):
        report = replay_batch(self.root, self.batch_sha)
        self.assertEqual(2, report["case_count"])
        self.assertEqual(21, report["artifact_count"])
        self.assertTrue(report["canonical_hashes_checked"])
        self.assertTrue(report["b0_deterministically_recomputed"])
        self.assertTrue(report["g1_historical_citations_checked"])
        self.assertTrue(report["g1_ranking_recomputed"])
        self.assertTrue(report["feature_lineage_artifact_reloaded"])
        self.assertFalse(report["feature_lineage_original_bytes_reread"])
        self.assertFalse(report["raw_archive_bytes_reread"])
        self.assertFalse(report["heldout_labels_accessed"])
        self.assertFalse(report["research_ready"])
        self.assertEqual(report, replay_batch(self.root, self.batch_sha))

    def store_rehashed(self, outputs):
        cid = outputs["pipeline_receipt"]["case_id"]
        plan = {"dataset_id": "synthetic", "dataset_version": "v1",
                "cases": [{"case_id": cid}]}
        summary = _receipt([outputs], plan)
        for key in ARTIFACT_NAMES:
            write_immutable_view(outputs[key], self.root)
        digest, _, _ = write_immutable_view(summary, self.root)
        return digest

    def test_rehashed_b0_evidence_hash_cannot_forge_observed_fact(self):
        outputs = sample_outputs("case-rehashed-b0")
        facts = outputs["b0_profile"]["facts"]
        self.assertTrue(facts)
        facts[0]["evidence_sha256s"] = ["0" * 64]
        reseal_case_links(outputs)
        receipt_sha = self.store_rehashed(outputs)
        with self.assertRaisesRegex(ValueError, "deterministic source graph"):
            replay_batch(self.root, receipt_sha)

    def test_rehashed_g1_proposed_relation_citation_must_exist_in_graph(self):
        outputs = sample_outputs("case-rehashed-g1-citation")
        predictions = outputs["g1_profile"]["predictions"]
        self.assertTrue(predictions)
        predictions[0]["proposed_relation_historical_support"][0][
            "evidence_sha256"] = "0" * 64
        reseal_case_links(outputs)
        receipt_sha = self.store_rehashed(outputs)
        with self.assertRaisesRegex(ValueError, "G1 support citation differs"):
            replay_batch(self.root, receipt_sha)

    def test_rehashed_g1_matching_feature_citation_must_exist_in_graph(self):
        outputs = sample_outputs("case-rehashed-feature-citation")
        prediction = outputs["g1_profile"]["predictions"][0]
        prediction["matching_features"][0]["historical_support"][0][
            "evidence_sha256"] = "0" * 64
        reseal_case_links(outputs)
        receipt_sha = self.store_rehashed(outputs)
        with self.assertRaisesRegex(ValueError, "G1 support citation differs"):
            replay_batch(self.root, receipt_sha)

    def test_missing_feature_lineage_artifact_refused(self):
        path = self.saved[("case-b", "feature_lineage")]
        path.unlink()
        with self.assertRaisesRegex(ValueError, "Missing"):
            replay_batch(self.root, self.batch_sha)

    def test_modified_feature_lineage_artifact_bytes_refused(self):
        path = self.saved[("case-a", "feature_lineage")]
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "declared SHA-256"):
            replay_batch(self.root, self.batch_sha)

    def test_rehashed_g1_ranking_must_match_recomputation(self):
        outputs = sample_outputs("case-ranking-attack")
        predictions = outputs["g1_profile"]["predictions"]
        self.assertTrue(predictions)
        predictions[0]["ranking_score"] = 0.123456
        reseal_case_links(outputs)
        receipt_sha = self.store_rehashed(outputs)
        with self.assertRaisesRegex(ValueError, "Saved G1 profile differs"):
            replay_batch(self.root, receipt_sha)

    def test_rehashed_g1_abstention_cannot_forge_recomputation(self):
        outputs = sample_outputs("case-abstention-attack")
        predictions = outputs["g1_profile"]["predictions"]
        self.assertTrue(predictions)
        outputs["g1_profile"]["abstention"]["reason"] = "fabricated"
        reseal_case_links(outputs)
        receipt_sha = self.store_rehashed(outputs)
        with self.assertRaisesRegex(ValueError, "Saved G1 profile differs"):
            replay_batch(self.root, receipt_sha)

    def test_changed_stored_profile_bytes_refused(self):
        path = self.saved[("case-a", "g1_profile")]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "declared SHA-256"):
            replay_batch(self.root, self.batch_sha)

    def test_deleted_case_artifact_refused(self):
        self.saved[("case-b", "b0_graph")].unlink()
        with self.assertRaisesRegex(ValueError, "Missing"):
            replay_batch(self.root, self.batch_sha)

    def test_tampered_batch_receipt_bytes_refused(self):
        self.batch_file.write_bytes(self.batch_file.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            replay_batch(self.root, self.batch_sha)

    def test_noncanonical_json_payload_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "test.json"
            file.write_text('{"z": 1, "a": 2}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Noncanonical"):
                _read_canonical(file)

    def test_duplicate_json_fields_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "test.json"
            file.write_text('{"a":1,"a":1}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                _read_canonical(file)

    def test_nonfinite_json_payload_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "test.json"
            file.write_text('{"x":NaN}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Nonfinite"):
                _read_canonical(file)

    def test_legacy_windows_reparse_root_without_junction_method_refused(self):
        from types import SimpleNamespace
        from src.threatragraph.local_file_inputs import WINDOWS_REPARSE_POINT
        marker = SimpleNamespace(st_file_attributes=WINDOWS_REPARSE_POINT)
        with (patch.object(Path, "is_symlink", return_value=False),
              patch.object(Path, "is_junction", new=None, create=True),
              patch.object(Path, "lstat", return_value=marker)):
            with self.assertRaisesRegex(ValueError, "reparse"):
                replay_batch(self.root, self.batch_sha)

    def test_symlinked_batch_root_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            link = Path(folder) / "alias"
            try:
                link.symlink_to(self.root, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("OS does not allow symlinks")
            with self.assertRaisesRegex(ValueError, "Symlinked"):
                replay_batch(link, self.batch_sha)

    def test_no_follow_read_rejects_symlinked_artifact_leaf(self):
        path = self.saved[("case-a", "g1_graph")]
        backup = path.parent / "original-evidence.txt"
        backup.write_bytes(path.read_bytes())
        path.unlink()
        try:
            path.symlink_to(backup)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks are unavailable")
        with self.assertRaisesRegex(ValueError, "Symlink"):
            replay_batch(self.root, self.batch_sha)

    def test_no_follow_read_rejects_symlinked_parent_directory(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            source = base / "real"
            source.mkdir()
            record = source / "source.json"
            record.write_text('{"a":1}\n', encoding="utf-8")
            linked = base / "linked"
            try:
                linked.symlink_to(source, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Directory symlinks are unavailable")
            with self.assertRaisesRegex(ValueError, "Symlink"):
                _read_canonical(linked / "source.json")

    def test_replay_refuses_fifo_leaf_without_blocking(self):
        import os
        if not hasattr(os, "mkfifo"):
            self.skipTest("Named pipes are not supported")
        path = self.saved[("case-a", "g1_graph")]
        path.unlink()
        os.mkfifo(path)
        with self.assertRaisesRegex(ValueError, "regular"):
            replay_batch(self.root, self.batch_sha)

    def test_replay_uses_descriptor_reader_not_racy_path_read_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "canonical.json"
            path.write_text('{"a":1}\n', encoding="utf-8")
            with patch.object(Path, "read_bytes",
                              side_effect=AssertionError("path read is racy")):
                parsed, _ = _read_canonical(path)
            self.assertEqual({"a": 1}, parsed)

    def test_replay_rejects_file_replaced_with_symlink_before_read(self):
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            path = base / "canonical.json"
            other = base / "other.json"
            path.write_text('{"a":1}\n', encoding="utf-8")
            other.write_text('{"a":1}\n', encoding="utf-8")
            path.unlink()
            try:
                path.symlink_to(other)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable")
            with self.assertRaisesRegex(ValueError, "Symlink"):
                _read_canonical(path)

    def test_swapped_leaf_symlink_during_descriptor_open_is_refused(self):
        from src.threatragraph.local_file_inputs import _open_regular
        with tempfile.TemporaryDirectory() as root:
            base = Path(root)
            leaf = base / "frozen.json"
            replacement = base / "unrelated.json"
            leaf.write_text('{"a":1}\n', encoding="utf-8")
            replacement.write_text('{"a":1}\n', encoding="utf-8")
            probe = base / "test-link"
            try:
                probe.symlink_to(replacement)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable")
            probe.unlink()
            swapped = []

            def swap_at_open(path):
                if not swapped:
                    leaf.unlink()
                    leaf.symlink_to(replacement)
                    swapped.append(True)
                return _open_regular(path)

            with patch("src.threatragraph.local_file_inputs._open_regular",
                       side_effect=swap_at_open):
                with self.assertRaisesRegex(ValueError, "Symlink"):
                    _read_canonical(leaf)
            self.assertEqual([True], swapped)

    def test_root_check_never_resolves_path_after_nofollow_checks(self):
        # An ancestor can be replaced between checking it and resolve();
        # replay must hand the lexical path to the descriptor-based reader.
        with patch.object(Path, "resolve",
                          side_effect=AssertionError("must not resolve")):
            checked = _root_directory(self.root)
        self.assertEqual(self.root.absolute(), checked)

    def test_invalid_batch_digest_refused(self):
        with self.assertRaisesRegex(ValueError, "Invalid digest"):
            replay_batch(self.root, "../gold-labels.json")

    def test_rehashed_lock_cannot_smuggle_future_labels(self):
        """Even if a malicious operator recomputes all local content hashes."""
        outputs = sample_outputs("case-c")
        lock = outputs["run_lock"]
        lock["heldout_labels"] = {"future": True}
        lock.pop("run_id")
        lock["run_id"] = "run:" + fingerprint(lock)
        receipt = outputs["pipeline_receipt"]
        receipt["run_id"] = lock["run_id"]
        receipt.pop("pipeline_id")
        receipt["pipeline_id"] = "pipeline:" + fingerprint(receipt)
        plan = {"dataset_id": "synthetic", "dataset_version": "v1",
                "cases": [{"case_id": "case-c"}]}
        batch = _receipt([outputs], plan)
        for key in ARTIFACT_NAMES:
            write_immutable_view(outputs[key], self.root)
        sha, _, _ = write_immutable_view(batch, self.root)
        with self.assertRaisesRegex(ValueError, "run-lock fields"):
            replay_batch(self.root, sha)

    def test_second_case_output_link_cannot_point_to_first_case(self):
        outputs = [sample_outputs("case-d"), sample_outputs("case-e")]
        plan = {"dataset_id": "synthetic", "dataset_version": "v1",
                "cases": [{"case_id": "case-d"}, {"case_id": "case-e"}]}
        receipt = _receipt(outputs, plan)
        for output in outputs:
            for key in ARTIFACT_NAMES:
                write_immutable_view(output[key], self.root)
        second = receipt["cases"][1]
        first = receipt["cases"][0]
        second["artifacts"]["b0_view"] = first["artifacts"]["b0_view"]
        receipt.pop("batch_id")
        receipt["batch_id"] = "batch:" + fingerprint(receipt)
        sha, _, _ = write_immutable_view(receipt, self.root)
        with self.assertRaisesRegex(ValueError, "Cross-case"):
            replay_batch(self.root, sha)

    def test_self_hashed_metadata_cannot_claim_scientific_approval(self):
        outputs = sample_outputs("case-z")
        outputs["pipeline_receipt"]["research_ready"] = True
        outputs["pipeline_receipt"].pop("pipeline_id")
        outputs["pipeline_receipt"]["pipeline_id"] = "pipeline:" + fingerprint(
            outputs["pipeline_receipt"])
        with self.assertRaisesRegex(ValueError, "Inconsistent"):
            _receipt([outputs], {
                "dataset_id": "synthetic", "dataset_version": "v1",
                "cases": [{"case_id": "case-z"}],
            })


if __name__ == "__main__":
    unittest.main()
