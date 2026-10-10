"""Synthetic source-level historical B0/G1 snapshot tests, no external CTI."""

import hashlib
import io
import json
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import unittest

from scripts.freeze_case_snapshots import (
    all_views, canonical_bytes, case_views, main,
    snapshot_sha256, write_immutable_view,
)


def source(version, date, group):
    return {
        "source_id": "src:" + version,
        "source_version_id": version,
        "source_kind": "cti_report",
        "title": "Synthetic " + version,
        "publisher": "Synthetic fixture",
        "url": "https://example.org/" + version,
        "status": "approved",
        "published_at": date,
        "available_at": date,
        "date_confidence": "verified",
        "date_evidence": "Synthetic test fixture date",
        "independence_group": group,
        "sha256": hashlib.sha256(version.encode("utf-8")).hexdigest(),
        "redistribution": "restricted",
        "selection_rationale": "Unit-test-only source",
    }


def manifests():
    source_manifest = {
        "schema_version": "1.0", "dataset_id": "synthetic",
        "dataset_version": "v1", "sources": [
            source("early1", "2024-01-01T00:00:00Z", "independent-a"),
            source("back-a", "2023-06-01T00:00:00Z", "independent-b"),
            source("back-z", "2023-07-01T00:00:00Z", "independent-c"),
            source("heldout-secret", "2024-02-01T00:00:00Z", "independent-d"),
        ],
    }
    case_manifest = {
        "schema_version": "1.0", "dataset_id": "synthetic",
        "dataset_version": "v1", "cases": [{
            "case_id": "synthetic-case",
            "target_entity_id": "malware:synthetic",
            "selection_rationale": "An invented fixture, not a real threat",
            "cutoff_at": "2024-01-15T00:00:00Z",
            "early_source_version_ids": ["early1"],
            "background_source_version_ids": ["back-z", "back-a"],
            "later_reference_source_version_ids": ["heldout-secret"],
        }],
    }
    return source_manifest, case_manifest


class SnapshotTests(unittest.TestCase):
    def test_baseline_only_early_and_graph_adds_background(self):
        sources, cases = manifests()
        views = case_views(sources, cases, "synthetic-case")
        self.assertEqual(["early1"], [
            x["source_version_id"] for x in views["B0"]["sources"]
        ])
        self.assertEqual(["early1", "back-a", "back-z"], [
            x["source_version_id"] for x in views["G1"]["sources"]
        ])
        self.assertEqual("B0_sparse_report_only", views["B0"]["method"])

    def test_heldout_identifiers_not_revealed_anywhere(self):
        sources, cases = manifests()
        views = case_views(sources, cases, "synthetic-case")
        serialized = json.dumps(views)
        self.assertNotIn("heldout-secret", serialized)
        self.assertNotIn("later_reference_source_version_ids", serialized)
        self.assertNotIn("https://example.org/heldout-secret", serialized)
        self.assertNotIn("reference_labels", serialized)

    def test_digest_stable_across_background_order(self):
        sources, cases = manifests()
        first = case_views(sources, cases, "synthetic-case")["G1"]
        cases["cases"][0]["background_source_version_ids"].reverse()
        second = case_views(sources, cases, "synthetic-case")["G1"]
        self.assertEqual(snapshot_sha256(first), snapshot_sha256(second))
        self.assertEqual(canonical_bytes(first), canonical_bytes(second))

    def test_future_source_in_background_refused(self):
        sources, cases = manifests()
        cases["cases"][0]["background_source_version_ids"].append(
            "heldout-secret"
        )
        with self.assertRaises(ValueError):
            case_views(sources, cases, "synthetic-case")

    def test_cutoff_tampering_refused(self):
        sources, cases = manifests()
        cases["cases"][0]["cutoff_at"] = "2023-12-01T00:00:00Z"
        with self.assertRaises(ValueError):
            case_views(sources, cases, "synthetic-case")

    def test_unknown_case_refused(self):
        sources, cases = manifests()
        with self.assertRaises(ValueError):
            case_views(sources, cases, "does-not-exist")

    def test_snapshot_file_immutable_and_idempotent(self):
        sources, cases = manifests()
        record = case_views(sources, cases, "synthetic-case")["B0"]
        with tempfile.TemporaryDirectory() as root:
            digest, path, created = write_immutable_view(record, root)
            self.assertTrue(created)
            self.assertEqual(snapshot_sha256(record), digest)
            self.assertEqual(canonical_bytes(record), path.read_bytes())
            digest_again, same_path, created_again = write_immutable_view(
                record, root
            )
            self.assertEqual(path, same_path)
            self.assertEqual(digest, digest_again)
            self.assertFalse(created_again)

    def test_snapshot_corruption_is_rejected(self):
        sources, cases = manifests()
        record = case_views(sources, cases, "synthetic-case")["B0"]
        with tempfile.TemporaryDirectory() as root:
            _, path, _ = write_immutable_view(record, root)
            path.write_text("tampered", encoding="utf-8")
            with self.assertRaises(ValueError):
                write_immutable_view(record, root)

    def test_symlink_output_root_refused(self):
        sources, cases = manifests()
        record = case_views(sources, cases, "synthetic-case")["B0"]
        with tempfile.TemporaryDirectory() as root:
            actual = Path(root) / "actual"
            actual.mkdir()
            alias = Path(root) / "alias"
            try:
                alias.symlink_to(actual, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink not supported")
            with self.assertRaises(ValueError):
                write_immutable_view(record, alias)

    def test_empty_case_registry_only_previews(self):
        sources, cases = manifests()
        cases["cases"] = []
        views, warnings, counts = all_views(sources, cases)
        self.assertEqual({}, views)
        self.assertEqual(0, counts["cases"])
        self.assertTrue(warnings)

    def test_dry_run_does_not_write_files(self):
        sources, cases = manifests()
        with tempfile.TemporaryDirectory() as root:
            sources_path = Path(root) / "sources.json"
            cases_path = Path(root) / "cases.json"
            snapshots_path = Path(root) / "snapshots"
            sources_path.write_text(json.dumps(sources))
            cases_path.write_text(json.dumps(cases))
            capture = io.StringIO()
            with redirect_stdout(capture):
                result = main([str(sources_path), str(cases_path),
                               "--output-dir", str(snapshots_path)])
            self.assertEqual(0, result)
            self.assertFalse(snapshots_path.exists())
            self.assertEqual("metadata_preview",
                             json.loads(capture.getvalue())["status"])

    def test_write_requires_full_research_readiness(self):
        sources, cases = manifests()
        with tempfile.TemporaryDirectory() as root:
            sources_path = Path(root) / "sources.json"
            cases_path = Path(root) / "cases.json"
            snapshots_path = Path(root) / "snapshots"
            sources_path.write_text(json.dumps(sources))
            cases_path.write_text(json.dumps(cases))
            capture = io.StringIO()
            with redirect_stdout(capture):
                result = main([str(sources_path), str(cases_path), "--write",
                               "--output-dir", str(snapshots_path)])
            self.assertEqual(2, result)
            self.assertFalse(snapshots_path.exists())
            self.assertEqual("not_research_ready",
                             json.loads(capture.getvalue())["status"])


if __name__ == "__main__":
    unittest.main()
