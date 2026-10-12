"""Synthetic atomic publication tests; authored only, not yet executed."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.freeze_case_snapshots import canonical_bytes, write_immutable_view
from scripts.exchange_graph_bundle import _write_csv
from src.threatragraph.immutable_artifacts import write_immutable_bytes


class ImmutableArtifactWriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "artifacts"
        self.payload = b'{"case":"synthetic"}\n'
        self.sha = hashlib.sha256(self.payload).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def test_atomic_digest_file_bytes_and_clean_private_stage(self):
        digest, path, created = write_immutable_bytes(
            self.payload, self.root, ".json")
        self.assertEqual(self.sha, digest)
        self.assertTrue(created)
        self.assertEqual(self.payload, path.read_bytes())
        self.assertEqual([], list(self.root.glob(".stage-*.partial")))

    def test_exact_byte_retry_is_idempotent(self):
        first = write_immutable_bytes(self.payload, self.root, ".json")
        second = write_immutable_bytes(self.payload, self.root, ".json")
        self.assertEqual(first[:2], second[:2])
        self.assertTrue(first[2])
        self.assertFalse(second[2])

    def test_canonical_snapshot_writer_uses_atomic_byte_helper(self):
        obj = {"b": "2", "a": "1"}
        digest, path, created = write_immutable_view(obj, self.root)
        self.assertTrue(created)
        self.assertEqual(canonical_bytes(obj), path.read_bytes())
        self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_csv_writer_preserves_byte_exact_newlines(self):
        sample = '"subject","evidence"\n"synthetic","aligned"\n'
        digest, path, created = _write_csv(sample, self.root)
        self.assertTrue(created)
        self.assertEqual(sample.encode("utf-8"), path.read_bytes())
        self.assertEqual(digest, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_rejects_replacement_of_digest_file_with_wrong_bytes(self):
        _, path, _ = write_immutable_bytes(self.payload, self.root, ".json")
        path.write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "artifact|digest"):
            write_immutable_bytes(self.payload, self.root, ".json")

    def test_rejects_persistently_hardlinked_digest_file(self):
        self.root.mkdir()
        other = self.base / "other.json"
        other.write_bytes(self.payload)
        try:
            os.link(other, self.root / (self.sha + ".json"))
        except OSError:
            self.skipTest("Hard links unavailable")
        with self.assertRaisesRegex(ValueError, "standalone"):
            write_immutable_bytes(self.payload, self.root, ".json")

    def test_rejects_symlinked_final_destination(self):
        self.root.mkdir()
        target = self.base / "target.json"
        target.write_bytes(self.payload)
        try:
            (self.root / (self.sha + ".json")).symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable")
        with self.assertRaises((OSError, ValueError)):
            write_immutable_bytes(self.payload, self.root, ".json")

    def test_rejects_symlinked_parent_directory(self):
        real = self.base / "real"
        real.mkdir()
        alias = self.base / "alias"
        try:
            alias.symlink_to(real, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable")
        with self.assertRaises((OSError, ValueError)):
            write_immutable_bytes(self.payload, alias / "nested", ".json")
        self.assertFalse((real / "nested").exists())

    def test_rejects_nonregular_digest_directory(self):
        self.root.mkdir()
        (self.root / (self.sha + ".json")).mkdir()
        with self.assertRaisesRegex(ValueError, "standalone"):
            write_immutable_bytes(self.payload, self.root, ".json")

    def test_link_failure_cleans_staging_without_exposing_final_file(self):
        with patch("src.threatragraph.immutable_artifacts.os.link",
                   side_effect=OSError("simulated failure to publish")):
            with self.assertRaisesRegex(OSError, "simulated failure"):
                write_immutable_bytes(self.payload, self.root, ".json")
        self.assertEqual([], list(self.root.glob(".stage-*.partial")))
        self.assertFalse((self.root / (self.sha + ".json")).exists())

    def test_flush_failure_cleans_staging_without_exposing_final_file(self):
        with patch("src.threatragraph.immutable_artifacts.os.fsync",
                   side_effect=OSError("simulated flush failure")):
            with self.assertRaisesRegex(OSError, "flush failure"):
                write_immutable_bytes(self.payload, self.root, ".json")
        self.assertEqual([], list(self.root.glob(".stage-*.partial")))
        self.assertFalse((self.root / (self.sha + ".json")).exists())

    def test_stale_private_stage_does_not_override_final_digest(self):
        self.root.mkdir()
        stale = self.root / ".stage-abandoned.partial"
        stale.write_bytes(b"truncated")
        digest, path, created = write_immutable_bytes(
            self.payload, self.root, ".json")
        self.assertTrue(created)
        self.assertEqual(self.sha, digest)
        self.assertEqual(self.payload, path.read_bytes())
        self.assertEqual(b"truncated", stale.read_bytes())

    def test_concurrent_identical_writes_never_overwrite(self):
        def publish(_):
            return write_immutable_bytes(self.payload, self.root, ".json")
        with ThreadPoolExecutor(max_workers=3) as pool:
            results = list(pool.map(publish, range(3)))
        self.assertEqual(1, sum(int(row[2]) for row in results))
        self.assertTrue(all(row[0] == self.sha for row in results))
        self.assertEqual(self.payload, results[0][1].read_bytes())

    def test_windows_reparse_output_ancestor_is_rejected_before_mkdir(self):
        from src.threatragraph import immutable_artifacts
        destination = self.base / "pretend-junction"
        original = immutable_artifacts.is_linked_path_component

        def linked(path):
            return path == destination or original(path)

        with patch.object(immutable_artifacts,
                          "is_linked_path_component", side_effect=linked):
            with self.assertRaisesRegex(ValueError, "reparse"):
                immutable_artifacts._fallback_root(destination)
        self.assertFalse(destination.exists())

    def test_reparse_digest_destination_is_refused_without_open(self):
        from src.threatragraph import immutable_artifacts
        self.root.mkdir()
        destination = self.root / (self.sha + ".json")
        destination.write_bytes(self.payload)
        with patch.object(immutable_artifacts,
                          "is_linked_path_component", return_value=True):
            with self.assertRaisesRegex(ValueError, "reparse"):
                immutable_artifacts._verify_existing(
                    self.root, destination.name, self.payload, dir_fd=None,
                )
        self.assertEqual(self.payload, destination.read_bytes())

    def test_rejects_unsupported_extensions_and_unbounded_payloads(self):
        for value in (".exe", "../results.json", ".json.extra"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "suffix"):
                    write_immutable_bytes(self.payload, self.root, value)
        with self.assertRaisesRegex(ValueError, "bounded"):
            write_immutable_bytes(b"", self.root, ".json")

    def test_same_data_different_artifact_extension_has_distinct_name(self):
        json_file = write_immutable_bytes(self.payload, self.root, ".json")
        csv_file = write_immutable_bytes(self.payload, self.root, ".csv")
        self.assertEqual(json_file[0], csv_file[0])
        self.assertNotEqual(json_file[1], csv_file[1])
        self.assertTrue(csv_file[2])

    def test_nested_output_directories_created_without_link_following(self):
        dest = self.base / "artifacts" / "nested" / "offline"
        digest, path, created = write_immutable_bytes(
            self.payload, dest, ".json")
        self.assertTrue(created)
        self.assertEqual(digest, self.sha)
        self.assertEqual(self.payload, path.read_bytes())


if __name__ == "__main__":
    unittest.main()
