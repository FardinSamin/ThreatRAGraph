"""Offline byte-integrity and tamper-resistance tests (synthetic data only)."""

import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts.audit_source_artifacts import audit_sources, sha256_file


def record(version, blob):
    return {
        "status": "approved",
        "source_version_id": version,
        "sha256": hashlib.sha256(blob).hexdigest(),
    }


def write_blob(root, blob):
    digest = hashlib.sha256(blob).hexdigest()
    directory = Path(root) / digest[:2]
    directory.mkdir(parents=True, exist_ok=True)
    (directory / digest).write_bytes(blob)
    return digest


class ArchiveAuditTests(unittest.TestCase):
    def test_valid_exact_source_bytes(self):
        with tempfile.TemporaryDirectory() as root:
            data = b"Allowed, synthetic threat report v1.\n"
            rec = record("fixture-v1", data)
            write_blob(root, data)
            report, errors, warnings = audit_sources(
                {"sources": [rec]}, root, require_all=True
            )
            self.assertEqual([], errors)
            self.assertEqual([], warnings)
            self.assertEqual("verified_all", report["status"])
            self.assertEqual(1, report["verified_bytes"])
            self.assertEqual("verified", report["checked"][0]["result"])

    def test_missing_required_archive_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            data = b"fixture"
            report, errors, _ = audit_sources(
                {"sources": [record("fixture", data)]}, root,
                require_all=True,
            )
            self.assertEqual("invalid", report["status"])
            self.assertEqual(1, report["missing_bytes"])
            self.assertTrue(any("not found" in x for x in errors))

    def test_missing_allowed_for_metadata_only(self):
        with tempfile.TemporaryDirectory() as root:
            data = b"fixture"
            report, errors, warnings = audit_sources(
                {"sources": [record("fixture", data)]}, root,
                require_all=False,
            )
            self.assertFalse(errors)
            self.assertEqual("incomplete", report["status"])
            self.assertTrue(warnings)

    def test_corrupted_archive_is_detected(self):
        with tempfile.TemporaryDirectory() as root:
            expected = b"Expected fixture report"
            rec = record("original", expected)
            archive = Path(root) / rec["sha256"][:2] / rec["sha256"]
            archive.parent.mkdir()
            archive.write_bytes(b"Changed report content")
            report, errors, _ = audit_sources(
                {"sources": [rec]}, root, require_all=True,
            )
            self.assertEqual("invalid", report["status"])
            self.assertEqual(1, report["mismatched_bytes"])
            self.assertTrue(any("mismatch" in e for e in errors))

    def test_not_a_valid_hex_digest_is_rejected(self):
        report, errors, _ = audit_sources(
            {"sources": [{"status": "approved",
                          "source_version_id": "bad", "sha256": "../../etc"}]},
            ".", require_all=True,
        )
        self.assertEqual("invalid", report["status"])
        self.assertTrue(any("invalid SHA-256" in x for x in errors))

    def test_skips_candidates_without_trusting_them(self):
        report, errors, warnings = audit_sources(
            {"sources": [{"status": "candidate",
                          "source_version_id": "not-yet-frozen"}]}, "."
        )
        self.assertFalse(errors)
        self.assertEqual(1, report["candidate_sources"])
        self.assertEqual(0, report["approved"])
        self.assertTrue(warnings)

    def test_size_ceiling_blocks_large_artifacts(self):
        with tempfile.TemporaryDirectory() as root:
            data = b"Large synthetic fixture data"
            rec = record("big", data)
            write_blob(root, data)
            report, errors, _ = audit_sources(
                {"sources": [rec]}, root, require_all=True, max_bytes=4,
            )
            self.assertEqual("invalid", report["status"])
            self.assertTrue(any("cannot safely hash" in e for e in errors))

    def test_detects_duplicate_bytes_with_different_ids(self):
        with tempfile.TemporaryDirectory() as root:
            data = b"Identical, syndicated report"
            write_blob(root, data)
            manifest = {"sources": [record("report-A", data),
                                    record("report-B", data)]}
            report, errors, warnings = audit_sources(
                manifest, root, require_all=True
            )
            self.assertFalse(errors)
            self.assertEqual(2, report["verified_bytes"])
            self.assertTrue(any("independence" in w for w in warnings))

    def test_rejects_symlink_to_external_content(self):
        with tempfile.TemporaryDirectory() as root:
            blob = b"test content"
            rec = record("symlink", blob)
            path = Path(root) / rec["sha256"][:2] / rec["sha256"]
            path.parent.mkdir()
            outside = Path(root) / "outside.txt"
            outside.write_bytes(blob)
            try:
                path.symlink_to(outside)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks not supported here")
            report, errors, _ = audit_sources(
                {"sources": [rec]}, root, require_all=True
            )
            self.assertEqual("invalid", report["status"])
            self.assertTrue(any("symlink" in e for e in errors))

    def test_scanning_returns_hash_and_byte_count(self):
        with tempfile.TemporaryDirectory() as root:
            data = b"original bytes"
            path = Path(root) / "fixture.bin"
            path.write_bytes(data)
            digest, size = sha256_file(path, max_bytes=100)
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            self.assertEqual(len(data), size)


if __name__ == "__main__":
    unittest.main()
