"""Offline synthetic verification of content-addressed candidate capture."""
import copy
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.capture_candidate_snapshot import capture_candidate, MAX_BYTES

UTC = datetime(2026, 10, 10, 23, 0, tzinfo=timezone.utc)


def manifest():
    return {"sources": [{
        "source_version_id": "candidate:public-archive:unfrozen",
        "source_id": "src:public-archive",
        "url": "https://www.openwall.com/lists/oss-security/2024/01/31/6",
        "status": "candidate",
        "available_at": None,
        "sha256": None,
        "date_confidence": "unknown",
    }]}


class CandidateCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.download = self.root / "manual_download.html"
        self.download.write_bytes(b"<html>synthetic public document</html>")
        self.archive_root = self.root / "artifacts" / "source_versions" / "sha256"

    def tearDown(self):
        self.temp.cleanup()

    def capture(self, source=None, file=None, **kwargs):
        return capture_candidate(
            manifest() if source is None else source,
            "candidate:public-archive:unfrozen",
            self.download if file is None else file,
            self.archive_root, now=UTC, **kwargs,
        )

    def test_bytes_archived_under_digest_and_only_candidate_receipt(self):
        rec = self.capture()
        raw = self.download.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        self.assertEqual(digest, rec["captured_sha256"])
        self.assertEqual(len(raw), rec["captured_bytes"])
        self.assertEqual(raw, (self.archive_root / digest[:2] / digest).read_bytes())
        self.assertEqual("2026-10-10T23:00:00Z", rec["local_imported_at_utc"])
        self.assertFalse(rec["research_ready"])
        self.assertIsNone(rec["historical_available_at"])
        self.assertFalse(rec["source_rights_verified"])
        self.assertFalse(rec["source_revision_verified"])
        receipts = list((self.archive_root.parent / "candidate_capture_receipts").glob("*.json"))
        self.assertEqual(1, len(receipts))
        self.assertEqual(rec, json.loads(receipts[0].read_text(encoding="utf-8")))
        self.assertFalse(any(x.is_file() and x.name.endswith(".html")
                             for x in self.archive_root.parent.rglob("*")))

    def test_import_is_idempotent_and_does_not_retimestamp_receipt(self):
        first = self.capture()
        second = capture_candidate(manifest(), "candidate:public-archive:unfrozen",
                                   self.download, self.archive_root,
                                   now=datetime(2026, 10, 11, tzinfo=timezone.utc))
        self.assertEqual(first, second)

    def test_rejects_registry_status_approval_or_self_certified_hash(self):
        for key, value in (
            ("status", "approved"), ("sha256", "0" * 64),
            ("available_at", "2024-01-31T20:33:01Z"), ("date_confidence", "verified"),
        ):
            m = manifest()
            m["sources"][0][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "Only undated"):
                self.capture(source=m)

    def test_unknown_source_or_ambiguous_duplicate_refused(self):
        with self.assertRaisesRegex(ValueError, "uniquely match"):
            capture_candidate(manifest(), "candidate:not-in-registry", self.download,
                              self.archive_root, now=UTC)
        m = manifest()
        m["sources"].append(copy.deepcopy(m["sources"][0]))
        with self.assertRaisesRegex(ValueError, "uniquely match"):
            self.capture(source=m)

    def test_input_cannot_be_empty_or_unbounded(self):
        self.download.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "empty"):
            self.capture()
        self.download.write_bytes(b"x" * 21)
        with self.assertRaisesRegex(ValueError, "size limit"):
            self.capture(max_bytes=20)

    def test_existing_corrupt_artifact_not_replaced(self):
        rec = self.capture()
        target = self.archive_root / rec["content_addressed_relative_path"]
        target.write_bytes(b"corrupted source file")
        with self.assertRaisesRegex(ValueError, "corrupt"):
            self.capture()
        self.assertEqual(b"corrupted source file", target.read_bytes())

    def test_existing_incompatible_receipt_rejected_without_approval(self):
        rec = self.capture()
        receipt_file = next((self.archive_root.parent / "candidate_capture_receipts").glob("*.json"))
        rec["research_ready"] = True
        receipt_file.write_text(json.dumps(rec), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "incompatible"):
            self.capture()

    def test_symlink_input_and_destination_rejected(self):
        symlink = self.root / "point_to_input.html"
        try:
            symlink.symlink_to(self.download)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable on test OS")
        with self.assertRaisesRegex(ValueError, "non-symlink"):
            self.capture(file=symlink)
        expected = hashlib.sha256(self.download.read_bytes()).hexdigest()
        bucket = self.archive_root / expected[:2]
        bucket.parent.mkdir(parents=True)
        bucket.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.capture()

    def test_no_network_dependency_or_automatic_study_approval(self):
        self.assertLess(self.download.stat().st_size, MAX_BYTES)
        rec = self.capture()
        self.assertEqual("investigator_supplied_local_file", rec["acquisition_method"])
        self.assertIn("NOT", rec["warning"])
        self.assertEqual("candidate_bytes_collected_not_historically_approved", rec["status"])
        self.assertEqual("https://www.openwall.com/lists/oss-security/2024/01/31/6",
                         rec["declared_origin_url"])


if __name__ == "__main__":
    unittest.main()
