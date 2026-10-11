"""Synthetic integrity tests for pinned third-party bibliography pointers.

Synthetic Git blobs in tests are not real historical source approvals.
The CI network witness tests the two actual GitHub-hosted pinned blobs.
"""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts.verify_historical_chimaera_bibliography import (
    ORIGINAL_URL, RECEIPT_SCHEMA, WITNESSES, _git_blob_sha1,
    main, validate_witness,
)


class HistoricalChimaeraBibliographyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = (
            'A historical 2021-09-08 citation: '
            'TeamTNT with new campaign aka "Chimaera" (2021-09-08) '
            + ORIGINAL_URL + "\n"
        ).encode("utf-8")
        self.spec = {
            "repository": "synthetic/test",
            "commit": "f" * 40,
            "path": "README.md",
            "git_blob_sha1": _git_blob_sha1(self.fixture),
            "declared_commit_time": "2021-12-19T00:00:00Z",
            "citation_marker": 'TeamTNT with new campaign aka "Chimaera" (2021-09-08)',
        }
        self.patched = patch.dict(WITNESSES, {"synthetic": self.spec})
        self.patched.start()

    def tearDown(self):
        self.patched.stop()

    def test_fixture_receipt_is_hash_only_and_never_authorizes_source(self):
        result = validate_witness(self.fixture, "synthetic")
        self.assertEqual(RECEIPT_SCHEMA, result["schema_version"])
        self.assertEqual("synthetic", result["witness"])
        self.assertEqual(hashlib.sha256(self.fixture).hexdigest(), result["sha256"])
        self.assertEqual(_git_blob_sha1(self.fixture), result["git_blob_sha1"])
        self.assertTrue(result["original_2021_citation_present"])
        for field in (
            "original_publisher_article_bytes_verified",
            "original_publisher_article_available_at_verified",
            "git_commit_public_push_time_independently_witnessed",
            "source_rights_approved",
            "historical_source_version_approved",
            "same_peer_independent_claim_groups_verified",
            "g1_evaluation_eligible", "research_ready",
        ):
            self.assertFalse(result[field])
        self.assertNotIn("historical 2021-09-08 citation:", json.dumps(result))

    def test_pin_binds_complete_file_not_merely_citation_snippet(self):
        for altered in (
            self.fixture + b" ", self.fixture[:-1], self.fixture.replace(b"2021", b"2022"),
            self.fixture.replace(b"Chimaera", b"SCARLETEEL"),
            self.fixture.replace(b"cybersecurity.att.com", b"evil.example.com"),
        ):
            with self.subTest(data=altered[-18:]), self.assertRaisesRegex(ValueError, "differ"):
                validate_witness(altered, "synthetic")

    def test_correct_blob_without_original_publisher_link_refused(self):
        changed = self.fixture.replace(ORIGINAL_URL.encode(), b"https://example.org")
        spec = copy.deepcopy(self.spec)
        spec["git_blob_sha1"] = _git_blob_sha1(changed)
        with patch.dict(WITNESSES, {"synthetic": spec}):
            with self.assertRaisesRegex(ValueError, "lacks exact"):
                validate_witness(changed, "synthetic")

    def test_correct_blob_without_exact_2021_article_title_refused(self):
        changed = self.fixture.replace(b' "Chimaera" ', b' "Other" ')
        spec = copy.deepcopy(self.spec)
        spec["git_blob_sha1"] = _git_blob_sha1(changed)
        with patch.dict(WITNESSES, {"synthetic": spec}):
            with self.assertRaisesRegex(ValueError, "lacks exact"):
                validate_witness(changed, "synthetic")

    def test_no_ambiguous_unknown_witness_or_fake_sha(self):
        with self.assertRaisesRegex(ValueError, "Unknown"):
            validate_witness(self.fixture, "not-a-witness")
        fake = copy.deepcopy(self.spec)
        fake["git_blob_sha1"] = "z" * 40
        with patch.dict(WITNESSES, {"synthetic": fake}):
            with self.assertRaisesRegex(ValueError, "Malformed"):
                validate_witness(self.fixture, "synthetic")

    def test_strict_byte_input_cap_and_type(self):
        for content in (b"", b"x" * (600 * 1024 + 1), "literal str"):
            with self.subTest(size=len(content)), self.assertRaises(ValueError):
                validate_witness(content, "synthetic")

    def test_invalid_utf8_fails_after_correct_pin(self):
        bad = self.fixture + b"\xff"
        spec = copy.deepcopy(self.spec)
        spec["git_blob_sha1"] = _git_blob_sha1(bad)
        with patch.dict(WITNESSES, {"synthetic": spec}):
            with self.assertRaisesRegex(ValueError, "not UTF-8"):
                validate_witness(bad, "synthetic")

    def test_cli_returns_safe_receipt_and_rejects_tampered_file(self):
        with TemporaryDirectory() as tmp:
            file = Path(tmp) / "bib.md"
            file.write_bytes(self.fixture)
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(0, main(["--witness", "synthetic",
                                          "--raw-file", str(file)]))
            self.assertFalse(json.loads(out.getvalue())["research_ready"])
            file.write_bytes(self.fixture + b"tamper")
            with redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(2, main(["--witness", "synthetic",
                                          "--raw-file", str(file)]))
            self.assertEqual("historical_bibliography_refused",
                             json.loads(stdout.getvalue())["status"])

    def test_cli_symlink_rejected_if_os_allows(self):
        with TemporaryDirectory() as tmp:
            file = Path(tmp) / "actual.md"
            link = Path(tmp) / "link.md"
            file.write_bytes(self.fixture)
            try:
                link.symlink_to(file)
            except (OSError, NotImplementedError):
                return
            with redirect_stdout(io.StringIO()):
                self.assertEqual(2, main(["--witness", "synthetic",
                                          "--raw-file", str(link)]))

    def test_exact_real_witness_catalog_constants_not_mutated(self):
        self.assertEqual({
            "cloud-native-reference-dec2021", "mitre-reference-may2022",
            "synthetic",
        }, set(WITNESSES))
        self.assertEqual("2021-12-19T10:35:48Z",
                         WITNESSES["cloud-native-reference-dec2021"]["declared_commit_time"])
        self.assertEqual("2022-05-05T14:44:52Z",
                         WITNESSES["mitre-reference-may2022"]["declared_commit_time"])
        for name in ("cloud-native-reference-dec2021", "mitre-reference-may2022"):
            self.assertEqual(40, len(WITNESSES[name]["git_blob_sha1"]))


if __name__ == "__main__":
    unittest.main()
