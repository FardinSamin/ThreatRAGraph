"""Synthetic range-header and original CDX locator pin tests."""
import copy
import json
from pathlib import Path
import unittest

from scripts.replay_original_cado_20230206 import (
    _fixed, FIRST_OBSERVED_LENGTH, FIRST_OBSERVED_OFFSET,
    FIRST_OBSERVED_WARC, verify_range_headers, verify_original_cado_html_identity,
)

ROOT = Path(__file__).resolve().parents[1]
META = ROOT / "datasets/provenance_pointers/cado_kissadog_20230206_ccmain202306.json"


class OriginalCadoIndexedWarcTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = json.loads(META.read_text(encoding="utf-8"))

    def test_real_observed_cdx_row_locator_is_exactly_pinned_not_approved(self):
        result = _fixed(self.source)
        self.assertEqual(FIRST_OBSERVED_WARC, result["filename"])
        self.assertEqual(FIRST_OBSERVED_OFFSET, result["offset"])
        self.assertEqual(FIRST_OBSERVED_LENGTH, result["length"])
        self.assertFalse(self.source["research_ready"])
        self.assertFalse(self.source["source_version_approved"])
        self.assertFalse(self.source["archive_time_independently_authenticated"])

    def test_reject_any_forced_promotion_or_mutated_real_index_metadata(self):
        for key, modified in (
            ("source_version_id", "fake:source"),
            ("timestamp", "20230207230544"),
            ("filename", "crawl-data/other.warc.gz"),
            ("offset", "0"), ("length", "999"),
            ("url", "https://evil.example/report"),
            ("digest", "A" * 32),
            ("status", "301"), ("mime", "application/pdf"),
            ("source_version_approved", True),
            ("publisher_article_rights_approved", True),
            ("archive_time_independently_authenticated", True),
            ("research_ready", True),
        ):
            obj = copy.deepcopy(self.source)
            obj[key] = modified
            with self.subTest(field=key), self.assertRaises(ValueError):
                _fixed(obj)

    def test_accept_exact_206_warc_byte_range_only(self):
        raw = (b"HTTP/2 206\r\ncontent-range: bytes 696857860-696880246/999999999\r\n"
               b"content-length: 22387\r\ncontent-type: application/octet-stream\r\n\r\n")
        verify_range_headers(raw)
        proxy = b"HTTP/1.1 200 Connection established\r\n\r\n" + raw
        verify_range_headers(proxy)

    def test_wrong_http_status_offset_length_and_encoding_fail(self):
        rows = [
            b"HTTP/2 200\r\ncontent-range: bytes 696857860-696880246/999\r\n\r\n",
            b"HTTP/2 206\r\ncontent-range: bytes 0-22386/999\r\n\r\n",
            b"HTTP/2 206\r\ncontent-range: bytes 696857860-696880245/999\r\n\r\n",
            b"HTTP/2 206\r\ncontent-range: bytes 696857860-696880246/999\r\ncontent-length: 123\r\n\r\n",
            b"HTTP/2 206\r\ncontent-range: bytes 696857860-696880246/999\r\ncontent-encoding: gzip\r\n\r\n",
        ]
        for bad in rows:
            with self.subTest(headers=bad[:50]), self.assertRaises(ValueError):
                verify_range_headers(bad)

    def test_html_identity_screen_excludes_script_only_injections(self):
        real = (b"<html><head><title>Kiss-a-Dog Discovered Utilizing a "
                b"20-Year-Old Process Hider</title></head><body>"
                b"<article><h1>Kiss-a-Dog and its process hider</h1>"
                b"Our Redis honeypot found XMRig and XHide.</article></body></html>")
        result = verify_original_cado_html_identity(real)
        self.assertTrue(all(result.values()))
        malicious = (b"<html><head><title>Unrelated admin page</title></head>"
                     b"<body><script>Kiss-a-Dog XHide XMRig Redis process hider</script>"
                     b"<p>Nothing to see here</p></body></html>")
        with self.assertRaisesRegex(ValueError, "not the expected original"):
            verify_original_cado_html_identity(malicious)

    def test_html_word_presence_cannot_be_forged_just_by_title(self):
        html = (b"<html><title>Kiss-a-Dog Process Hider</title>"
                b"<body>general update without campaign details</body></html>")
        with self.assertRaises(ValueError):
            verify_original_cado_html_identity(html)

    def test_duplicate_headers_and_oversized_header_fail(self):
        with self.assertRaisesRegex(ValueError, "Duplicated"):
            verify_range_headers(
                b"HTTP/2 206\r\ncontent-range: bytes 696857860-696880246/999\r\n"
                b"Content-Range: bytes 696857860-696880246/999\r\n\r\n"
            )
        with self.assertRaises(ValueError):
            verify_range_headers(b"x" * 40000)


if __name__ == "__main__":
    unittest.main()
