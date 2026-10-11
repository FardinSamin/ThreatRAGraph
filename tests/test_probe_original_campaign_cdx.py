"""Synthetic-only tests for bounded official-CDX historical article discovery."""
from contextlib import redirect_stdout
import io
import json
import unittest
from urllib.error import HTTPError

from scripts.probe_original_campaign_cdx import (
    COLLECTIONS, TARGETS, VERSION, _parse_response_bytes,
    classify_row, main, probe,
)


def _index_row(url, timestamp="20230112010000", **edits):
    row = {
        "url": url, "timestamp": timestamp, "status": "200", "mime": "text/html",
        "filename": (
            "crawl-data/CC-MAIN-2023-06/segments/123.4/warc/"
            "CC-MAIN-20230101010000-00001.warc.gz"
        ), "offset": "1122", "length": "3344", "digest": "Z" * 32,
    }
    row.update(edits)
    return row


class HistoricalOriginalReportCDXProbeTests(unittest.TestCase):
    def test_exhaustive_real_publisher_url_lookups_do_not_approve(self):
        calls = []
        def network(url):
            calls.append(url)
            return b""
        result = probe(client=network)
        self.assertEqual(len(calls), result["query_count"])
        self.assertEqual(sum(len(TARGETS[k]) for k in TARGETS) * len(COLLECTIONS), len(calls))
        self.assertEqual(0, result["candidate_record_count"])
        self.assertFalse(result["source_version_approved"])
        self.assertFalse(result["original_article_body_recovered"])
        self.assertFalse(result["g1_evaluation_eligible"])
        self.assertFalse(result["research_ready"])
        for url in calls:
            self.assertTrue(url.startswith("https://index.commoncrawl.org/"))
            self.assertNotIn("web.archive.org", url)

    def test_original_early_2023_cado_crowdstrike_page_url_is_not_syndication(self):
        source = "cado-original-2022"
        row = _index_row(TARGETS[source][0])
        d = classify_row(row, target=source, requested_url=row["url"], collection=COLLECTIONS[1])
        self.assertEqual("prospective_pre_cutoff_html_record_not_yet_warc_verified",
                         d["candidate_status"])
        self.assertEqual("original_investigator_url_candidate", d["role"])
        self.assertFalse(d["original_article_body_recovered"])

    def test_authorized_republication_is_not_a_third_independent_investigator(self):
        source = "crowdstrike-csa-republication-2022"
        row = _index_row(TARGETS[source][0])
        d = classify_row(row, target=source, requested_url=row["url"], collection=COLLECTIONS[1])
        self.assertEqual("publisher_authorized_republication_not_independent_investigation",
                         d["role"])

    def test_early_sysdig_before_release_not_eligible(self):
        name = "sysdig-early-2023"
        u = TARGETS[name][0]
        result = classify_row(_index_row(u, "20230227230000"), target=name,
                              requested_url=u, collection=COLLECTIONS[1])
        self.assertEqual("before_even_claimed_original_publication_calendar_day",
                         result["candidate_status"])
        result = classify_row(_index_row(u, "20230228230000"), target=name,
                              requested_url=u, collection=COLLECTIONS[1])
        self.assertEqual("prospective_pre_cutoff_html_record_not_yet_warc_verified",
                         result["candidate_status"])

    def test_march_capture_is_not_pre_cutoff_even_for_2022_article(self):
        name = "cado-original-2022"
        u = TARGETS[name][0]
        d = classify_row(_index_row(u, "20230301000000"), target=name,
                         requested_url=u, collection=COLLECTIONS[1])
        self.assertEqual("post_cutoff_archive_record_ineligible", d["candidate_status"])

    def test_malformed_cdx_timestamp_is_rejected(self):
        name = "cado-original-2022"
        u = TARGETS[name][0]
        for stamp in ("20230230030000", "2023-01-01T00:00:00Z", "202301010000", "abc"):
            with self.subTest(stamp=stamp), self.assertRaises(ValueError):
                classify_row(_index_row(u, stamp), target=name,
                             requested_url=u, collection=COLLECTIONS[1])

    def test_wrong_publisher_alias_or_unknown_collection_refused(self):
        name = "cado-original-2022"
        u = TARGETS[name][0]
        for target, url, coll in (
            (name, "https://evil.example.com/report", COLLECTIONS[1]),
            (name, u, "CC-MAIN-2026-39"),
            ("other-report", u, COLLECTIONS[1]),
        ):
            with self.subTest(target=target, url=url, coll=coll), self.assertRaises(ValueError):
                classify_row(_index_row(u), target=target, requested_url=url, collection=coll)

    def test_html_only_and_exact_200(self):
        name = "cado-original-2022"
        u = TARGETS[name][0]
        for field, value in (("mime", "application/pdf"), ("status", "301")):
            result = classify_row(_index_row(u, **{field: value}),
                                  target=name, requested_url=u, collection=COLLECTIONS[1])
            self.assertEqual("non_original_200_html_record", result["candidate_status"])

    def test_missing_warc_byte_range_never_becomes_eligible(self):
        name = "cado-original-2022"
        u = TARGETS[name][0]
        d = classify_row(_index_row(u, filename=None), target=name,
                         requested_url=u, collection=COLLECTIONS[1])
        self.assertEqual("missing_required_warc_locator_or_digest", d["candidate_status"])

    def test_duplicate_json_fields_and_malformed_response_fail(self):
        for data in (
            b'{"url":"first","url":"second"}',
            b'{invalid-json}',
            b'["not a CDX object"]',
            b'x' * (128 * 1024 + 1),
        ):
            with self.subTest(size=len(data)), self.assertRaises(ValueError):
                _parse_response_bytes(data)

    def test_candidate_response_witness_does_not_recover_article(self):
        name = "crowdstrike-original-2022"
        url = TARGETS[name][0]
        sample = (json.dumps(_index_row(url, timestamp="20221205000000")) + "\n").encode()
        result = probe(targets=[name], collections=[COLLECTIONS[0]],
                       client=lambda _: sample)
        self.assertEqual(1, result["candidate_record_count"])
        self.assertEqual(VERSION, result["schema_version"])
        self.assertFalse(result["original_article_body_recovered"])
        self.assertFalse(result["source_version_approved"])
        self.assertTrue(result["candidate_archive_records_are_untrusted_until_warc_and_time_review"])

    def test_404_not_confused_with_network_unavailable_or_absence_proof(self):
        def not_found(url):
            raise HTTPError(url, 404, "Not found", {}, None)
        result = probe(targets=["cado-original-2022"], collections=[COLLECTIONS[1]],
                       client=not_found)
        self.assertEqual(2, result["query_count"])
        self.assertEqual(0, result["candidate_record_count"])
        self.assertTrue(all(q["query_status"] == "index_record_absent_http_404"
                            for q in result["query_receipts"]))

    def test_network_unavailability_distinguished(self):
        def fail(url):
            raise OSError("Connection blocked")
        result = probe(targets=["sysdig-early-2023"], collections=[COLLECTIONS[1]], client=fail)
        self.assertEqual("index_transport_unavailable", result["query_receipts"][0]["query_status"])

    def test_reject_unregistered_scope_and_duplicate_rows(self):
        with self.assertRaises(ValueError):
            probe(targets=["unknown"], client=lambda _: b"")
        with self.assertRaises(ValueError):
            probe(collections=["CC-MAIN-2025-21"], client=lambda _: b"")
        name = "sysdig-early-2023"
        url = TARGETS[name][0]
        line = json.dumps(_index_row(url)).encode() + b"\n"
        with self.assertRaisesRegex(ValueError, "numerous"):
            _parse_response_bytes(line * 9)

    def test_cli_real_network_not_needed_for_offline_syntax_smoke(self):
        with redirect_stdout(io.StringIO()) as o:
            self.assertEqual(2, main(["--targets", "nonexistent"]))
        self.assertEqual("", o.getvalue())


if __name__ == "__main__":
    unittest.main()
