"""Synthetic offline tests: direct-CDXJ is source metadata, not primary report approval."""
import gzip
import json
import unittest

from scripts import probe_direct_original_cdxj as module
from scripts.probe_original_campaign_cdx import TARGETS


def _row(url, stamp="20230206120544"):
    return {
        "url": url, "timestamp": stamp, "status": "200", "mime": "text/html",
        "filename": (
            "crawl-data/CC-MAIN-2023-06/segments/1674764500339.37/warc/"
            "CC-MAIN-20230206113934-20230206143934-00755.warc.gz"
        ), "offset": "696857860", "length": "22387",
        "digest": "IIQQZYE7EHNZFM6CFTJLNT226VHY2D3P",
    }


def _cdx_line(url, stamp="20230206120544"):
    return (
        module._url_key(url) + " " + stamp + " " +
        json.dumps(_row(url, stamp), sort_keys=True) + "\n"
    ).encode("utf-8")


class _FakeOriginalArchive:
    def __init__(self):
        self.collection = "CC-MAIN-2023-06"
        self.files = {}
        self.rebuild()

    def rebuild(self):
        urls = [TARGETS["cado-original-2022"][0],
                TARGETS["crowdstrike-original-2022"][0]]
        entries = []
        for i, url in enumerate(urls):
            name = "cdx-00000.gz"
            raw = gzip.compress(_cdx_line(url), mtime=0)
            offset = sum(len(self.files.get(name, b"")) for _ in [0])
            # Keep two separate independently indexed compressed gzip members.
            self.files[name] = self.files.get(name, b"") + raw
            entries.append(
                module._url_key(url) + " 20230206120544\t" + name + "\t" +
                str(offset) + "\t" + str(len(raw)) + "\t" + str(i+1) + "\n"
            )
        self.files["cluster.idx"] = "".join(entries).encode("ascii")

    def reader(self):
        def obj(url):
            return url.rsplit("/", 1)[-1]
        return module._RangeReader(
            get_size=lambda u: len(self.files[obj(u)]),
            get_range=lambda u, start, size: self.files[obj(u)][start:start+size],
        )


class OriginalIndexDirectLookupTests(unittest.TestCase):
    def setUp(self):
        self.data = _FakeOriginalArchive()

    def test_real_source_roles_with_synthetic_index_no_approval(self):
        receipt = module.probe_direct(
            ["cado-original-2022", "crowdstrike-original-2022"],
            ["CC-MAIN-2023-06"], reader=self.data.reader()
        )
        self.assertEqual(2, receipt["matching_pre_cutoff_candidate_count"])
        self.assertEqual(2, len(receipt["candidate_metadata_rows"]))
        self.assertEqual(4, len(receipt["query_receipts"]))
        self.assertFalse(receipt["archive_article_bytes_acquired"])
        self.assertFalse(receipt["research_ready"])
        self.assertFalse(receipt["source_version_approved"])
        for row in receipt["candidate_metadata_rows"]:
            self.assertFalse(row["research_ready"])
            self.assertFalse(row["source_version_approved"])
            self.assertTrue(row["cdxj_direct_index_original_bytes_verified"])

    def test_source_url_surt_normalizes_www_but_not_other_domains(self):
        self.assertEqual(
            "com,crowdstrike)/blog/new-kiss-a-dog",
            module._url_key("https://www.crowdstrike.com/blog/new-kiss-a-dog"),
        )
        with self.assertRaises(ValueError):
            module._url_key("http://evil.example.com/report")
        with self.assertRaises(ValueError):
            module._url_key("https://example.com/report?inject=1")

    def test_cdxj_does_not_accept_same_domain_wrong_page(self):
        url = TARGETS["cado-original-2022"][0]
        other = url.replace("kiss-a-dog-discovered", "unrelated")
        candidate = gzip.compress(_cdx_line(other), mtime=0)
        self.assertEqual(
            [], module._parse_cdxj(candidate, "cado-original-2022",
                                  url, "CC-MAIN-2023-06")
        )

    def test_non_200_and_after_cutoff_are_not_candidates(self):
        url = TARGETS["cado-original-2022"][0]
        after = _cdx_line(url, "20230302000000")
        result = module._parse_cdxj(
            gzip.compress(after, mtime=0), "cado-original-2022",
            url, "CC-MAIN-2023-06"
        )
        self.assertEqual(1, len(result))
        self.assertEqual("post_cutoff_archive_record_ineligible",
                         result[0]["candidate_status"])

    def test_cluster_idx_rejects_invalid_shards_and_oversize_ranges(self):
        for bad in (
            b"com,cado)/ 20230101\t../evil.gz\t0\t100\t1\n",
            b"com,cado)/ 20230101\tcdx-00000.gz\t0\t999999999\t1\n",
            b"com,cado)/ 20230101\tcdx-00000.gz\t-1\t20\t1\n",
            b"com,cado)/ 20230101\tcdx-00000.gz\t0\t0\t1\n",
        ):
            with self.subTest(bad=bad[:40]), self.assertRaises(ValueError):
                module._cluster_rows(bad, start_offset=0, total=1000)

    def test_duplicate_or_unsorted_cluster_keys_fail_closed(self):
        lines = (
            b"com,z)/ 20230101000000\tcdx-00000.gz\t0\t100\t1\n"
            b"com,a)/ 20230101000000\tcdx-00000.gz\t100\t100\t2\n"
        )
        with self.assertRaisesRegex(ValueError, "unsorted"):
            module._cluster_rows(lines, start_offset=0, total=1000)

    def test_corrupt_compressed_source_index_does_not_supply_evidence(self):
        url = TARGETS["cado-original-2022"][0]
        with self.assertRaises(ValueError):
            module._parse_cdxj(b"not-gzip", "cado-original-2022",
                               url, "CC-MAIN-2023-06")

    def test_reject_out_of_scope_crawl_and_role(self):
        for target, crawl in (
            (["evil-source"], ["CC-MAIN-2023-06"]),
            (["crowdstrike-original-2022"], ["CC-MAIN-2026-39"]),
            ([], ["CC-MAIN-2023-06"]),
        ):
            with self.subTest(target=target, crawl=crawl), self.assertRaises(ValueError):
                module.probe_direct(target, crawl, reader=self.data.reader())

    def test_absence_in_one_crawl_only_is_not_global_absence(self):
        original = TARGETS["crowdstrike-original-2022"][0]
        result = module._parse_cdxj(
            gzip.compress(_cdx_line(original), mtime=0),
            "crowdstrike-original-2022",
            TARGETS["crowdstrike-original-2022"][1],
            "CC-MAIN-2023-06"
        )
        self.assertEqual([], result)

    def test_reproducible_compressed_index_receipts_never_emit_article_text(self):
        receipt = module.probe_direct(["cado-original-2022"], ["CC-MAIN-2023-06"],
                                      reader=self.data.reader())
        text = json.dumps(receipt)
        self.assertNotIn('"article_body": {', text)
        self.assertNotIn("XHide was", text)
        self.assertFalse(receipt["independent_researcher_claims_reviewed"])


if __name__ == "__main__":
    unittest.main()
