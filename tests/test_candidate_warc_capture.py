"""Adversarial offline CDX/WARC integrity tests; no real archive time assertions."""
import base64
import copy
from contextlib import redirect_stdout
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.verify_candidate_warc_capture import (
    CUTOFF, LIMIT_UNCOMPRESSED, VERSION, main, validate_capture
)

ROOT = Path(__file__).resolve().parents[1]
SOURCE = "candidate:kissadog-crowdstrike-20221026:unfrozen"
CHIMAERA = "candidate:chimaera-alienlabs-20210908:unfrozen"
SCARLETEEL = "candidate:scarleteel-sysdig-20230228:unfrozen"


def _b32(raw):
    return base64.b32encode(hashlib.sha1(raw, usedforsecurity=False).digest()).decode().rstrip("=")


def synthetic_capture(url, timestamp="20221026150000", *, body=None, code=200,
                      target=None, when=None, mime="text/html", block_digest=True,
                      warc_digest=True, http_mime="text/html"):
    body = body if body is not None else b"<!doctype html><html><body>Research fixture</body></html>"
    http = (f"HTTP/1.1 {code} OK\r\nContent-Type: {http_mime}\r\n\r\n".encode()
            + body)
    utc = datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    date = utc.strftime("%Y-%m-%dT%H:%M:%SZ") if when is None else when
    headers = [
        "WARC/1.0", "WARC-Type: response",
        "WARC-Record-ID: <urn:uuid:bbbbbbbb-0000-0000-0000-000000000000>",
        f"WARC-Target-URI: {url if target is None else target}",
        f"WARC-Date: {date}",
        "Content-Type: application/http; msgtype=response",
        f"Content-Length: {len(http)}",
    ]
    if warc_digest:
        headers.append("WARC-Payload-Digest: sha1:" + _b32(body))
    if block_digest:
        headers.append("WARC-Block-Digest: sha1:" + _b32(http))
    record = ("\r\n".join(headers) + "\r\n\r\n").encode() + http + b"\r\n\r\n"
    compressed = gzip.compress(record)
    index = {
        "url": url, "timestamp": timestamp, "status": "200", "mime": mime,
        "digest": _b32(body), "length": str(len(compressed)), "offset": "123456",
        "filename": (
            "crawl-data/CC-MAIN-2022-49/segments/1661234567890.12/warc/"
            "CC-MAIN-20221026120000-20221026180000-00000.warc.gz"
        ),
    }
    return index, compressed


class CandidateWarcIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.registry = json.loads(
            (ROOT / "datasets/manifests/pilot.json").read_text(encoding="utf-8")
        )

    def _fixture(self, sid=SOURCE, timestamp="20221026150000", **kwargs):
        rec = next(s for s in self.registry["sources"]
                   if s["source_version_id"] == sid)
        return synthetic_capture(rec["url"], timestamp, **kwargs)

    def test_all_three_real_registered_candidate_urls_are_compatible(self):
        for sid, stamp in (
            (SOURCE, "20221026150000"),
            (CHIMAERA, "20210909020000"),
            (SCARLETEEL, "20230228200000"),
        ):
            index, raw = self._fixture(sid, stamp)
            with self.subTest(source=sid):
                result = validate_capture(index, raw, self.registry, sid)
                self.assertEqual(VERSION, result["schema_version"])
                self.assertTrue(result["declared_observation_precedes_proposed_cutoff"])
                self.assertFalse(result["archive_timestamp_independently_authenticated"])
                self.assertFalse(result["capture_from_genuine_commoncrawl_origin_authenticated"])
                self.assertFalse(result["source_version_approved"])
                self.assertFalse(result["semantically_reviewed_feature_claims"])
                self.assertFalse(result["g1_evaluation_eligible"])
                self.assertFalse(result["research_ready"])
                self.assertEqual(CUTOFF, result["declared_cutoff_utc"])

    def test_payload_digest_is_verified_exactly(self):
        index, raw = self._fixture()
        index["digest"] = _b32(b"other body")
        with self.assertRaisesRegex(ValueError, "SHA-1"):
            validate_capture(index, raw, self.registry, SOURCE)

    def test_gzip_byte_tampering_fails(self):
        index, raw = self._fixture()
        for bad in (raw[:-1], raw[:-1] + bytes([raw[-1] ^ 1]), b"not gzip", raw + b"t"):
            edited = dict(index, length=str(len(bad)))
            with self.subTest(bad=bad[-3:]), self.assertRaises(ValueError):
                validate_capture(edited, bad, self.registry, SOURCE)

    def test_multiple_gzip_members_refused(self):
        index, raw = self._fixture()
        duplicate = raw + raw
        index["length"] = str(len(duplicate))
        with self.assertRaisesRegex(ValueError, "concatenated"):
            validate_capture(index, duplicate, self.registry, SOURCE)

    def test_decompression_bomb_refused_before_expansion(self):
        index, raw = self._fixture(body=b"<!doctype html><html>" + b"a" * (LIMIT_UNCOMPRESSED + 10))
        with self.assertRaisesRegex(ValueError, "decompression-bomb"):
            validate_capture(index, raw, self.registry, SOURCE)

    def test_bad_publication_time_and_future_capture_refused(self):
        index, raw = self._fixture(timestamp="20230410130000")
        with self.assertRaisesRegex(ValueError, "not earlier"):
            validate_capture(index, raw, self.registry, SOURCE)
        index["timestamp"] = "20220230010101"
        with self.assertRaisesRegex(ValueError, "calendar"):
            validate_capture(index, raw, self.registry, SOURCE)
        index["timestamp"] = "20221026150000"
        with self.assertRaisesRegex(ValueError, "UTC"):
            validate_capture(index, raw, self.registry, SOURCE, cutoff="2023-02-30T00:00:00Z")

    def test_capture_before_even_proposed_publication_day_refused(self):
        for sid, timestamp in (
            (SOURCE, "20221025170000"),
            (CHIMAERA, "20210907150000"),
            (SCARLETEEL, "20230227030000"),
        ):
            idx, raw = self._fixture(sid, timestamp)
            with self.subTest(source=sid), self.assertRaisesRegex(ValueError, "precedes"):
                validate_capture(idx, raw, self.registry, sid)

    def test_wrong_cdx_origin_or_archive_path_refused(self):
        idx, raw = self._fixture()
        for field, value in (
            ("url", "https://evil.example/blog/attack"),
            ("url", idx["url"] + "?preview=later"),
            ("url", idx["url"].replace("https", "javascript", 1)),
            ("filename", "../warc/fake.warc.gz"),
            ("filename", "crawl-data/CC-MAIN-2022-49/segments/../warc/fake.warc.gz"),
        ):
            temp = dict(idx, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate_capture(temp, raw, self.registry, SOURCE)

    def test_wrong_http_response_and_redirect_refused(self):
        for code in (301, 404, 500):
            idx, raw = self._fixture(code=code)
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, "status"):
                validate_capture(idx, raw, self.registry, SOURCE)

    def test_warc_target_must_bind_exact_cdx_url(self):
        idx, raw = self._fixture(target="https://example.com/fake")
        with self.assertRaisesRegex(ValueError, "WARC target"):
            validate_capture(idx, raw, self.registry, SOURCE)

    def test_warc_date_must_match_exact_cdx_timestamp(self):
        idx, raw = self._fixture(when="2022-10-27T15:00:00Z")
        with self.assertRaisesRegex(ValueError, "WARC-Date"):
            validate_capture(idx, raw, self.registry, SOURCE)

    def test_missing_warc_payload_sha1_or_wrong_block_digest_refused(self):
        idx, raw = self._fixture(warc_digest=False)
        with self.assertRaisesRegex(ValueError, "WARC payload digest"):
            validate_capture(idx, raw, self.registry, SOURCE)
        idx, raw = self._fixture(block_digest=False)
        self.assertFalse(validate_capture(idx, raw, self.registry, SOURCE)["research_ready"])

    def test_non_html_and_bogus_cdx_status_refused(self):
        idx, raw = self._fixture(mime="application/pdf")
        with self.assertRaisesRegex(ValueError, "content type"):
            validate_capture(idx, raw, self.registry, SOURCE)
        idx, raw = self._fixture(http_mime="text/plain")
        with self.assertRaisesRegex(ValueError, "must contain HTML"):
            validate_capture(idx, raw, self.registry, SOURCE)
        idx, raw = self._fixture()
        idx["status"] = "302"
        with self.assertRaisesRegex(ValueError, "Only original"):
            validate_capture(idx, raw, self.registry, SOURCE)

    def test_range_length_and_offset_traversal_fail(self):
        idx, raw = self._fixture()
        for field, value in (
            ("length", "-2"), ("length", str(len(raw) + 5)),
            ("length", "0"), ("offset", "-1"), ("offset", "00123"),
            ("offset", "999999999999999999999"),
        ):
            temp = dict(idx, **{field: value})
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                validate_capture(temp, raw, self.registry, SOURCE)

    def test_no_unapproved_source_can_fake_approval_metadata(self):
        index, raw = self._fixture()
        for key, value in (
            ("sha256", "a" * 64), ("available_at", "2022-10-26T00:00:00Z"),
            ("status", "approved"), ("date_confidence", "verified"),
            ("redistribution", "allowed"),
        ):
            registry = copy.deepcopy(self.registry)
            rec = next(r for r in registry["sources"] if r["source_version_id"] == SOURCE)
            rec[key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "unapproved"):
                validate_capture(index, raw, registry, SOURCE)

    def test_later_and_unknown_source_cannot_be_intake_target(self):
        index, raw = self._fixture()
        for version in ("candidate:scarleteel-sysdig-20230711:unfrozen", "fake:version"):
            with self.subTest(source=version), self.assertRaisesRegex(ValueError, "predeclared"):
                validate_capture(index, raw, self.registry, version)

    def test_cli_synthetic_case_receipt_and_duplicate_key_refusal(self):
        idx, raw = self._fixture()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            metadata = root / "index.json"
            member = root / "member.gz"
            metadata.write_text(json.dumps(idx), encoding="utf-8")
            member.write_bytes(raw)
            args = ["--index-record", str(metadata), "--warc-member", str(member),
                    "--source-version-id", SOURCE,
                    "--manifest", str(ROOT / "datasets/manifests/pilot.json")]
            result = io.StringIO()
            with redirect_stdout(result):
                self.assertEqual(0, main(args))
            receipt = json.loads(result.getvalue())
            self.assertEqual(VERSION, receipt["schema_version"])
            self.assertFalse(receipt["source_version_approved"])
            metadata.write_text('{"url":"x","url":"y"}', encoding="utf-8")
            with redirect_stdout(io.StringIO()) as result2:
                self.assertEqual(2, main(args))
            self.assertEqual("candidate_warc_refused",
                             json.loads(result2.getvalue())["status"])

    def test_cli_refuses_symlink_to_warc(self):
        idx, raw = self._fixture()
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            meta, member, link = root / "m.json", root / "body.gz", root / "alias.gz"
            meta.write_text(json.dumps(idx), encoding="utf-8")
            member.write_bytes(raw)
            try:
                link.symlink_to(member)
            except (OSError, NotImplementedError):
                return
            with redirect_stdout(io.StringIO()):
                self.assertEqual(2, main([
                    "--index-record", str(meta), "--warc-member", str(link),
                    "--source-version-id", SOURCE,
                    "--manifest", str(ROOT / "datasets/manifests/pilot.json")
                ]))


if __name__ == "__main__":
    unittest.main()
