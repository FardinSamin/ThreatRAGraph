"""Verify a REAL 2023-02-06 Common Crawl range for Cado's original report.

Do not print article text or archive it in Git. Successful replay authenticates
captured response bytes and internal CDX/WARC consistency, not first-public
publisher time, permissions, independent scientific review or G1 eligibility.
"""
from __future__ import annotations

import argparse
import hashlib
from html.parser import HTMLParser
import json
import re

from scripts.verify_candidate_warc_capture import (
    CADO_ID, CADO_HISTORIC_URL, _read_file, _read_json, validate_capture,
    LIMIT_COMPRESSED, LIMIT_MANIFEST, _decode_member, _headers,
)

INDEX_PATH = "datasets/provenance_pointers/cado_kissadog_20230206_ccmain202306.json"
FIRST_OBSERVED_COLLECTION = "CC-MAIN-2023-06"
FIRST_OBSERVED_UTC = "20230206120544"
FIRST_OBSERVED_WARC = (
    "crawl-data/CC-MAIN-2023-06/segments/1674764500339.37/warc/"
    "CC-MAIN-20230206113934-20230206143934-00755.warc.gz"
)
FIRST_OBSERVED_OFFSET = "696857860"
FIRST_OBSERVED_LENGTH = "22387"
FIRST_OBSERVED_CDX_PAYLOAD_SHA1_B32 = "IIQQZYE7EHNZFM6CFTJLNT226VHY2D3P"
# These exact original-byte digests were measured from the real Common Crawl
# WARC replay in GitHub Actions run 38110956406 (not synthetic input).
EXPECTED_WARC_MEMBER_SHA256 = "".join((
    "0e2cdbd6", "b1c58f8a", "e6737c15", "70d00003",
    "46d660d4", "c7047d89", "692d1854", "3755478d",
))
EXPECTED_ORIGINAL_HTML_SHA256 = "".join((
    "b3482293", "f74524ef", "a323ffcf", "18e13819",
    "2b2137f6", "ceda143d", "dc89e130", "2c88ef83",
))
EXPECTED_ORIGINAL_HTML_BYTE_COUNT = 92875
# These original first-party HTML block fingerprints were measured in real
# GitHub Actions run 38111634755. Hashes refer to normalized p/li/h2-h4
# text blocks, *not* editor-approved security relations or legal use rights.
EXPECTED_REVIEW_BLOCK_COUNT = 107
EXPECTED_MATCHED_REVIEW_BLOCK_COUNT = 15
EXPECTED_UNREVIEWED_ORIGINAL_BLOCKS = {
    52: ("xmrig", "".join((
        "9f0062acb7d7eae0", "1ba18b57f2b40e5b",
        "e810f4eefd7aed81", "64174ccf0d6144f2",
    ))),
    59: ("xmrig,xhide", "".join((
        "6c45096683853ea3", "1b4a2c486f79bc76",
        "98e16aa909e49780", "da1eb0565595c9d1",
    ))),
}


def _require(value: bool, message: str):
    if not value:
        raise ValueError(message)


def _fixed(index: dict) -> dict:
    _require(isinstance(index, dict), "Fixed original CDX metadata object required")
    for key, expected in (
        ("source_version_id", CADO_ID),
        ("original_commoncrawl_collection", FIRST_OBSERVED_COLLECTION),
        ("url", CADO_HISTORIC_URL),
        ("timestamp", FIRST_OBSERVED_UTC),
        ("filename", FIRST_OBSERVED_WARC),
        ("offset", FIRST_OBSERVED_OFFSET),
        ("length", FIRST_OBSERVED_LENGTH),
        ("status", "200"),
        ("mime", "text/html"),
        ("digest", FIRST_OBSERVED_CDX_PAYLOAD_SHA1_B32),
        ("provenance_status",
         "official_cdx_index_fields_observed_via_github_actions_not_yet_archived_html_verified"),
        ("source_version_approved", False),
        ("publisher_article_rights_approved", False),
        ("archive_time_independently_authenticated", False),
        ("research_ready", False),
    ):
        _require(index.get(key) == expected and type(index.get(key)) == type(expected),
                 "Fixed real CDX observed locator differs: " + key)
    _require(index.get("original_index_query_run_id") == 38110672261,
             "Historical CDX index evidence run missing")
    return {k: index[k] for k in (
        "url", "timestamp", "filename", "offset", "length", "status", "mime", "digest"
    )}


def verify_range_headers(raw: bytes) -> None:
    if not isinstance(raw, bytes) or len(raw) > 32768:
        raise ValueError("Invalid bounded HTTP headers")
    try:
        headers = raw.decode("iso-8859-1")
    except UnicodeError as exc:
        raise ValueError("Invalid HTTP response header encoding") from exc
    # Multiple response blocks can reflect proxy CONNECT; validate the *last*
    # definitive response, and do not treat earlier 200/302 as a range success.
    blocks = [x for x in re.split(r"\r?\n\r?\n", headers) if x.strip()]
    _require(bool(blocks), "Missing HTTP response headers")
    response = blocks[-1].splitlines()
    _require(bool(response) and re.match(r"^HTTP/[0-9.]+ 206(?:\s|$)", response[0]) is not None,
             "Official archive range retrieval must be HTTP 206 Partial Content")
    fields = {}
    for line in response[1:]:
        _require(":" in line, "Malformed HTTP response field")
        key, value = line.split(":", 1)
        k = key.strip().lower()
        _require(k not in fields, "Duplicated HTTP response field")
        fields[k] = value.strip()
    expected = f"bytes {FIRST_OBSERVED_OFFSET}-{int(FIRST_OBSERVED_OFFSET) + int(FIRST_OBSERVED_LENGTH) - 1}/"
    _require(fields.get("content-range", "").startswith(expected)
             and fields["content-range"][len(expected):].isdigit(),
             "Content-Range does not match the exact pinned original CDX span")
    _require(fields.get("content-length") in (None, FIRST_OBSERVED_LENGTH),
             "HTTP range response declares the wrong length")
    _require(fields.get("content-encoding", "identity").lower() in ("identity", ""),
             "Unexpected compressed transfer representation")


class _ArticleTextOnly(HTMLParser):
    """Never load scripts/resources; inspect bounded literal HTML text only."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.suppressed = []
        self.title_depth = 0
        self.heading_depth = 0
        self.text = []
        self.headings = []

    def handle_starttag(self, tag, attrs):
        if tag in {"script", "style", "noscript", "svg"}:
            self.suppressed.append(tag)
        if not self.suppressed:
            if tag == "title":
                self.title_depth += 1
            elif tag == "h1":
                self.heading_depth += 1

    def handle_endtag(self, tag):
        if self.suppressed:
            if tag == self.suppressed[-1]:
                self.suppressed.pop()
            return
        if tag == "title" and self.title_depth:
            self.title_depth -= 1
        if tag == "h1" and self.heading_depth:
            self.heading_depth -= 1

    def handle_data(self, data):
        if self.suppressed:
            return
        self.text.append(data)
        if self.heading_depth or self.title_depth:
            self.headings.append(data)


def verify_original_cado_html_identity(original_html: bytes) -> dict:
    _require(isinstance(original_html, bytes) and 0 < len(original_html) <= 4 * 1024 * 1024,
             "Historical original Cado HTML is missing or unbounded")
    parser = _ArticleTextOnly()
    try:
        parser.feed(original_html.decode("utf-8", errors="replace"))
        parser.close()
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise ValueError("Historical HTML cannot be screened safely") from exc
    titles = " ".join(parser.headings).casefold()
    rendered = " ".join(parser.text).casefold()
    title_ok = "kiss-a-dog" in titles and "process hider" in titles
    # These are mere visible-word presence screens, NOT independent human
    # confirmation of what any reported code/variant does.
    token_presence = {
        "kiss_a_dog_report_title": title_ok,
        "redis": "redis" in rendered,
        "xmrig": "xmrig" in rendered,
        "xhide": "xhide" in rendered,
    }
    _require(all(token_presence.values()),
             "Archived response is not the expected original Cado Kiss-a-dog/XHide research HTML")
    return token_presence


class _TextBlockFingerprints(HTMLParser):
    """Deterministic inert original-HTML block locators; never export report text.

    Paragraph, list item and visible heading content is normalized solely to
    calculate SHA-256 fingerprints, not to assert the source's graph semantics.
    """

    BLOCKS = {"p", "li", "h2", "h3", "h4"}
    SUPPRESSED = {"script", "style", "noscript", "svg", "template"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hidden = []
        self.active = []
        self.blocks = []
        self.line = 0

    def handle_starttag(self, tag, attrs):
        if tag in self.SUPPRESSED:
            self.hidden.append(tag)
            return
        if self.hidden:
            return
        if tag in self.BLOCKS:
            self.active.append({"tag": tag, "parts": [],
                                "line": self.getpos()[0]})

    def handle_data(self, data):
        if not self.hidden and self.active:
            self.active[-1]["parts"].append(data)

    def handle_endtag(self, tag):
        if self.hidden:
            if self.hidden[-1] == tag:
                self.hidden.pop()
            return
        if not self.active or self.active[-1]["tag"] != tag:
            return
        node = self.active.pop()
        norm = " ".join(" ".join(node["parts"]).split())
        if self.active:
            self.active[-1]["parts"].append(norm)
        if not norm or len(norm) > 32 * 1024:
            return
        self.blocks.append({"tag": tag, "line": node["line"], "text": norm})


def candidate_review_fingerprints(original_html: bytes) -> dict:
    """Create reviewer locators without storing prose, gold labels, or a verdict."""
    _require(isinstance(original_html, bytes)
             and 0 < len(original_html) <= 4 * 1024 * 1024,
             "Bounded original Cado HTML bytes required")
    parser = _TextBlockFingerprints()
    try:
        parser.feed(original_html.decode("utf-8", errors="replace"))
        parser.close()
    except (ValueError, RecursionError, UnicodeError) as exc:
        raise ValueError("Archived HTML review-block parser failed") from exc

    terms = ("kiss-a-dog", "redis", "xmrig", "xhide")
    cues = []
    for i, block in enumerate(parser.blocks):
        present = [term for term in terms if term in block["text"].casefold()]
        if not present:
            continue
        cues.append({
            "source_block_index": i,
            "html_line_number": block["line"],
            "html_element": block["tag"],
            "normalized_block_text_sha256": hashlib.sha256(
                block["text"].encode("utf-8")
            ).hexdigest(),
            "candidate_terms_present": present,
        })
    _require(len(cues) <= 128, "Excessive candidate evidence blocks")
    _require(any("xmrig" in c["candidate_terms_present"] for c in cues)
             and any("xhide" in c["candidate_terms_present"] for c in cues),
             "No reviewer-locatable original XMRig/XHide evidence blocks")
    return {
        "schema_version": "original-cado-20230206-unreviewed-evidence-block-fingerprints-v1",
        "original_html_sha256": hashlib.sha256(original_html).hexdigest(),
        "indexed_visible_blocks": len(parser.blocks),
        "matched_candidate_block_count": len(cues),
        "evidence_block_hashes_and_structural_positions_only": cues,
        "literal_source_text_exported": False,
        "claim_semantics_reviewer_verified": False,
        "same_campaign_variant_scope_verified": False,
        "source_rights_approved": False,
        "g1_evaluation_eligible": False,
        "research_ready": False,
    }


def verify_original_cado(archive: str, headers: str, *, manifest: str, metadata: str):
    index = _fixed(_read_json(metadata, 4096))
    verify_range_headers(_read_file(headers, 32768))
    raw = _read_file(archive, LIMIT_COMPRESSED)
    _require(len(raw) == int(FIRST_OBSERVED_LENGTH), "Exact original WARC gzip member size differs")
    registry = _read_json(manifest, LIMIT_MANIFEST)
    receipt = validate_capture(index, raw, registry, CADO_ID)
    warc_headers, remaining = _headers(_decode_member(raw), b"WARC/1.")
    declared = int(warc_headers["content-length"])
    http_headers, original_html = _headers(
        remaining[:declared], b"HTTP/1.", allow_repeated_http_fields=True
    )
    _require(http_headers.get("content-type", "").lower().startswith("text/html"),
             "Expected actual historical HTML content type")
    lexical_checks = verify_original_cado_html_identity(original_html)
    receipt["historical_html_visible_text_identity_tokens"] = lexical_checks
    anchors = candidate_review_fingerprints(original_html)
    _require(anchors["indexed_visible_blocks"] == EXPECTED_REVIEW_BLOCK_COUNT
             and anchors["matched_candidate_block_count"] ==
             EXPECTED_MATCHED_REVIEW_BLOCK_COUNT,
             "Original historical Cado reviewer block inventory drifted")
    cue_map = {
        cue["source_block_index"]: cue
        for cue in anchors["evidence_block_hashes_and_structural_positions_only"]
    }
    for block_index, (expected_terms, expected_sha) in EXPECTED_UNREVIEWED_ORIGINAL_BLOCKS.items():
        cue = cue_map.get(block_index)
        _require(cue is not None
                 and cue["normalized_block_text_sha256"] == expected_sha
                 and ",".join(cue["candidate_terms_present"]) == expected_terms,
                 "Historical XMRig/XHide source evidence fingerprint changed")
    receipt["unreviewed_original_page_evidence_block_fingerprints"] = anchors
    receipt["historical_html_token_presence_is_not_semantic_review"] = True
    _require(receipt["source_version_id"] == CADO_ID
             and receipt["captured_html_byte_count"] == EXPECTED_ORIGINAL_HTML_BYTE_COUNT
             and receipt["captured_html_sha256"] == EXPECTED_ORIGINAL_HTML_SHA256
             and receipt["warc_member_sha256"] == EXPECTED_WARC_MEMBER_SHA256,
             "Complete archived original 2023 Cado webpage differs from pinned observed bytes")
    receipt["official_commoncrawl_range_http_206_verified"] = True
    receipt["original_cado_historic_url_matched"] = True
    receipt["full_original_article_identity_reviewed"] = False
    receipt["original_cado_article_body_historical_byte_capture_verified"] = True
    receipt["archive_timestamp_independently_authenticated"] = False
    receipt["source_rights_approved"] = False
    receipt["source_version_approved"] = False
    receipt["research_ready"] = False
    return receipt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--warc-member", required=True)
    parser.add_argument("--range-headers", required=True)
    parser.add_argument("--metadata", default=INDEX_PATH)
    parser.add_argument("--manifest", default="datasets/manifests/pilot.json")
    args = parser.parse_args(argv)
    try:
        out = verify_original_cado(
            args.warc_member, args.range_headers,
            manifest=args.manifest, metadata=args.metadata
        )
    except (ValueError, OSError, TypeError) as exc:
        print(json.dumps({"status": "original_cado_archive_refused",
                          "reason": str(exc)[:400], "research_ready": False}, sort_keys=True))
        return 2
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
