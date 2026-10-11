"""Offline, candidate-only Common Crawl CDX/WARC byte-range integrity gate.

The operator must separately acquire a specific CDX JSON record and exactly the
corresponding compressed WARC member using the declared HTTPS byte range.
No network access, untrusted code execution, automatic source approval, or
historical availability claims based only on untrusted metadata.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
import zlib

VERSION = "commoncrawl-candidate-warc-integrity-v1"
LIMIT_CDX = 32 * 1024
LIMIT_MANIFEST = 2 * 1024 * 1024
LIMIT_COMPRESSED = 4 * 1024 * 1024
LIMIT_UNCOMPRESSED = 8 * 1024 * 1024
LIMIT_PAYLOAD = 4 * 1024 * 1024
CUTOFF = "2023-03-01T00:00:00Z"
FIRST_CLAIMED_PUBLICATION_DAY = {
    # Screening-only lower bounds derived from current publisher pages and
    # independent contemporary references, NOT verified historical release times.
    "candidate:scarleteel-sysdig-20230228:unfrozen": "2023-02-28T00:00:00Z",
    "candidate:chimaera-alienlabs-20210908:unfrozen": "2021-09-08T00:00:00Z",
    "candidate:kissadog-crowdstrike-20221026:unfrozen": "2022-10-26T00:00:00Z",
    "candidate:kissadog-cado-202212:unfrozen": "2022-10-26T00:00:00Z",
}
CANDIDATES = set(FIRST_CLAIMED_PUBLICATION_DAY)
# Cado moved its original December 2022 report URL to a /blog/ form.
# Only its exact known historic URL is admitted as an alternate report path.
CADO_HISTORIC_URL = (
    "https://www.cadosecurity.com/"
    "kiss-a-dog-discovered-utilizing-a-20-year-old-process-hider/"
)
CADO_ID = "candidate:kissadog-cado-202212:unfrozen"
WARC_PATH = re.compile(
    r"crawl-data/CC-MAIN-[0-9]{4}-[0-9]{2}/segments/"
    r"[0-9]+\.[0-9]+/warc/CC-MAIN-[A-Za-z0-9.-]+\.warc\.gz"
)
UTC_SECONDS = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
DIGEST_B32 = re.compile(r"[A-Z2-7]{32}")


def _require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def _instant(value: str) -> datetime:
    _require(isinstance(value, str) and UTC_SECONDS.fullmatch(value) is not None,
             "Exact UTC seconds required")
    try:
        dt = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("Invalid calendar UTC timestamp") from exc
    _require(dt.strftime("%Y-%m-%dT%H:%M:%SZ") == value, "Noncanonical UTC time")
    return dt


def _canonical_url(value: str) -> tuple[str, str]:
    _require(isinstance(value, str) and len(value) <= 1024,
             "Invalid bounded source URL")
    u = urlsplit(value)
    host = u.hostname or ""
    _require(u.scheme in {"https", "http"} and host and u.username is None
             and u.password is None and u.port is None
             and not u.query and not u.fragment and
             all(c not in u.path for c in ("%", "\\", ";")),
             "URL must be a simple origin page without credentials, query or fragments")
    _require(u.path.startswith("/") and "//" not in u.path and
             all(p not in {".", ".."} for p in u.path.split("/")),
             "Noncanonical source path")
    return host.lower().removeprefix("www."), u.path.rstrip("/")


def _pairs_no_duplicate(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _read_file(path: str | Path, cap: int) -> bytes:
    p = Path(path)
    _require(not p.is_symlink() and p.is_file() and 0 < p.stat().st_size <= cap,
             "File missing, symlinked, empty or too large")
    with p.open("rb") as fp:
        data = fp.read(cap + 1)
    _require(0 < len(data) <= cap, "File changes or is out of bounds")
    return data


def _read_json(path: str | Path, cap: int):
    try:
        return json.loads(_read_file(path, cap).decode("utf-8"),
                          object_pairs_hook=_pairs_no_duplicate)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Invalid UTF-8 JSON input") from exc


def _headers(raw: bytes, prefix: bytes, *, limit: int = 32768,
             allow_repeated_http_fields: bool = False) -> tuple[dict, bytes]:
    _require(len(raw) <= LIMIT_UNCOMPRESSED and len(raw) >= 10, "Invalid record size")
    stop = raw.find(b"\r\n\r\n")
    _require(0 <= stop <= limit, "Missing or oversized CRLF headers")
    lines = raw[:stop].split(b"\r\n")
    _require(lines[0].startswith(prefix), "Wrong WARC or HTTP record start")
    headers = {}
    for line in lines[1:]:
        _require(b":" in line and not line.startswith((b" ", b"\t")),
                 "Malformed or folded header")
        key, val = line.split(b":", 1)
        try:
            name = key.decode("ascii").lower()
            value = val.strip().decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Non-ASCII metadata header") from exc
        _require(bool(re.fullmatch(r"[a-z0-9-]+", name)),
                 "Unsupported metadata header key")
        if name in headers:
            # RFC-valid repeated HTTP response negotiation/cookie metadata is
            # safe to ignore here; never silently override Content-Type,
            # length, encoding, transfer-encoding, or any WARC evidence digest.
            if allow_repeated_http_fields and name in {"vary", "set-cookie"}:
                continue
            raise ValueError("Duplicate HTTP/WARC header key: " + name)
        headers[name] = value
    return headers, raw[stop + 4:]


def _sha1_b32(raw: bytes) -> str:
    return base64.b32encode(hashlib.sha1(raw, usedforsecurity=False).digest()).decode("ascii").rstrip("=")


def _decode_member(raw: bytes) -> bytes:
    _require(isinstance(raw, bytes) and 0 < len(raw) <= LIMIT_COMPRESSED,
             "Bounded gzip WARC byte-range required")
    d = zlib.decompressobj(wbits=16 + 15)
    try:
        payload = d.decompress(raw, LIMIT_UNCOMPRESSED + 1)
    except zlib.error as exc:
        raise ValueError("Invalid compressed WARC member") from exc
    _require(d.eof and not d.unused_data and not d.unconsumed_tail
             and 0 < len(payload) <= LIMIT_UNCOMPRESSED,
             "Truncated, concatenated or decompression-bomb WARC member")
    return payload


def _source_record(manifest: dict, version: str) -> dict:
    _require(isinstance(manifest, dict) and isinstance(manifest.get("sources"), list),
             "Source registry is missing")
    _require(version in CANDIDATES, "Only predeclared SCARLETEEL/peer source leads allowed")
    found = [s for s in manifest["sources"]
             if isinstance(s, dict) and s.get("source_version_id") == version]
    _require(len(found) == 1, "Candidate source must appear exactly once")
    row = found[0]
    _require(row.get("status") == "candidate" and row.get("sha256") is None
             and row.get("available_at") is None and row.get("date_confidence") == "unknown"
             and row.get("redistribution") == "unknown",
             "Only unapproved, undated source leads accepted")
    _canonical_url(row["url"])
    return row


def validate_capture(index: dict, gzip_member: bytes, manifest: dict,
                     source_version_id: str, *, cutoff: str = CUTOFF) -> dict:
    row = _source_record(manifest, source_version_id)
    _require(isinstance(index, dict), "CDX must be JSON object")
    for k in ("url", "timestamp", "filename", "offset", "length", "status", "mime", "digest"):
        _require(isinstance(index.get(k), str), "Missing or invalid CDX field: " + k)
    _require(index["status"] == "200", "Only original HTML 200 captures accepted")
    _require(index["mime"].lower() in {"text/html", "application/xhtml+xml"},
             "CDX content type must be HTML")
    _require(WARC_PATH.fullmatch(index["filename"]) is not None,
             "Invalid Common Crawl WARC archive path")
    _require(index["offset"].isdigit() and len(index["offset"]) <= 17
             and (index["offset"] == "0" or not index["offset"].startswith("0")),
             "Invalid bounded WARC range start")
    _require(index["length"].isdigit() and len(index["length"]) <= 10
             and not index["length"].startswith("0")
             and 0 < int(index["length"]) <= LIMIT_COMPRESSED,
             "Invalid bounded WARC member length")
    _require(len(gzip_member) == int(index["length"]), "WARC range length mismatch")
    _require(DIGEST_B32.fullmatch(index["digest"].upper()) is not None,
             "CDX SHA-1 payload digest missing or malformed")
    acceptable_urls = {_canonical_url(row["url"])}
    if source_version_id == CADO_ID:
        acceptable_urls.add(_canonical_url(CADO_HISTORIC_URL))
    _require(_canonical_url(index["url"]) in acceptable_urls,
             "CDX capture URL is not the exact registered or historically pinned publisher page")

    _require(re.fullmatch(r"[0-9]{14}", index["timestamp"]) is not None,
             "CDX timestamp must be exactly 14 digits")
    try:
        observed = datetime.strptime(index["timestamp"], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("Invalid CDX UTC calendar timestamp") from exc
    cutoff_dt = _instant(cutoff)
    _require(observed < cutoff_dt, "Archived capture not earlier than screen cutoff")
    _require(observed >= _instant(FIRST_CLAIMED_PUBLICATION_DAY[source_version_id]),
             "Capture precedes even the unverified first-published calendar day")

    decompressed = _decode_member(gzip_member)
    wh, remainder = _headers(decompressed, b"WARC/1.")
    _require(wh.get("warc-type") == "response", "Capture must be HTTP response WARC")
    _require(wh.get("warc-record-id", "").startswith("<urn:uuid:"),
             "WARC record identity missing")
    _require(wh.get("warc-target-uri") == index["url"],
             "WARC target URL does not equal claimed CDX URL")
    _require(wh.get("warc-date") == observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
             "WARC-Date differs from CDX time")
    _require(wh.get("content-type", "").startswith("application/http"),
             "WARC block is not HTTP response")
    declared_len = wh.get("content-length", "")
    _require(declared_len.isdigit() and not declared_len.startswith("0")
             and 0 < int(declared_len) <= LIMIT_UNCOMPRESSED,
             "Missing or invalid WARC block Content-Length")
    n = int(declared_len)
    _require(remainder[n:] == b"\r\n\r\n", "WARC block length or end marker mismatch")
    http_block = remainder[:n]
    if "warc-block-digest" in wh:
        _require(wh["warc-block-digest"].upper() == "SHA1:" + _sha1_b32(http_block),
                 "WARC HTTP block digest mismatch")
    hh, body = _headers(http_block, b"HTTP/1.", allow_repeated_http_fields=True)
    _require(re.match(rb"HTTP/1\.[01] 200(?:\s|$)", http_block.split(b"\r\n", 1)[0]) is not None,
             "Archive HTTP status is not 200")
    _require(hh.get("content-type", "").lower().startswith(("text/html", "application/xhtml+xml")),
             "Archived HTTP response must contain HTML")
    _require(hh.get("content-encoding", "identity").lower() in {"identity", ""},
             "Precompressed HTTP content requires separate reviewed decoding")
    _require("transfer-encoding" not in hh, "Chunked HTTP requires separately reviewed decoding")
    _require(0 < len(body) <= LIMIT_PAYLOAD, "Empty or oversized original captured page")
    body_b32 = _sha1_b32(body)
    _require(body_b32 == index["digest"].upper(),
             "Original HTML payload SHA-1 does not match CDX digest")
    _require(wh.get("warc-payload-digest", "").upper() == "SHA1:" + body_b32,
             "WARC payload digest disagrees with captured body")
    _require(b"<html" in body[:8192].lower() or b"<!doctype html" in body[:8192].lower(),
             "Captured body does not look like HTML")

    return {
        "schema_version": VERSION,
        "status": "candidate_archival_record_bytes_consistent_not_historically_approved",
        "source_version_id": source_version_id,
        "publisher_url": row["url"],
        "cdx_capture_url": index["url"],
        "archive_collection": index["filename"].split("/")[1],
        "warc_filename": index["filename"],
        "warc_offset": int(index["offset"]),
        "warc_gzip_length": len(gzip_member),
        "warc_member_sha256": hashlib.sha256(gzip_member).hexdigest(),
        "captured_html_sha256": hashlib.sha256(body).hexdigest(),
        "captured_html_byte_count": len(body),
        "cdx_sha1_base32_verified_against_html": body_b32,
        "cdx_and_warc_declared_observation_time": observed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "declared_observation_precedes_proposed_cutoff": True,
        "publisher_page_calendar_lower_bound_not_independently_verified": (
            FIRST_CLAIMED_PUBLICATION_DAY[source_version_id]
        ),
        "declared_cutoff_utc": cutoff,
        "capture_from_genuine_commoncrawl_origin_authenticated": False,
        "archive_timestamp_independently_authenticated": False,
        "original_publisher_article_version_accepted": False,
        "copyright_and_redistribution_approved": False,
        "source_version_approved": False,
        "semantically_reviewed_feature_claims": False,
        "g1_evaluation_eligible": False,
        "research_ready": False,
        "next_step": (
            "Independently reacquire this exact WARC range from official Common Crawl "
            "and audit provenance, rights, source chronology and body semantics before approval."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index-record", required=True, help="Local original CDX JSON object")
    parser.add_argument("--warc-member", required=True, help="Local exact gzip WARC byte-range")
    parser.add_argument("--source-version-id", required=True)
    parser.add_argument("--manifest", default="datasets/manifests/pilot.json")
    parser.add_argument("--cutoff", default=CUTOFF)
    args = parser.parse_args(argv)
    try:
        report = validate_capture(
            _read_json(args.index_record, LIMIT_CDX),
            _read_file(args.warc_member, LIMIT_COMPRESSED),
            _read_json(args.manifest, LIMIT_MANIFEST),
            args.source_version_id, cutoff=args.cutoff
        )
    except (ValueError, TypeError, OSError, UnicodeError) as exc:
        print(json.dumps({"status": "candidate_warc_refused",
                          "reason": str(exc)[:400], "research_ready": False}, sort_keys=True))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
