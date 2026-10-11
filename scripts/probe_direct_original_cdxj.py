"""Bounded original Common Crawl CDXJ index lookup via direct immutable index files.

Does NOT contact rate-limited index.commoncrawl.org, AWS APIs, Athena or paid
services. Performs serial HTTPS *byte-range* reads of a monthly cluster.idx
and a few exact compressed CDXJ blocks. Never downloads any article contents,
approves source versions, or treats lack of a hit in one crawl as corpus absence.
"""
from __future__ import annotations

import argparse
from bisect import bisect_right
import gzip
import hashlib
import io
import json
import re
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from scripts.probe_original_campaign_cdx import (COLLECTIONS, TARGETS, _no_duplicates,
                                                 classify_row)

VERSION = "original-cdxj-direct-cluster-lookup-v1"
BASE = "https://data.commoncrawl.org/cc-index/collections"
MAX_CLUSTER_SIZE = 256 * 1024 * 1024
MAX_RANGE = 768 * 1024
MAX_CDX_MEMBER = 700 * 1024
MAX_INFLATED = 16 * 1024 * 1024
MAX_BINARY_PROBES = 28
MAX_LOCATOR_BLOCKS = 5
WINDOW = 8192


def _require(value, message):
    if not value:
        raise ValueError(message)


def _url_key(url):
    parts = urlsplit(url)
    _require(parts.scheme == "https" and parts.hostname and not parts.username
             and not parts.password and parts.port is None
             and not parts.query and not parts.fragment,
             "Expected exact HTTPS original publisher URL")
    host = parts.hostname.lower()
    if host.startswith("www."):
        host = host[4:]
    return ",".join(reversed(host.split("."))) + ")" + parts.path.lower()


def _index_surt_variants(url):
    """Probe apex and preserved-www sort keys; trust only exact JSON URLs.

    Historical index generations can differ on whether leading www is
    canonicalized. Selecting a compressed block using only the apex key can
    silently miss an existing original-publisher record in the www keyspace.
    """
    canonical = _url_key(url)
    host = urlsplit(url).hostname or ""
    if not host.startswith("www."):
        return (canonical,)
    key_host, separator, suffix = canonical.partition(")")
    _require(separator == ")", "Malformed generated canonical SURT")
    preserved_www = key_host + ",www)" + suffix
    return (canonical, preserved_www)


def _cluster_filename(collection, shard):
    _require(collection in COLLECTIONS, "Unexpected Common Crawl collection")
    _require(re.fullmatch(r"cdx-[0-9]{5}\.gz", shard) is not None,
             "Untrusted compressed CDXJ shard path")
    return f"{BASE}/{collection}/indexes/{shard}"


def _cluster_rows(buffer, *, start_offset, total):
    _require(isinstance(buffer, bytes) and buffer
             and 0 <= start_offset < total, "Missing original cluster index span")
    # Slice to complete ASCII rows on both ends of a partial HTTP range.
    begin = 0 if start_offset == 0 else buffer.find(b"\n") + 1
    end = buffer.rfind(b"\n")
    _require(begin >= 0 and end >= begin, "No complete index lines in byte range")
    rows = []
    for line in buffer[begin:end].split(b"\n"):
        try:
            original = line.decode("ascii")
            cols = original.split("\t")
            _require(len(cols) >= 4, "Incorrect cluster index column count")
            first = cols[0].rsplit(" ", 1)
            _require(len(first) == 2 and bool(first[0]), "Invalid SURT boundary")
            _require(re.fullmatch(r"cdx-[0-9]{5}\.gz", cols[1]) is not None,
                     "Unexpected indexed CDXJ filename")
            offset, length = int(cols[2]), int(cols[3])
            _require(0 <= offset <= 5_000_000_000
                     and 0 < length <= MAX_CDX_MEMBER,
                     "Unbounded original CDXJ compressed member range")
        except (UnicodeError, IndexError, ValueError) as exc:
            raise ValueError("Invalid original Common Crawl cluster.idx row") from exc
        rows.append({
            "key": first[0],
            "timestamp": first[1],
            "shard": cols[1],
            "offset": offset,
            "length": length,
        })
    _require(rows and all(rows[i]["key"] <= rows[i+1]["key"]
                          for i in range(len(rows)-1)),
             "Cluster.idx boundary rows are unsorted or absent")
    return rows


class _RangeReader:
    """Strict HTTPS-only 206 reader, accepts injected deterministic test transport."""

    def __init__(self, get_size=None, get_range=None):
        self.get_size = get_size or self._head
        self.get_range = get_range or self._fetch

    @staticmethod
    def _head(url):
        _require(url.startswith(BASE + "/"), "Unexpected archive host")
        req = Request(url, method="HEAD", headers={
            "User-Agent": "ThreatRAGraph-P1g-2023-DirectIndex/1.0 (noncommercial candidate research)"
        })
        with urlopen(req, timeout=20) as res:
            _require(res.status == 200 and res.geturl() == url,
                     "Unexpected direct original cluster index endpoint")
            return int(res.headers["content-length"])

    @staticmethod
    def _fetch(url, start, length):
        _require(url.startswith(BASE + "/") and 0 <= start
                 and 0 < length <= MAX_RANGE, "Refuse broad archive read")
        end = start + length - 1
        request = Request(url, headers={
            "User-Agent": "ThreatRAGraph-P1g-2023-DirectIndex/1.0 (noncommercial candidate research)",
            "Range": f"bytes={start}-{end}",
            "Accept-Encoding": "identity",
        })
        with urlopen(request, timeout=25) as res:
            _require(res.status == 206 and res.geturl() == url,
                     "Archive must honor exact immutable HTTP 206 byte range")
            field = res.headers.get("Content-Range", "")
            match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", field)
            _require(match is not None
                     and int(match.group(1)) == start
                     and int(match.group(2)) == end
                     and res.headers.get("Content-Encoding", "identity") == "identity",
                     "Original archive HTTP response range is inconsistent")
            data = res.read(length+1)
            _require(len(data) == length, "Truncated or oversized original index range")
            return data

    def size(self, url):
        s = self.get_size(url)
        _require(type(s) is int and 0 < s <= MAX_CLUSTER_SIZE,
                 "Unknown or excessive cluster idx byte length")
        return s

    def read(self, url, offset, length, total=None):
        _require(0 <= offset and 0 < length <= MAX_RANGE
                 and (total is None or offset+length <= total),
                 "Unbounded direct index read")
        data = self.get_range(url, offset, length)
        _require(isinstance(data, bytes) and len(data) == length,
                 "Archive returned wrong byte count")
        return data


def _block_covering_url(reader, collection, needle):
    url = f"{BASE}/{collection}/indexes/cluster.idx"
    total = reader.size(url)
    lo, hi = 0, total
    probes = 0
    while hi - lo > 64000:
        _require(probes < MAX_BINARY_PROBES,
                 "Original index lower-bound binary probe exceeded limits")
        midpoint = (lo+hi)//2
        fetch = min(WINDOW, total-midpoint)
        buf = reader.read(url, midpoint, fetch, total)
        first = buf.find(b"\n")
        second = buf.find(b"\n", first+1)
        _require(first >= 0 and second > first,
                 "Cannot locate complete original cluster boundary line")
        line = buf[first+1:second].decode("ascii", "strict")
        key = line.split("\t", 1)[0].split(" ", 1)[0]
        if key < needle:
            lo = midpoint+second+1
        else:
            hi = midpoint
        probes += 1
    # Look at bounded complete rows around the lower bound and one predecessor.
    start = max(0, lo-24000)
    end = min(total, hi+24000)
    size = end-start
    _require(0 < size <= MAX_RANGE, "Excessive cluster local index window")
    chunk = reader.read(url, start, size, total)
    lines = _cluster_rows(chunk, start_offset=start, total=total)
    keys = [x["key"] for x in lines]
    n = bisect_right(keys, needle)-1
    _require(n >= 0, "Original index predecessor outside bounded window")
    selected = lines[max(0, n-1):min(len(lines), n+4)]
    # Rows can point to the same compressed CDX chunk; deduplicate.
    uniques = []
    seen = set()
    for obj in selected:
        ident = (obj["shard"], obj["offset"], obj["length"])
        if ident not in seen:
            seen.add(ident)
            uniques.append(obj)
    _require(0 < len(uniques) <= MAX_LOCATOR_BLOCKS,
             "No bounded original index range")
    return {
        "cluster_size": total,
        "cluster_local_sha256": hashlib.sha256(chunk).hexdigest(),
        "cluster_local_offset": start,
        "cluster_local_length": len(chunk),
        "binary_probe_count": probes,
        "cluster_first_key": lines[0]["key"],
        "cluster_last_key": lines[-1]["key"],
        "selected_surt_boundary_keys": [r["key"] for r in uniques],
    }, uniques


def _read_gzip_chunk(chunk):
    _require(0 < len(chunk) <= MAX_CDX_MEMBER, "Excessive CDXJ compressed bytes")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(chunk)) as f:
            out = f.read(MAX_INFLATED+1)
    except (OSError, EOFError, OverflowError) as exc:
        raise ValueError("Invalid original compressed CDXJ byte range") from exc
    _require(len(out) <= MAX_INFLATED, "Excessive CDXJ uncompressed block")
    return out


def _parse_cdxj(chunk, target, alias, collection):
    """Parse original CDXJ line metadata, never article contents.

    Keep the recorded source URL authoritative; inconsistent target-record
    timestamps or duplicate JSON fields fail closed rather than producing
    plausible-looking historical chronology receipts.
    """
    found = []
    for raw in _read_gzip_chunk(chunk).splitlines():
        if not raw:
            continue
        _require(len(raw) <= 16384, "Oversized original CDXJ record")
        # Historical www SURT representations may vary; do not equate the
        # physical SURT prefix with the stored original publisher URL.
        surt, sep, rest = raw.partition(b" ")
        _require(bool(sep and surt), "Invalid original CDXJ SURT field")
        timestamp, separator, data = rest.partition(b" ")
        _require(bool(separator and len(timestamp) == 14
                      and timestamp.isascii() and timestamp.isdigit()),
                 "Invalid original CDXJ timestamp field")
        try:
            row = json.loads(
                data.decode("utf-8"), object_pairs_hook=_no_duplicates
            )
        except (ValueError, UnicodeError, TypeError, RecursionError) as exc:
            raise ValueError("Invalid original CDXJ JSON record") from exc
        _require(isinstance(row, dict), "Non-object original CDXJ record")
        if row.get("url") != alias:
            continue
        # An index-line timestamp inconsistent with its JSON record must not
        # be treated as an independently corroborating date observation.
        _require(row.get("timestamp") == timestamp.decode("ascii"),
                 "Original CDXJ line and JSON capture timestamps disagree")
        info = classify_row(
            row, target=target, requested_url=alias, collection=collection
        )
        info["observed_index_record_sha256"] = hashlib.sha256(raw).hexdigest()
        found.append(info)
    return found

def probe_direct(targets, collections, reader=None):
    reader = reader or _RangeReader()
    _require(0 < len(targets) <= 4 and 0 < len(collections) <= 3
             and all(t in TARGETS for t in targets)
             and all(c in COLLECTIONS for c in collections),
             "Only bounded registered investigator/collection scope allowed")
    observations = []
    records = []
    cached = {}
    for collection in collections:
        for target in targets:
            for alias in TARGETS[target]:
                variant_diagnostics = []
                matched = []
                for needle in _index_surt_variants(alias):
                    try:
                        diag, locator_rows = _block_covering_url(
                            reader, collection, needle
                        )
                        debug_chunk_keys = []
                        count_before = len(matched)
                        for row in locator_rows:
                            index_url = _cluster_filename(collection, row["shard"])
                            block_key = (index_url, row["offset"], row["length"])
                            if block_key not in cached:
                                cached[block_key] = reader.read(
                                    index_url, row["offset"], row["length"]
                                )
                            block = cached[block_key]
                            uncompressed = _read_gzip_chunk(block)
                            keys = [
                                line.partition(b" ")[0].decode(
                                    "ascii", errors="replace"
                                )
                                for line in uncompressed.splitlines() if line
                            ]
                            host = (urlsplit(alias).hostname or "").removeprefix(
                                "www."
                            )
                            debug_chunk_keys.append({
                                "boundary": row["key"],
                                "row_count": len(keys),
                                "first_urlkey": keys[0] if keys else None,
                                "last_urlkey": keys[-1] if keys else None,
                                "registered_original_host_token_present":
                                    host.encode("ascii") in uncompressed,
                            })
                            matched.extend(
                                _parse_cdxj(block, target, alias, collection)
                            )
                        variant_diagnostics.append({
                            "searched_surt_key": needle,
                            "status": "index_range_examined",
                            "raw_matches": len(matched) - count_before,
                            "blocks_read": len(locator_rows),
                            "bounded_compressed_cdxj_block_diagnostics":
                                debug_chunk_keys,
                            **diag,
                        })
                    except (OSError, ValueError, UnicodeError, TimeoutError) as exc:
                        variant_diagnostics.append({
                            "searched_surt_key": needle,
                            "status": "direct_index_access_or_format_error",
                            "error_category": type(exc).__name__,
                        })
                # Overlapping index ranges may contain the same source record.
                # Keep each original WARC locator once, not once per search key.
                deduplicated = {}
                for item in matched:
                    identity = (
                        item["observed_url"], item["cdx_timestamp_declared_utc"],
                        item["archive_filename"], item["archive_offset"],
                        item["archive_length"], item["archive_payload_digest"],
                    )
                    deduplicated[identity] = item
                found = list(deduplicated.values())
                for item in found:
                    item["cdxj_direct_index_original_bytes_verified"] = True
                    item["source_version_approved"] = False
                    item["research_ready"] = False
                    records.append(item)
                coverage_complete = all(
                    result["status"] == "index_range_examined"
                    for result in variant_diagnostics
                )
                # A miss is never an archive-absence claim; a failed variant
                # makes even the bounded lookup incomplete.
                if found:
                    status = "matching_original_cdxj_rows_found"
                elif not coverage_complete:
                    status = "direct_index_partial_coverage_unvalidated"
                else:
                    status = "no_matching_exact_url_in_selected_index_blocks"
                observations.append({
                    "collection": collection,
                    "target": target,
                    "original_publisher_url": alias,
                    "status": status,
                    "matched_rows": len(found),
                    "all_declared_surt_variants_probed": coverage_complete,
                    "index_surt_variant_diagnostics": variant_diagnostics,
                })
    return {
        "schema_version": VERSION,
        "status": "original_index_bytes_only_source_capture_not_authenticated",
        "query_receipts": observations,
        "candidate_metadata_rows": records,
        "matching_pre_cutoff_candidate_count": sum(
            r["candidate_status"] ==
            "prospective_pre_cutoff_html_record_not_yet_warc_verified"
            for r in records
        ),
        "known_cado_20230206_positive_control_matched": any(
            r.get("target") == "cado-original-2022"
            and r.get("collection") == "CC-MAIN-2023-06"
            and r.get("observed_url") == TARGETS["cado-original-2022"][0]
            and r.get("cdx_timestamp_declared_utc") == "2023-02-06T12:05:44Z"
            and r.get("archive_offset") == "696857860"
            and r.get("archive_length") == "22387"
            and r.get("archive_payload_digest") == "IIQQZYE7EHNZFM6CFTJLNT226VHY2D3P"
            for r in records
        ),
        "archive_article_bytes_acquired": False,
        "archive_timestamp_independently_authenticated": False,
        "publisher_reuse_rights_approved": False,
        "independent_researcher_claims_reviewed": False,
        "source_version_approved": False,
        "g1_evaluation_eligible": False,
        "research_ready": False,
    }


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--require-cado-positive", action="store_true",
                   help="Refuse to treat historical index search as validated unless known archived Cado 2023-02-06 CDXJ record is recovered")
    p.add_argument("--targets", nargs="+", choices=tuple(TARGETS),
                   default=["cado-original-2022", "crowdstrike-original-2022"])
    p.add_argument("--collections", nargs="+", choices=COLLECTIONS,
                   default=["CC-MAIN-2023-06"])
    args = p.parse_args(argv)
    receipt = probe_direct(args.targets, args.collections)
    if args.require_cado_positive and not receipt["known_cado_20230206_positive_control_matched"]:
        receipt["status"] = "original_index_lookup_unvalidated_known_cado_positive_control_failed"
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
