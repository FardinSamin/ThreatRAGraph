"""Live, bounded archival-CDX *discovery* for original campaign publisher URLs.

This tool intentionally does not fetch or approve HTML source bytes. Historical
CDX rows, even when found, remain untrusted until official WARC range and
independent time/source rights verification. The original publisher URL forms
are explicit; historical aliases are investigated separately.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

VERSION = "p1e-original-campaign-cdx-discovery-v1"
CUTOFF = datetime(2023, 3, 1, tzinfo=timezone.utc)
MAX_RESPONSE_BYTES = 128 * 1024
MAX_ROWS_PER_QUERY = 8
COLLECTIONS = (
    "CC-MAIN-2022-49",
    "CC-MAIN-2023-06",
    "CC-MAIN-2023-07",
)
# These are *original* investigator URLs or separate publisher-authorized
# syndication. Keep each alias visible rather than treating redirects/current
# URL rewrites as the historically observed primary source.
TARGETS = {
    "cado-original-2022": (
        "https://www.cadosecurity.com/kiss-a-dog-discovered-utilizing-a-20-year-old-process-hider/",
        "https://www.cadosecurity.com/blog/kiss-a-dog-discovered-utilizing-a-20-year-old-process-hider",
    ),
    "crowdstrike-original-2022": (
        "https://www.crowdstrike.com/blog/new-kiss-a-dog-cryptojacking-campaign-targets-docker-and-kubernetes/",
        "https://www.crowdstrike.com/en-us/blog/new-kiss-a-dog-cryptojacking-campaign-targets-docker-and-kubernetes/",
    ),
    "crowdstrike-csa-republication-2022": (
        "https://cloudsecurityalliance.org/blog/2022/12/09/new-kiss-a-dog-cryptojacking-campaign-targets-vulnerable-docker-and-kubernetes-infrastructure",
    ),
    "sysdig-early-2023": (
        "https://www.sysdig.com/blog/cloud-breach-terraform-data-theft",
    ),
}
DECLARED_FIRST_DAYS = {
    "cado-original-2022": "2022-10-26",
    "crowdstrike-original-2022": "2022-10-26",
    "crowdstrike-csa-republication-2022": "2022-12-09",
    "sysdig-early-2023": "2023-02-28",
}


def _parse_response_bytes(raw: bytes) -> list:
    if not isinstance(raw, bytes) or len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Oversized or unbounded original CDX response")
    out = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        if len(line) > 16384 or len(out) >= MAX_ROWS_PER_QUERY:
            raise ValueError("Oversized or overly numerous index rows")
        try:
            row = json.loads(line.decode("utf-8"), object_pairs_hook=_no_duplicates)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise ValueError("Invalid CDX JSON row") from exc
        if not isinstance(row, dict):
            raise ValueError("CDX row must be an object")
        out.append(row)
    return out


def _no_duplicates(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("Duplicate CDX field")
        result[k] = v
    return result


def _utc_stamp(value: str) -> datetime:
    if not isinstance(value, str) or len(value) != 14 or not value.isascii() or not value.isdigit():
        raise ValueError("Noncanonical original CDX timestamp")
    try:
        return datetime.strptime(value, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ValueError("Invalid CDX timestamp") from exc


def classify_row(row: dict, *, target: str, requested_url: str, collection: str) -> dict:
    if target not in TARGETS or requested_url not in TARGETS[target] or collection not in COLLECTIONS:
        raise ValueError("Unregistered URL, source role or index")
    if not isinstance(row, dict) or row.get("url") != requested_url:
        raise ValueError("CDX index URL differs from queried exact publisher alias")
    stamp = _utc_stamp(row.get("timestamp"))
    lower = datetime.strptime(DECLARED_FIRST_DAYS[target], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    if str(row.get("status")) != "200" or str(row.get("mime")).lower() not in ("text/html", "application/xhtml+xml"):
        status = "non_original_200_html_record"
    elif stamp < lower:
        status = "before_even_claimed_original_publication_calendar_day"
    elif stamp >= CUTOFF:
        status = "post_cutoff_archive_record_ineligible"
    else:
        status = "prospective_pre_cutoff_html_record_not_yet_warc_verified"
    fields = ("filename", "offset", "length", "digest")
    if any(not isinstance(row.get(field), str) for field in fields):
        status = "missing_required_warc_locator_or_digest"
    return {
        "target": target,
        "role": "publisher_authorized_republication_not_independent_investigation"
                if target == "crowdstrike-csa-republication-2022"
                else "original_investigator_url_candidate",
        "collection": collection,
        "queried_publisher_url": requested_url,
        "observed_url": row["url"],
        "cdx_timestamp_declared_utc": stamp.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "cdx_status": str(row.get("status")),
        "cdx_mime": str(row.get("mime")),
        "archive_filename": row.get("filename"),
        "archive_offset": row.get("offset"),
        "archive_length": row.get("length"),
        "archive_payload_digest": row.get("digest"),
        "candidate_status": status,
        "original_article_body_recovered": False,
        "independent_timestamp_verified": False,
        "source_version_approved": False,
        "research_ready": False,
    }


def probe(*, targets=None, collections=None, client=None) -> dict:
    names = tuple(TARGETS) if targets is None else tuple(targets)
    colls = COLLECTIONS if collections is None else tuple(collections)
    if not names or not colls or any(name not in TARGETS for name in names) or any(c not in COLLECTIONS for c in colls):
        raise ValueError("Only predeclared targets and collections may be searched")
    results = []
    queries = []
    for target in names:
        for alias in TARGETS[target]:
            for collection in colls:
                query = urlencode({"url": alias, "output": "json", "filter": "status:200", "collapse": "urlkey"})
                endpoint = f"https://index.commoncrawl.org/{collection}-index?{query}"
                try:
                    raw = client(endpoint) if client else _download(endpoint)
                    rows = _parse_response_bytes(raw)
                    count = 0
                    for row in rows:
                        result = classify_row(row, target=target, requested_url=alias, collection=collection)
                        results.append(result)
                        count += 1
                    qstatus = "index_returned_records" if count else "index_returned_empty_result"
                except HTTPError as exc:
                    qstatus = "index_record_absent_http_404" if exc.code == 404 else f"index_http_error_{exc.code}"
                    count = 0
                except (OSError, URLError, TimeoutError) as exc:
                    qstatus = "index_transport_unavailable"
                    count = 0
                except (ValueError, TypeError) as exc:
                    qstatus = "index_data_invalid_or_nonconforming"
                    count = 0
                queries.append({
                    "target": target, "collection": collection, "requested_url": alias,
                    "query_status": qstatus, "records_examined": count,
                })
    elig = [r for r in results if r["candidate_status"] == "prospective_pre_cutoff_html_record_not_yet_warc_verified"]
    return {
        "schema_version": VERSION,
        "status": "candidate_archival_index_search_only_no_source_approval",
        "query_count": len(queries),
        "candidate_record_count": len(elig),
        "query_receipts": queries,
        "candidate_metadata_rows": results,
        "candidate_archive_records_are_untrusted_until_warc_and_time_review": True,
        "original_article_body_recovered": False,
        "source_version_approved": False,
        "g1_evaluation_eligible": False,
        "research_ready": False,
    }


def _download(endpoint: str) -> bytes:
    host = urlsplit(endpoint)
    if host.scheme != "https" or host.hostname != "index.commoncrawl.org":
        raise ValueError("Only official HTTPS Common Crawl CDX endpoint permitted")
    request = Request(endpoint, headers={
        "User-Agent": "ThreatRAGraph-P1e-SourceProvenance/1.0 (candidate-only)",
        "Accept": "application/json",
    })
    with urlopen(request, timeout=17) as res:
        if res.status != 200:
            raise ValueError("Unexpected CDX response status")
        content = res.read(MAX_RESPONSE_BYTES + 1)
        if len(content) > MAX_RESPONSE_BYTES:
            raise ValueError("CDX response exceeds safe size")
        return content


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--targets", nargs="*", choices=tuple(TARGETS))
    parser.add_argument("--collections", nargs="*", choices=COLLECTIONS)
    args = parser.parse_args(argv)
    try:
        receipt = probe(targets=args.targets, collections=args.collections)
    except (ValueError, TypeError, OSError) as exc:
        print(json.dumps({"status": "original_index_probe_refused",
                          "reason": str(exc)[:300], "research_ready": False}, sort_keys=True))
        return 2
    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
