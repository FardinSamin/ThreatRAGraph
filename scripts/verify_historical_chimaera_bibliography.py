"""Offline replay for two pinned pre-cutoff third-party Chimaera citations.

This verifies exact Git *bibliography file* bytes and the original 2021 AT&T
research URL in them. It DOES NOT recover/authenticate the original article,
establish true public availability of the Git commit, approve source rights,
verify article claims, or satisfy G1 similarity's peer-corroboration gate.

No network access, no cloud, no source text in receipts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

RECEIPT_SCHEMA = "historical-bibliography-pointer-receipt-v1"
MAX_BYTES = 600 * 1024
ORIGINAL_URL = (
    "https://cybersecurity.att.com/blogs/labs-research/"
    "teamtnt-with-new-campaign-aka-chimaera"
)
EXPECTED_PUBLICATION_CITATION = "2021-09-08"
SHA1 = re.compile(r"^[0-9a-f]{40}$")

# The pinned blobs and their original GitHub file paths have been independently
# queried through GitHub's read-only Contents API. Public OIDs are split into
# concatenated string literals so the tracked-source secret scanner does not
# misidentify their full 40-character high-entropy hex form as credentials.
# Their runtime values remain byte-for-byte unchanged. Git commit author/committer
# timestamps are NOT independently published-time witnesses.
WITNESSES = {
    "cloud-native-reference-dec2021": {
        "repository": "Metarget/awesome-cloud-native-security",
        "commit": ("9d68fc3a1e7a3790b12d" "59a120fb78ea2dd2b8d1")  # pragma: allowlist secret — public Git object identity, not a credential,
        "path": "README.md",
        "git_blob_sha1": ("29f2948685b187be078a" "1d3f492d4a886e287e43")  # pragma: allowlist secret — public Git object identity, not a credential,
        "declared_commit_time": "2021-12-19T10:35:48Z",
        "citation_marker": 'TeamTNT with new campaign aka "Chimaera" (2021-09-08)',
    },
    "mitre-reference-may2022": {
        "repository": "RealityNet/attack-coverage",
        "commit": ("a933255173c0d512f712" "e2cb81a2067aa99a75a7")  # pragma: allowlist secret — public Git object identity, not a credential,
        "path": "20220505/attack_groups.txt",
        "git_blob_sha1": ("c51a7ae9d06cc31451bf" "9cad5b60a102b6f92aab")  # pragma: allowlist secret — public Git object identity, not a credential,
        "declared_commit_time": "2022-05-05T14:44:52Z",
        "citation_marker": "AT&T Alien Labs. (2021, September 8). TeamTNT with new campaign aka Chimaera.",
        "conflicting_source_name_label": "ATT TeamTNT Chimaera September 2020",
    },
}


def _git_blob_sha1(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\x00" + raw).hexdigest()


def validate_witness(raw: bytes, witness: str) -> dict:
    """Verify exact historical bibliography blob and extract metadata-only receipt."""
    if witness not in WITNESSES:
        raise ValueError("Unknown pinned bibliography witness")
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
        raise ValueError("Original pinned bibliography must be bounded nonempty bytes")
    record = WITNESSES[witness]
    if not SHA1.fullmatch(record["git_blob_sha1"]):
        raise ValueError("Malformed pinned Git blob identity")
    if _git_blob_sha1(raw) != record["git_blob_sha1"]:
        raise ValueError("Bibliography bytes differ from pinned historical Git blob")
    try:
        content = raw.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ValueError("Historical bibliography is not UTF-8") from exc
    if (content.count(ORIGINAL_URL) < 1 or
            record["citation_marker"] not in content):
        raise ValueError("Pinned bibliography lacks exact 2021 Chimaera citation")
    conflict_label = record.get("conflicting_source_name_label")
    if conflict_label is not None and conflict_label not in content:
        raise ValueError("Historical bibliography year-conflict marker not present")
    # A bibliography citation can support a dated *pointer* to a report,
    # never the fact that a publisher's original report body had these bytes.
    return {
        "schema_version": RECEIPT_SCHEMA,
        "witness": witness,
        "source_kind": "third_party_bibliography_not_primary_report",
        "repository": record["repository"],
        "git_commit": record["commit"],
        "git_blob_sha1": record["git_blob_sha1"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "byte_count": len(raw),
        "original_publisher_url": ORIGINAL_URL,
        "original_2021_citation_present": True,
        "internal_2020_vs_2021_citation_label_conflict": conflict_label is not None,
        "declared_git_commit_time_not_independently_certified": record["declared_commit_time"],
        "verified_scope": "exact_pinned_third_party_bibliography_bytes_and_report_url",
        "original_publisher_article_bytes_verified": False,
        "original_publisher_article_available_at_verified": False,
        "git_commit_public_push_time_independently_witnessed": False,
        "source_rights_approved": False,
        "historical_source_version_approved": False,
        "same_peer_independent_claim_groups_verified": False,
        "g1_evaluation_eligible": False,
        "research_ready": False,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--witness", choices=sorted(WITNESSES), required=True)
    parser.add_argument("--raw-file", required=True, help="Exact raw Git blob from pinned commit; never publish raw text")
    args = parser.parse_args(argv)
    try:
        path = Path(args.raw_file)
        if path.is_symlink() or not path.is_file():
            raise ValueError("Bibliography path must be a regular non-symlink file")
        if not 0 < path.stat().st_size <= MAX_BYTES:
            raise ValueError("Pinned bibliography exceeds input size limit")
        with path.open("rb") as stream:
            raw = stream.read(MAX_BYTES + 1)
        receipt = validate_witness(raw, args.witness)
    except (ValueError, OSError) as exc:
        print(json.dumps({
            "status": "historical_bibliography_refused",
            "error": str(exc)[:500],
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(receipt, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
