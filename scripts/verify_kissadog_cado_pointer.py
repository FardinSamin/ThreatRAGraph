"""Offline candidate-only replay of 2022 Securonix pointer to Cado Kiss-a-dog.

These are original Git blob bytes of a third-party derivative IOC/reference index,
NOT the original Cado honeypot investigation or historical publication proof.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re

VERSION = "kissadog-cado-derivative-pointer-v1"
COMMIT = "".join(("79b944c1", "77a8640f", "b8f53965", "15daf2c2", "49a43b15"))
REFERENCE_GIT_BLOB = "".join(("12bd1a3b", "9158c392", "70ba1072", "7d03b349", "f13302ea"))
IOC_GIT_BLOB = "".join(("76844e58", "b73bda7e", "2af8d296", "f4cc9d0c", "2afc201e"))
REFERENCE_PATH = "New_Variant_of_Kiss_a_Dog_Cryptojacking_Campaign/References.txt"
IOC_PATH = "New_Variant_of_Kiss_a_Dog_Cryptojacking_Campaign/README.md"
CANONICAL_OLD_CADO_URL = (
    "https://www.cadosecurity.com/"
    "kiss-a-dog-discovered-utilizing-a-20-year-old-process-hider/"
)
MAX_BYTES = 16 * 1024


def _blob_oid(raw: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + bytes((0,)) + raw,
                        usedforsecurity=False).hexdigest()


def verify_reference(original_reference: bytes, original_iocs: bytes) -> dict:
    for raw, oid in ((original_reference, REFERENCE_GIT_BLOB), (original_iocs, IOC_GIT_BLOB)):
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BYTES:
            raise ValueError("Bounded historical Git blob bytes required")
        if _blob_oid(raw) != oid:
            raise ValueError("Source Git blob differs from pinned 2022 commit")
    try:
        ref = original_reference.decode("utf-8", "strict")
        iocs = original_iocs.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise ValueError("Original Git bytes are not UTF-8") from exc
    if ref.strip() != CANONICAL_OLD_CADO_URL or ref.count(CANONICAL_OLD_CADO_URL) != 1:
        raise ValueError("Expected exact original Cado report link")
    if not iocs.startswith("\n## IOCs\n") or iocs.count("__hash__:") != 1:
        raise ValueError("Expected bounded Securonix IoC listing")
    # Derived IOCs are not independently collected by the Securonix reference
    # list; they cannot substantiate a second Cado behavioral-research group.
    hashes = re.findall(r"(?m)^[0-9a-f]{64}$", iocs)
    if len(hashes) != 7 or len(set(hashes)) != 7:
        raise ValueError("Unexpected number or duplication of cited Cado hashes")
    if "kiss.a-dog.top/b2f628/m/xm.jpg" not in iocs:
        raise ValueError("Historical Cado reference did not include expected IOC cue")
    return {
        "schema_version": VERSION,
        "status": "exact_derivative_reference_bytes_verified_not_original_cado_article",
        "original_source_repository": "Securonix/AutonomousThreatSweeper",
        "git_commit": COMMIT,
        "git_declared_committer_time_unverified_as_public_by": "2022-12-23T11:42:26Z",
        "historical_original_cado_link": CANONICAL_OLD_CADO_URL,
        "reference_path": REFERENCE_PATH,
        "reference_blob_sha1": REFERENCE_GIT_BLOB,
        "reference_sha256": hashlib.sha256(original_reference).hexdigest(),
        "reference_bytes": len(original_reference),
        "derived_iocs_path": IOC_PATH,
        "derived_iocs_blob_sha1": IOC_GIT_BLOB,
        "derived_iocs_sha256": hashlib.sha256(original_iocs).hexdigest(),
        "derived_ioc_count": len(hashes),
        "derived_iocs_bytes": len(original_iocs),
        "original_cado_report_body_present": False,
        "original_cado_report_public_time_verified": False,
        "publisher_source_rights_approved": False,
        "original_cado_source_version_approved": False,
        "securonix_independent_honeypot_investigation_verified": False,
        "g1_two_independent_claim_groups_verified": False,
        "research_ready": False,
    }


def _read(path: str) -> bytes:
    p = Path(path)
    if p.is_symlink() or not p.is_file() or not 0 < p.stat().st_size <= MAX_BYTES:
        raise ValueError("A bounded non-symlink original input file is required")
    with p.open("rb") as fp:
        return fp.read(MAX_BYTES + 1)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference-file", required=True)
    parser.add_argument("--ioc-file", required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_reference(_read(args.reference_file), _read(args.ioc_file))
    except (ValueError, TypeError, OSError) as exc:
        print(json.dumps({"status": "historical_kissadog_reference_refused",
                          "reason": str(exc)[:400], "research_ready": False}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
