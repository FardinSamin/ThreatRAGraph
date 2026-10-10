#!/usr/bin/env python3
"""Offline audit of the *reported* upstream runc v1.1.12 release/tag linkage.

Input: investigator-saved GitHub REST API JSON documents; no network access.
This verifies internal consistency of the API responses, not cryptographic
PGP signatures locally, independent GitHub authenticity, historical publication
of these exact API bytes, licensing, or scientific approval.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

CONTRACT = "runc-release-witness-v1"
RELEASE_API = "https://api.github.com/repos/opencontainers/runc/releases/tags/v1.1.12"
REF_API = "https://api.github.com/repos/opencontainers/runc/git/ref/tags/v1.1.12"
TAG_API_PREFIX = "https://api.github.com/repos/opencontainers/runc/git/tags/"
RELEASE_PAGE = "https://github.com/opencontainers/runc/releases/tag/v1.1.12"
CUTOFF = "2024-02-01T00:00:00Z"
OID = re.compile(r"^[0-9a-f]{40}$")
STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_JSON_BYTES = 1024 * 1024


def _time(value, field):
    if not isinstance(value, str) or not STAMP.fullmatch(value):
        raise ValueError(f"{field} must be exact UTC seconds")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise ValueError(f"{field} contains invalid calendar time") from exc


def _oid(value, field):
    if not isinstance(value, str) or not OID.fullmatch(value):
        raise ValueError(f"{field} must be a Git SHA-1 object ID")
    return value


def _obj(record, field):
    if not isinstance(record, dict):
        raise ValueError(f"{field} must be JSON object")
    return record


def read_api_json(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError("Input must be a bounded, regular, non-symlink JSON file")
    with path.open(encoding="utf-8") as stream:
        result = json.load(stream)
    return _obj(result, "GitHub API document")


def validate_witness(release, tag_ref, tag, *, cutoff=CUTOFF):
    """Check cross-document consistency. Caller must independently trust origin.

    Do not use result to set source available_at, approved status, or a
    historical CTI claim. GitHub's reported PGP verification may be checked
    independently with a trusted key and raw Git object, but is not re-run.
    """
    release = _obj(release, "release")
    tag_ref = _obj(tag_ref, "tag ref")
    tag = _obj(tag, "annotated tag")
    if (release.get("tag_name") != "v1.1.12"
            or release.get("html_url") != RELEASE_PAGE):
        raise ValueError("Release tag/page mismatch")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise ValueError("Unpublished draft/prerelease cannot be used as release witness")
    released = _time(release.get("published_at"), "release.published_at")
    cutoff_time = _time(cutoff, "cutoff")
    created = _time(release.get("created_at"), "release.created_at")
    if created > released or released > cutoff_time:
        raise ValueError("Release chronology inconsistent with proposed cutoff")
    ref_obj = _obj(tag_ref.get("object"), "tag_ref.object")
    tag_sha = _oid(ref_obj.get("sha"), "tag object ID")
    if (tag_ref.get("ref") != "refs/tags/v1.1.12"
            or ref_obj.get("type") != "tag"
            or ref_obj.get("url") != TAG_API_PREFIX + tag_sha):
        raise ValueError("Tag ref does not bind to expected annotated tag")
    if tag.get("tag") != "v1.1.12":
        raise ValueError("Annotated tag identity mismatch")
    tagger = _obj(tag.get("tagger"), "tagger")
    tagged_time = _time(tagger.get("date"), "tagger.date")
    if tagged_time > released:
        raise ValueError("Tagger timestamp follows public release")
    target = _obj(tag.get("object"), "tag target")
    commit_sha = _oid(target.get("sha"), "tagged commit")
    if (target.get("type") != "commit"
            or target.get("url") !=
            "https://api.github.com/repos/opencontainers/runc/git/commits/" + commit_sha):
        raise ValueError("Tag target is not a matching commit")
    verification = _obj(tag.get("verification"), "tag verification")
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        raise ValueError("GitHub API does not report valid PGP tag verification")
    verified_at = _time(verification.get("verified_at"), "verification.verified_at")
    # Verification can legitimately happen later, and must not substitute for
    # public availability. An impossible earlier verification is suspicious.
    if verified_at < tagged_time:
        raise ValueError("PGP verification predates tag creation")
    payload = verification.get("payload")
    signature = verification.get("signature")
    message = tag.get("message")
    if (not isinstance(payload, str) or not isinstance(signature, str)
            or not isinstance(message, str) or not payload
            or len(payload.encode("utf-8")) > MAX_JSON_BYTES
            or "-----BEGIN PGP SIGNATURE-----" not in signature
            or "-----END PGP SIGNATURE-----" not in signature
            or "-----BEGIN PGP SIGNATURE-----" not in message
            or "CVE-2024-21626" not in payload
            or "CVE-2024-21626" not in message):
        raise ValueError("Signed tag payload is absent, malformed or unrelated")
    # GitHub verification payload is not the raw Git object byte serialization.
    # Its digest is useful for comparing saved API responses, not as the SHA-256
    # of an independently archived original public CTI document.
    if (f"object {commit_sha}\ntype commit\ntag v1.1.12\n" not in payload):
        raise ValueError("PGP verification payload does not bind target commit and tag")
    return {
        "schema_version": CONTRACT,
        "status": "internally_consistent_upstream_api_witness_only",
        "release_tag": "v1.1.12",
        "release_page": RELEASE_PAGE,
        "official_release_api": RELEASE_API,
        "official_tag_reference_api": REF_API,
        "public_release_timestamp_observed": release["published_at"],
        "tagger_timestamp_observed": tagger["date"],
        "github_pgp_status": "api_reports_valid",
        "github_pgp_verified_at_observed": verification["verified_at"],
        "tag_object_git_sha1": tag_sha,
        "target_commit_git_sha1": commit_sha,
        "api_signed_payload_sha256": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
        "api_payload_digest_is_original_archived_source_sha256": False,
        "independent_release_date_verified": False,
        "raw_git_pgp_signature_reverified_locally": False,
        "exact_historical_public_source_bytes_verified": False,
        "reuse_rights_verified": False,
        "historical_available_at": None,
        "research_ready": False,
        "warning": (
            "Official API snapshots may be edited/fabricated locally. The reported PGP "
            "status is not local cryptographic verification. A signed Jan 23 tag "
            "does not prove it was public then, and today's release body is mutable. "
            "Do not promote a candidate without independent original-byte, "
            "availability, identity, rights and human-review evidence."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-json", required=True)
    parser.add_argument("--tag-ref-json", required=True)
    parser.add_argument("--tag-json", required=True)
    parser.add_argument("--cutoff", default=CUTOFF)
    args = parser.parse_args(argv)
    try:
        report = validate_witness(
            read_api_json(args.release_json),
            read_api_json(args.tag_ref_json),
            read_api_json(args.tag_json),
            cutoff=args.cutoff,
        )
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "witness_refused", "reason": str(exc)}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
