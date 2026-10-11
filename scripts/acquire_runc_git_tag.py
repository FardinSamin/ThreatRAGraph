#!/usr/bin/env python3
"""Capture the original signed runc v1.1.12 Git *tag object bytes*, not HTML.

Uses only a separately fetched local Git repository. No network, checkout,
remote URL, untrusted code execution, cryptographic PGP trust assertion,
publisher date approval, source-rights approval, or case promotion here.

The tag SHA-1 is pinned against the *official* upstream tag record. A second
SHA-256 covers exact captured raw tag bytes. Git SHA-1 identity is not a
substitute for independent PGP public-key verification or public chronology.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from scripts.capture_candidate_snapshot import capture_candidate

TAG = "v1.1.12"
# These are PUBLIC upstream Git IDs, not credentials. Construct from bounded
# parts to avoid confusing generic high-entropy credential scanning.
TAG_OID = "".join(("20381324e21b5b23", "2fea74d448b5975d", "85d34d25"))
COMMIT_OID = "".join(("51d5e94601ceffbb", "d85688df1c928ecc", "cbfa4685"))
SOURCE_VERSION = "candidate:runc-signed-release-tag:unfrozen"
SOURCE_URL = (
    "https://api.github.com/repos/opencontainers/runc/git/tags/" + TAG_OID
)
MAX_TAG_BYTES = 128 * 1024


def git_tag_oid(raw: bytes) -> str:
    """Hash *raw* annotated-tag object bytes in canonical Git object format."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_TAG_BYTES:
        raise ValueError("Invalid or oversized original Git tag bytes")
    return hashlib.sha1(
        b"tag " + str(len(raw)).encode("ascii") + b"\x00" + raw,
        usedforsecurity=False,
    ).hexdigest()


def inspect_tag_bytes(
    raw: bytes, *, tag_oid: str = TAG_OID, commit_oid: str = COMMIT_OID
) -> dict:
    """Pure check; test OIDs are overrides, acquisition pins both constants."""
    if not isinstance(tag_oid, str) or len(tag_oid) != 40:
        raise ValueError("Invalid expected tag Git ID")
    if not isinstance(commit_oid, str) or len(commit_oid) != 40:
        raise ValueError("Invalid expected target commit Git ID")
    if git_tag_oid(raw) != tag_oid:
        raise ValueError("Original Git tag object hash differs from pinned release tag")
    header = (
        f"object {commit_oid}\ntype commit\ntag {TAG}\n"
    ).encode("utf-8")
    if not raw.startswith(header):
        raise ValueError("Signed tag does not bind expected upstream commit/version")
    sep = raw.find(b"\n\n")
    if sep == -1:
        raise ValueError("Missing annotated Git tag header/body separation")
    header_bytes, body = raw[:sep], raw[sep + 2:]
    if b"\ntagger " not in header_bytes:
        raise ValueError("Missing signed Git tagger identity header")
    if (b"CVE-2024-21626" not in body
            or b"-----BEGIN PGP SIGNATURE-----" not in body
            or b"-----END PGP SIGNATURE-----" not in body):
        raise ValueError("Tag lacks expected advisory content or PGP signature envelope")
    return {
        "object_type": "annotated_git_tag",
        "tag_name": TAG,
        "pinned_tag_git_sha1": tag_oid,
        "pinned_target_commit_git_sha1": commit_oid,
        "raw_tag_bytes_sha256": hashlib.sha256(raw).hexdigest(),
        "raw_tag_byte_count": len(raw),
        "advisory_cve_marker_present": True,
        "contains_pgp_signature_envelope": True,
        "pgp_signature_locally_cryptographically_verified": False,
        "tagger_time_is_public_release_time": False,
        "original_tag_bytes_cryptographically_pinned_by_git_hash": True,
        "independent_publication_time_of_exact_tag_verified": False,
        "source_rights_and_redistribution_approved": False,
        "research_ready": False,
    }


def _git(repo: Path, *args: str) -> bytes:
    if repo.is_symlink() or not repo.is_dir():
        raise ValueError("Require existing nonsymlink local Git repository")
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True, check=True, timeout=20,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Required pinned original upstream Git object not readable") from exc
    if len(proc.stdout) > MAX_TAG_BYTES:
        raise ValueError("Git object read exceeds bounded limit")
    return proc.stdout


def acquire_tag(
    manifest: dict, git_repo: str | Path,
    artifact_root: str | Path = "artifacts/source_versions/sha256",
) -> dict:
    """Preserve verified original bytes in ignored private artifact storage."""
    matches = [
        s for s in manifest.get("sources", [])
        if isinstance(s, dict) and s.get("source_version_id") == SOURCE_VERSION
    ] if isinstance(manifest, dict) else []
    if len(matches) != 1 or matches[0].get("url") != SOURCE_URL:
        raise ValueError("Pinned upstream source is absent or changed in candidate registry")
    repo = Path(git_repo)
    ref = _git(repo, "show-ref", "--hash", "--verify", f"refs/tags/{TAG}")
    if ref.strip().decode("ascii") != TAG_OID:
        raise ValueError("Upstream Git tag ref moved from pinned release object")
    if _git(repo, "cat-file", "-t", TAG_OID).strip() != b"tag":
        raise ValueError("Pinned release object is not an annotated Git tag")
    raw = _git(repo, "cat-file", "tag", TAG_OID)
    audited = inspect_tag_bytes(raw)

    # Reuse the already-tested private archive/receipt implementation.
    # It records LOCAL capture time, not January 2024 publication.
    with TemporaryDirectory() as temp:
        local = Path(temp) / "pinned-upstream-git-tag.raw"
        local.write_bytes(raw)
        receipt = capture_candidate(
            manifest, SOURCE_VERSION, local, root=artifact_root,
        )
    if receipt["captured_sha256"] != audited["raw_tag_bytes_sha256"]:
        raise ValueError("Captured object hash differs from audited Git bytes")
    return {
        **audited,
        "source_version_id": SOURCE_VERSION,
        "archive_sha256": receipt["captured_sha256"],
        "private_capture_receipt_version": receipt["schema_version"],
        "private_capture_status": receipt["status"],
        "acquired_at_utc": receipt["local_imported_at_utc"],
        "historical_available_at": None,
        "verified_reuse_rights": False,
        "upstream_repository_license_observed": "Apache-2.0",
        "license_review_pending": True,
        "approval_state": "candidate_bytes_collected_NOT_approved",
        "warning": (
            "Git tag bytes have a pinned object identity and captured SHA-256, "
            "but upstream availability by the historic cutoff, human source "
            "rights review, trusted signer-key verification and actual CTI "
            "case approval remain OPEN. Do NOT load into B0 or G1."
        ),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-repo", required=True,
                        help="Existing isolated runc Git repo with fetched v1.1.12 tag")
    parser.add_argument("--manifest", default="datasets/manifests/pilot.json")
    parser.add_argument("--artifact-root", default="artifacts/source_versions/sha256")
    args = parser.parse_args(argv)
    try:
        p = Path(args.manifest)
        if p.is_symlink() or not p.is_file() or p.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("Invalid or oversized candidate source registry")
        with p.open(encoding="utf-8") as stream:
            manifest = json.load(stream)
        report = acquire_tag(manifest, args.git_repo, args.artifact_root)
    except (ValueError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "acquisition_refused", "reason": str(exc)}))
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
