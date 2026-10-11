"""Offline GH Archive public GitHub PushEvent witness for a 2022 Cado-report pointer.

Required evidence: original complete GH Archive hour plus original Securonix
Git commit/tree/file bytes checked independently. This module only binds the
public-push event to that commit and time. It DOES NOT certify Cado's article
contents, original source availability, copyright or a reviewed CTI claim.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path

from scripts.verify_kissadog_cado_pointer import (
    COMMIT, REFERENCE_GIT_BLOB, IOC_GIT_BLOB,
    REFERENCE_PATH, IOC_PATH, verify_reference,
)
from scripts.verify_advisory_public_witness import git_object, verify_file_chain

SCHEMA = "kissadog-cado-pointer-gharchive-public-push-v1"
HOUR = "2022-12-23T11:"
REPO = "Securonix/AutonomousThreatSweeper"
REPO_ID = 359980821
CUTOFF = datetime(2023, 3, 1, tzinfo=timezone.utc)
MAX_COMPRESSED = 160 * 1024 * 1024
MAX_EVENT_LINE = 3 * 1024 * 1024
MAX_DECOMPRESSED = 3 * 1024 * 1024 * 1024
MAX_LINES = 1800000
# Pinned original 2022 GH Archive hourly bytes and public event line, first
# genuinely measured in live GitHub Actions run 38109864154.
ARCHIVE_SHA256 = "".join((
    "e13cf35c", "7bbc532d", "325f8297", "0064b91d",
    "d9041e81", "fc0b1bdd", "cdcb37fb", "f3bb60a6",
))
EVENT_LINE_SHA256 = "".join((
    "3d3506ad", "1a7a2eff", "ed5d969c", "b4f8fdcc",
    "4277acda", "c75dc49d", "8afff633", "b28d9b13",
))
PUBLIC_EVENT_ID = "26063265903"
PUBLIC_EVENT_AT = "2022-12-23T11:42:28Z"
ARCHIVE_BYTES = 73677982


def _require(value, message):
    if not value:
        raise ValueError(message)


def event_matches(event: dict) -> bool:
    """Reject near misses without claiming that a nonmatch proves no public event."""
    if not isinstance(event, dict):
        return False
    if (event.get("type") != "PushEvent" or event.get("public") is not True
            or not isinstance(event.get("id"), str)
            or not event["id"].isdigit()):
        return False
    repo = event.get("repo")
    if (not isinstance(repo, dict) or repo.get("id") != REPO_ID
            or repo.get("name") != REPO):
        return False
    payload = event.get("payload")
    if not isinstance(payload, dict):
        return False
    if payload.get("ref") != "refs/heads/main":
        return False
    if payload.get("head") != COMMIT:
        return False
    commits = payload.get("commits")
    if not isinstance(commits, list) or not any(
            isinstance(c, dict) and c.get("sha") == COMMIT for c in commits):
        return False
    when = event.get("created_at")
    if not isinstance(when, str) or not when.startswith(HOUR) or not when.endswith("Z"):
        return False
    try:
        stamp = datetime.strptime(when, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return stamp < CUTOFF


def _find_event(fp):
    """Single-pass gzip with bounded event lines; stream never emits raw content."""
    nbytes = 0
    count = 0
    matches = []
    with gzip.GzipFile(fileobj=fp, mode="rb") as stream:
        while True:
            raw = stream.readline(MAX_EVENT_LINE + 1)
            if not raw:
                break
            count += 1
            nbytes += len(raw)
            _require(count <= MAX_LINES and len(raw) <= MAX_EVENT_LINE
                     and nbytes <= MAX_DECOMPRESSED,
                     "Hourly event stream exceeds bounded limits")
            # Avoid parsing every event: the original repo name and target
            # commit must both appear; the complete JSON is verified below.
            if REPO.encode("ascii") not in raw or COMMIT.encode("ascii") not in raw:
                continue
            try:
                candidate = json.loads(raw)
            except (ValueError, UnicodeError, RecursionError) as exc:
                raise ValueError("Candidate public event is malformed JSON") from exc
            if event_matches(candidate):
                matches.append((hashlib.sha256(raw).hexdigest(), candidate))
                _require(len(matches) <= 1, "Ambiguous duplicate public-push matches")
    _require(bool(matches), "No exact target public-push event found in complete hour")
    digest, event = matches[0]
    return digest, event, count, nbytes


def verify_archive(archive: str | Path, *, pinned_archive_sha256: str | None = None,
                   require_original: bool = False, git_repo: str | Path | None = None) -> dict:
    path = Path(archive)
    _require(path.is_file() and not path.is_symlink()
             and 0 < path.stat().st_size <= MAX_COMPRESSED,
             "Require bounded complete regular GH Archive hourly file")
    if require_original:
        _require(pinned_archive_sha256 in (None, ARCHIVE_SHA256),
                 "Original pinned archive hash cannot be overridden")
        pinned_archive_sha256 = ARCHIVE_SHA256
    if pinned_archive_sha256 is not None:
        _require(len(pinned_archive_sha256) == 64
                 and all(c in "0123456789abcdef" for c in pinned_archive_sha256),
                 "Pinned GH Archive SHA-256 must be full lowercase hex")
    try:
        with path.open("rb") as fp:
            digest = hashlib.file_digest(fp, "sha256").hexdigest()
            _require(pinned_archive_sha256 is None or digest == pinned_archive_sha256,
                     "Complete hourly archive digest differs from pinned bytes")
            fp.seek(0)
            event_sha, event, count, uncompressed = _find_event(fp)
    except (OSError, gzip.BadGzipFile, EOFError, OverflowError) as exc:
        raise ValueError("Unable to fully read authentic-format gzip archive") from exc
    if require_original:
        _require(digest == ARCHIVE_SHA256 and path.stat().st_size == ARCHIVE_BYTES
                 and event_sha == EVENT_LINE_SHA256
                 and event["id"] == PUBLIC_EVENT_ID
                 and event["created_at"] == PUBLIC_EVENT_AT,
                 "Original retained archive/event identity mismatch")
    checked_objects = 0
    if git_repo is not None:
        repo = Path(git_repo)
        _require(not repo.is_symlink() and repo.is_dir(),
                 "Pinned Git object repository missing")
        read_object = lambda kind, oid: git_object(repo, kind, oid)
        ref_bytes, count_a = verify_file_chain(
            read_object, COMMIT, REFERENCE_PATH, REFERENCE_GIT_BLOB
        )
        ioc_bytes, count_b = verify_file_chain(
            read_object, COMMIT, IOC_PATH, IOC_GIT_BLOB
        )
        verify_reference(ref_bytes, ioc_bytes)
        checked_objects = count_a + count_b
    return {
        "schema_version": SCHEMA,
        "status": "third_party_gharchive_public_push_event_found_candidate_only",
        "archived_hour_url": "https://data.gharchive.org/2022-12-23-11.json.gz",
        "archive_sha256": digest,
        "archive_sha256_frozen_in_source": require_original,
        "exact_original_event_id_and_line_sha256_verified": require_original,
        "archive_compressed_byte_count": path.stat().st_size,
        "parsed_event_count": count,
        "uncompressed_byte_count": uncompressed,
        "public_event_id": event["id"],
        "public_event_created_at": event["created_at"],
        "event_line_sha256": event_sha,
        "repo": REPO,
        "repository_id": REPO_ID,
        "commit": COMMIT,
        "branch": "refs/heads/main",
        "pinned_reference_blob_git_sha1": REFERENCE_GIT_BLOB,
        "pinned_derivative_ioc_blob_git_sha1": IOC_GIT_BLOB,
        "independent_public_push_event_found": True,
        "historical_pointer_git_tree_chain_verified_in_this_replay": git_repo is not None,
        "original_git_objects_checked_including_paths": checked_objects,
        "historical_cado_article_body_verifiable_from_event": False,
        "original_cado_report_public_by_verified": False,
        "copyright_and_use_rights_approved": False,
        "independent_semantic_campaign_claim_verified": False,
        "source_version_approved": False,
        "g1_evaluation_eligible": False,
        "research_ready": False,
        "limitation": (
            "GH Archive recorded a public GitHub PushEvent for the Securonix pointer "
            "commit; archive integrity and event authenticity still require external "
            "review. Git commit/ref and Git blob evidence are separately pinned, "
            "but this event does not bind to Cado's original research body."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--pinned-archive-sha256")
    parser.add_argument("--require-original", action="store_true",
                        help="Enforce original hour SHA-256, event hash/ID/time and byte length")
    parser.add_argument("--git-repo", help="Local bare Git repository containing original pushed commit/tree/blob objects")
    args = parser.parse_args(argv)
    try:
        receipt = verify_archive(args.archive, pinned_archive_sha256=args.pinned_archive_sha256,
                                 require_original=args.require_original, git_repo=args.git_repo)
    except (ValueError, TypeError, OSError) as exc:
        print(json.dumps({"status": "historical_pointer_push_witness_refused",
                          "reason": str(exc)[:400], "research_ready": False}, sort_keys=True))
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
