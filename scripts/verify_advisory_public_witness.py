"""Offline replay of the pinned GH Archive witness for the original runc GHSA.

No acquisition, promotion, source approval or claim of a cryptographic timestamp.
Supply the complete original hourly archive and already materialized Git objects.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

# Public evidence identities, never credentials; use the existing short-chunk convention.
COMMIT = "".join(("02a8b9a4", "f9d305f0", "e028ef58", "f0dcf28f", "55bf10ae"))

BLOB = "".join(("2a90e030", "e322bd49", "c4b3f434", "10867428", "e474fa48"))

SOURCE_SHA256 = "".join(("e13a3fd3", "7dc98874", "e6e942d3", "237660a6", "4e7310a7", "757427ee", "60953e76", "a9f6f4a2"))

ARCHIVE_SHA256 = "".join(("0d888a72", "5800cdf7", "786a4e63", "2ad742e8", "9186f380", "317c5be4", "f290c017", "70de1021"))

EVENT_SHA256 = "".join(("291d4337", "4d69d248", "5024bca0", "5f2e9c9a", "dcbf0714", "6e2a779d", "1df4e76a", "22783e92"))

SOURCE_PATH = "advisories/github-reviewed/2024/01/GHSA-xr7r-f8xq-vfvv/GHSA-xr7r-f8xq-vfvv.json"
EVENT_TIME = "2024-01-31T22:46:10Z"
EVENT_LINE = 163762
MAX_OBJECT = 16 * 1024 ** 2


def require(condition, message):
    if not condition:
        raise ValueError(message)


def git_object(repo, kind, oid):
    require(kind in {"commit", "tree", "blob"} and re.fullmatch(r"[0-9a-f]{40}", oid),
            "Invalid Git object request")
    env = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0",
           "GIT_NO_REPLACE_OBJECTS": "1"}
    command = ["git", "-c", "protocol.allow=never", "-C", str(repo), "cat-file"]
    try:
        size = subprocess.run([*command, "-s", oid], env=env, capture_output=True,
                              check=True, timeout=20).stdout
        require(0 < int(size) <= MAX_OBJECT, "Unbounded or empty Git object")
        raw = subprocess.run([*command, kind, oid], env=env, capture_output=True,
                             check=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("Required local Git object unavailable; materialize it before offline replay") from exc
    require(len(raw) == int(size), "Git object size changed")
    actual = hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw,
                          usedforsecurity=False).hexdigest()
    require(actual == oid, "Git object identity mismatch")
    return raw


def verify_file_chain(read_object, commit_id, path, blob_id):
    commit = read_object("commit", commit_id)
    require(commit.startswith(b"tree "), "Commit lacks root tree")
    tree_id = commit.split(b"\n", 1)[0][5:].decode("ascii")
    parts = path.split("/")
    require(all(p and p not in {".", ".."} for p in parts), "Invalid source path")
    count = 1
    for depth, part in enumerate(parts):
        raw = read_object("tree", tree_id)
        count += 1
        matches, pos = [], 0
        while pos < len(raw):
            stop = raw.find(b"\0", pos)
            require(stop >= 0 and stop + 21 <= len(raw), "Truncated Git tree")
            entry = raw[pos:stop].split(b" ", 1)
            require(len(entry) == 2, "Malformed Git tree entry")
            mode, name = entry
            oid = raw[stop + 1:stop + 21].hex()
            if name == part.encode("utf-8"):
                matches.append((mode, oid))
            pos = stop + 21
        require(len(matches) == 1, "Missing or duplicate source path component")
        mode, oid = matches[0]
        if depth < len(parts) - 1:
            require(mode == b"40000", "Source parent is not a directory")
            tree_id = oid
        else:
            require(mode == b"100644" and oid == blob_id, "Source file identity or mode mismatch")
            return read_object("blob", oid), count + 1


def read_event(archive, archive_sha=ARCHIVE_SHA256, line_number=EVENT_LINE, event_sha=EVENT_SHA256):
    path = Path(archive)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 250 * 1024 ** 2,
            "Require bounded regular archive")
    require(type(line_number) is int and 1 <= line_number <= 250000, "Invalid event line")
    # Hash and decompress the same opened file, avoiding a path-replacement gap.
    with path.open("rb") as compressed:
        digest = hashlib.file_digest(compressed, "sha256").hexdigest()
        require(digest == archive_sha, "Hourly archive hash mismatch")
        compressed.seek(0)
        total = 0
        with gzip.GzipFile(fileobj=compressed) as stream:
            for _ in range(line_number):
                raw = stream.readline(MAX_OBJECT + 1)
                total += len(raw)
                require(raw and len(raw) <= MAX_OBJECT and total <= 2 * 1024 ** 3,
                        "Missing or unbounded event record")
    require(hashlib.sha256(raw).hexdigest() == event_sha, "Event line hash mismatch")
    return json.loads(raw)


def verify_event(event, cutoff):
    require(isinstance(cutoff, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", cutoff),
            "Cutoff must be exact UTC seconds")
    require(isinstance(event, dict), "Event must be an object")
    repo, payload = event.get("repo"), event.get("payload")
    require(isinstance(repo, dict) and isinstance(payload, dict), "Missing event metadata")
    require(event.get("id") == "35293494004" and event.get("type") == "PushEvent"
            and event.get("public") is True and event.get("created_at") == EVENT_TIME,
            "Wrong, private or re-dated event")
    require(repo.get("name") == "github/advisory-database" and repo.get("id") == 458364565,
            "Wrong public repository")
    require(payload.get("head") == COMMIT and payload.get("ref") == "refs/heads/main",
            "Event does not bind pinned main commit")
    commits = payload.get("commits")
    require(isinstance(commits, list) and any(isinstance(c, dict) and c.get("sha") == COMMIT for c in commits),
            "Pinned commit missing from public push")
    require(datetime.fromisoformat(EVENT_TIME) < datetime.fromisoformat(cutoff),
            "Public event is not before proposed cutoff")


def verify(archive, git_repo, cutoff="2024-02-01T00:00:00Z"):
    verify_event(read_event(archive), cutoff)
    read = lambda kind, oid: git_object(git_repo, kind, oid)
    raw, count = verify_file_chain(read, COMMIT, SOURCE_PATH, BLOB)
    require(len(raw) == 13105 and hashlib.sha256(raw).hexdigest() == SOURCE_SHA256,
            "Original advisory bytes mismatch")
    license_blob = "".join(("4ea99c21", "3c5c0c00", "5ae4e80d", "f8e52169", "d06896ec"))

    readme_blob = "".join(("9041b771", "16cf3a7f", "c3e13317", "ec53a553", "c1793487"))

    verify_file_chain(read, COMMIT, "LICENSE.md", license_blob)
    verify_file_chain(read, COMMIT, "README.md", readme_blob)
    return {
        "schema_version": "advisory-public-witness-v1",
        "status": "pinned_public_event_and_source_bytes_verified",
        "source_version_id": "candidate:runc-ghsa-original:20240131",
        "commit": COMMIT, "git_blob_sha1": BLOB, "source_sha256": SOURCE_SHA256,
        "source_byte_count": len(raw), "advisory_git_objects_verified": count,
        "archive_sha256": ARCHIVE_SHA256, "event_line_sha256": EVENT_SHA256,
        "event_id": "35293494004", "proposed_public_by_utc": EVENT_TIME,
        "proposed_cutoff_utc": cutoff, "observed_repository_license": "CC-BY-4.0",
        "historical_timing_basis": "GitHub server event retained by GH Archive; requires reviewer acceptance",
        "independence_group": "runc-maintainer-releases",
        "first_ever_publication_proven": False, "cryptographic_timestamp_verified": False,
        "exact_signed_tag_publication_proven": False,
        "rights_review_approved": False, "source_approved": False, "research_ready": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--git-repo", required=True)
    parser.add_argument("--cutoff", default="2024-02-01T00:00:00Z")
    args = parser.parse_args(argv)
    try:
        report = verify(args.archive, args.git_repo, args.cutoff)
    except (ValueError, OSError, EOFError) as exc:
        print(json.dumps({"status": "witness_refused", "reason": str(exc), "research_ready": False}))
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
