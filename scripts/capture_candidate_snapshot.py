#!/usr/bin/env python3
"""Preserve exact manually acquired candidate bytes privately; NEVER approve them.

The supplied file may be downloaded *today*, even if the page says "2024".
Only the local import time and SHA-256 byte identity are established here.
No HTTP fetching, HTML normalization, code execution or research approval.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sys

DEFAULT_ROOT = "artifacts/source_versions/sha256"
MAX_BYTES = 4 * 1024 * 1024
SHA256 = re.compile(r"^[0-9a-f]{64}$")
RECEIPT_VERSION = "candidate-byte-capture-v1"


def _safe_dir(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("Artifact storage directory may not be a symlink")
    if path.exists() and not path.is_dir():
        raise ValueError("Artifact storage path is not a directory")
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError("Artifact storage directory may not be a symlink")


def _bounded_bytes(path: Path, *, limit: int) -> bytes:
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        raise ValueError("Invalid file-size cap")
    if path.is_symlink() or not path.is_file():
        raise ValueError("Input must be an existing regular non-symlink file")
    if path.stat().st_size > limit:
        raise ValueError("Candidate file exceeds size limit")
    with path.open("rb") as fp:
        data = fp.read(limit + 1)
    if not data or len(data) > limit:
        raise ValueError("Candidate file empty or exceeds size limit")
    return data


def _candidate_record(manifest: dict, source_version_id: str) -> dict:
    if not isinstance(manifest, dict) or not isinstance(manifest.get("sources"), list):
        raise ValueError("Invalid candidate source registry")
    if not isinstance(source_version_id, str) or not source_version_id:
        raise ValueError("source_version_id required")
    matched = [
        row for row in manifest["sources"]
        if isinstance(row, dict) and row.get("source_version_id") == source_version_id
    ]
    if len(matched) != 1:
        raise ValueError("Source version must uniquely match candidate registry")
    row = matched[0]
    if (row.get("status") != "candidate" or row.get("available_at") is not None
            or row.get("sha256") is not None or row.get("date_confidence") != "unknown"):
        raise ValueError("Only undated, unapproved candidate versions can be captured")
    for key in ("url", "source_id", "source_version_id"):
        if not isinstance(row.get(key), str) or not row[key].strip():
            raise ValueError("Candidate identity or canonical source URL missing")
    if not row["url"].startswith("https://"):
        raise ValueError("Candidate origin must be HTTPS")
    return row


def capture_candidate(
    manifest: dict, source_version_id: str, input_file: str | Path,
    root: str | Path = DEFAULT_ROOT, *, now: datetime | None = None,
    max_bytes: int = MAX_BYTES,
) -> dict:
    row = _candidate_record(manifest, source_version_id)
    data = _bounded_bytes(Path(input_file), limit=max_bytes)
    digest = hashlib.sha256(data).hexdigest()
    if not SHA256.fullmatch(digest):
        raise ValueError("Invalid computed digest")
    root = Path(root).expanduser()
    _safe_dir(root)
    bucket = root / digest[:2]
    _safe_dir(bucket)
    archive = bucket / digest
    if archive.is_symlink():
        raise ValueError("Archived content address must not be a symlink")
    if archive.exists():
        if _bounded_bytes(archive, limit=max_bytes) != data:
            raise ValueError("Existing source archive is corrupt; refusing overwrite")
    else:
        try:
            with archive.open("xb") as fp:
                fp.write(data)
        except FileExistsError:
            if _bounded_bytes(archive, limit=max_bytes) != data:
                raise ValueError("Archive path changed during capture") from None
    timestamp = now if now is not None else datetime.now(timezone.utc)
    if not isinstance(timestamp, datetime) or timestamp.tzinfo is None:
        raise ValueError("Capture time must be an aware datetime")
    stamp = timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    receipt = {
        "schema_version": RECEIPT_VERSION,
        "status": "candidate_bytes_collected_not_historically_approved",
        "source_version_id": source_version_id,
        "source_id": row["source_id"],
        "declared_origin_url": row["url"],
        "acquisition_method": "investigator_supplied_local_file",
        "local_imported_at_utc": stamp,
        "captured_sha256": digest,
        "captured_bytes": len(data),
        "content_addressed_relative_path": f"{digest[:2]}/{digest}",
        "historical_available_at": None,
        "source_revision_verified": False,
        "source_rights_verified": False,
        "research_ready": False,
        "warning": (
            "Source origin and historic availability of these exact bytes are NOT "
            "authenticated by the local filename, current HTML, publication label, "
            "or hash. Keep private; do not promote to approved or run B0/G1."
        ),
    }
    # Receipts are ignored/private and immutable. One per source-version/digest.
    receipt_dir = root.parent / "candidate_capture_receipts"
    _safe_dir(receipt_dir)
    key = hashlib.sha256(source_version_id.encode("utf-8")).hexdigest()[:12]
    dest = receipt_dir / f"{digest}-{key}.json"
    if dest.is_symlink():
        raise ValueError("Receipt must not be a symlink")
    if dest.exists():
        with dest.open(encoding="utf-8") as stream:
            prior = json.load(stream)
        if (not isinstance(prior, dict)
                or prior.get("source_version_id") != source_version_id
                or prior.get("captured_sha256") != digest
                or prior.get("status") != receipt["status"]
                or prior.get("research_ready") is not False):
            raise ValueError("Existing capture receipt is incompatible")
        return prior
    try:
        with dest.open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, indent=2, sort_keys=True)
            stream.write("\n")
    except FileExistsError:
        raise ValueError("Concurrent capture receipt creation; retry and verify") from None
    return receipt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default="datasets/manifests/pilot.json")
    parser.add_argument("--source-version-id", required=True)
    parser.add_argument("--input-file", required=True, help="Existing locally downloaded bytes; no network fetch")
    parser.add_argument("--artifact-root", default=DEFAULT_ROOT)
    args = parser.parse_args(argv)
    try:
        file = Path(args.manifest)
        if file.is_symlink() or file.stat().st_size > 2 * 1024 * 1024:
            raise ValueError("Unsafe or oversized source registry")
        with file.open(encoding="utf-8") as stream:
            manifest = json.load(stream)
        receipt = capture_candidate(
            manifest, args.source_version_id, args.input_file, args.artifact_root
        )
    except (ValueError, OSError, json.JSONDecodeError, UnicodeError) as exc:
        print(json.dumps({"status": "capture_refused", "reason": str(exc)}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
