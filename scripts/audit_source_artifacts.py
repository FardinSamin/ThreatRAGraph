#!/usr/bin/env python3
"""Offline integrity audit of exact source versions used by ThreatRAGraph.

Source content is stored privately under a content-addressed folder:
    <artifact-root>/<first-2-sha256-characters>/<full-sha256>
This tool performs **byte-integrity**, not historical publication-date verification.
It makes no network calls, writes no files, and never logs source bytes.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

SHA256 = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_ROOT = "artifacts/source_versions/sha256"


def sha256_file(path, max_bytes):
    """Hash bytes in bounded chunks; reject files exceeding the permitted limit."""
    sha = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("source version exceeds configured size limit")
            sha.update(chunk)
    return sha.hexdigest(), total


def audit_sources(manifest, root, require_all=False, max_bytes=50 * 1024 * 1024):
    """Return report, errors, warnings. A missing draft archive is not approval."""
    errors, warnings = [], []
    report = {
        "status": "unverified", "approved": 0, "verified_bytes": 0,
        "missing_bytes": 0, "mismatched_bytes": 0, "candidate_sources": 0,
        "checked": [], "scope": "local byte integrity ONLY",
    }
    if not isinstance(manifest, dict) or not isinstance(manifest.get("sources"), list):
        return report, ["manifest.sources must be an array"], warnings
    if max_bytes < 1:
        return report, ["max_bytes must be positive"], warnings

    root = Path(root).expanduser()
    if root.is_symlink():
        return report, ["artifact root may not be a symlink"], warnings
    if root.exists() and not root.is_dir():
        return report, ["artifact root must be a directory"], warnings

    records = manifest["sources"]
    # Never allow a filename from an untrusted manifest to form a path.
    by_digest = {}

    for i, item in enumerate(records):
        where = f"sources[{i}]"
        if not isinstance(item, dict):
            errors.append(f"{where}: object expected")
            continue
        status = item.get("status")
        if status != "approved":
            report["candidate_sources"] += 1
            continue

        report["approved"] += 1
        version = item.get("source_version_id")
        if not isinstance(version, str) or not version.strip():
            errors.append(f"{where}: approved source has no stable version ID")
            continue
        digest = item.get("sha256")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            errors.append(f"{where}: approved source has invalid SHA-256")
            continue

        if digest in by_digest and by_digest[digest] != version:
            warnings.append(
                f"{where}: same archived content as version {by_digest[digest]}; "
                "verify source independence"
            )
        else:
            by_digest[digest] = version

        path = root / digest[:2] / digest
        record = {"source_version_id": version, "sha256": digest}
        # pathlib.exists() may follow links; explicitly forbid symlink components.
        if (root / digest[:2]).is_symlink() or path.is_symlink():
            errors.append(f"{where}: content-addressed path contains a symlink")
            record["result"] = "unsafe_symlink"
        elif not path.is_file():
            report["missing_bytes"] += 1
            record["result"] = "missing"
            if require_all:
                errors.append(f"{where}: approved source archive not found")
            else:
                warnings.append(f"{where}: approved source archive not available locally")
        else:
            try:
                actual, size = sha256_file(path, max_bytes=max_bytes)
            except (OSError, ValueError) as exc:
                record["result"] = "unreadable_or_oversized"
                errors.append(f"{where}: cannot safely hash archived source: {type(exc).__name__}")
            else:
                record["bytes"] = size
                if actual != digest:
                    report["mismatched_bytes"] += 1
                    record["result"] = "sha256_mismatch"
                    errors.append(f"{where}: on-disk archived source bytes mismatch expected SHA-256")
                else:
                    record["result"] = "verified"
                    report["verified_bytes"] += 1
        report["checked"].append(record)

    if report["approved"] == 0:
        warnings.append("No approved sources yet; integrity verification has not been demonstrated")
    report["status"] = "invalid" if errors else (
        "verified_all" if report["approved"] > 0 and report["missing_bytes"] == 0
        else "incomplete"
    )
    return report, errors, warnings


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", help="JSON source-version registry")
    parser.add_argument("--artifact-root", default=DEFAULT_ROOT,
                        help="Directory of content-addressed source copies (never uploaded)")
    parser.add_argument("--require-all", action="store_true",
                        help="Fail unless EVERY approved source has matching local bytes")
    parser.add_argument("--max-file-mib", type=int, default=50,
                        help="Maximum allowed size of one archived version")
    args = parser.parse_args(argv)
    try:
        path = Path(args.manifest)
        if path.stat().st_size > 5 * 1024 * 1024:
            raise ValueError("source manifest too large")
        with path.open(encoding="utf-8") as stream:
            manifest = json.load(stream)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(json.dumps({"status": "read_error", "error_type": type(exc).__name__}))
        return 1

    report, errors, warnings = audit_sources(
        manifest, args.artifact_root,
        require_all=args.require_all,
        max_bytes=args.max_file_mib * 1024 * 1024,
    )
    report["errors"], report["warnings"] = errors, warnings
    print(json.dumps(report, indent=2))
    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
