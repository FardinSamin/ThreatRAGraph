#!/usr/bin/env python3
"""Offline JSON/CSV graph exchange; neither import nor export modifies SQLite."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from scripts.freeze_case_snapshots import write_immutable_view
from src.threatragraph.portable_exchange import (
    create_bundle, export_claims_csv, parse_bundle_json, verify_bundle,
    verify_claims_csv,
)

MAX_INPUT = 8 * 1024 * 1024


def _unique_fields(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate input JSON key")
        obj[key] = value
    return obj


def _read_text(path):
    file = Path(path)
    if file.is_symlink() or not file.is_file():
        raise ValueError("Local regular non-symlink file required")
    if not 0 < file.stat().st_size <= MAX_INPUT:
        raise ValueError("Empty or oversized exchange input")
    return file.read_text(encoding="utf-8")


def _read_json(path):
    record = json.loads(_read_text(path), object_pairs_hook=_unique_fields)
    if not isinstance(record, dict):
        raise ValueError("JSON root must be an object")
    return record


def _write_csv(content, output_dir):
    root = Path(output_dir)
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise ValueError("Unsafe exchange output directory")
    root.mkdir(parents=True, exist_ok=True)
    data = content.encode("utf-8")
    digest = hashlib.sha256(data).hexdigest()
    dest = root / (digest + ".csv")
    if dest.is_symlink():
        raise ValueError("Linked export output forbidden")
    if dest.exists():
        if not dest.is_file() or dest.read_bytes() != data:
            raise ValueError("Existing export no longer matches exact bytes")
        return digest, dest, False
    try:
        with dest.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if dest.is_symlink() or not dest.is_file() or dest.read_bytes() != data:
            raise ValueError("Concurrent CSV export is different")
        return digest, dest, False
    return digest, dest, True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", required=True, choices=("export", "verify"))
    parser.add_argument("--view")
    parser.add_argument("--graph")
    parser.add_argument("--reviewed", action="store_true")
    parser.add_argument("--bundle")
    parser.add_argument("--csv")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--output-dir", default="artifacts/portable_exchange")
    args = parser.parse_args(argv)
    try:
        if args.mode == "export":
            if not args.view or not args.graph or args.bundle or args.csv:
                raise ValueError("Export requires only view and graph JSON")
            bundle = create_bundle(
                _read_json(args.view), _read_json(args.graph),
                reviewed=args.reviewed,
            )
            csv_data = export_claims_csv(bundle)
            receipt = verify_claims_csv(csv_data, bundle)
            result = {
                "status": "portable_export_preview",
                "bundle_id": bundle["bundle_id"],
                "claim_count": receipt["claim_count"],
                "csv_sha256": receipt["csv_sha256"],
            }
            if args.write:
                sha, path, _ = write_immutable_view(bundle, args.output_dir)
                csv_sha, csv_file, _ = _write_csv(csv_data, args.output_dir)
                result.update({
                    "status": "portable_export_written",
                    "bundle_sha256": sha, "bundle_path": str(path),
                    "csv_sha256": csv_sha, "csv_path": str(csv_file),
                })
        else:
            if (not args.bundle or args.view or args.graph
                    or args.reviewed or args.write):
                raise ValueError("Verification requires a bundle, optional CSV")
            bundle = parse_bundle_json(_read_text(args.bundle))
            receipt = (verify_claims_csv(_read_text(args.csv), bundle)
                       if args.csv else verify_bundle(bundle))
            result = {
                "status": "portable_exchange_verified",
                "bundle_id": receipt["bundle_id"],
                "claim_count": receipt["claim_count"],
                "csv_verified": bool(args.csv),
            }
        result["research_ready"] = False
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            RecursionError, UnicodeError, json.JSONDecodeError) as exc:
        print(json.dumps({
            "status": "portable_exchange_refused",
            "reason_category": type(exc).__name__,
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
