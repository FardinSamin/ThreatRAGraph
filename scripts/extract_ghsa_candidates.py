"""Offline CLI: bounded, hash-pinned GHSA JSON -> unapproved review candidates.

This does not date, approve, publish, label or insert a source or claim.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.threatragraph.ghsa_candidates import MAX_SOURCE_BYTES, extract_ghsa_candidates


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-file", required=True, help="Permitted privately archived GHSA JSON bytes")
    parser.add_argument("--source-version-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        path = Path(args.input_file)
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_SOURCE_BYTES:
            raise ValueError("Source must be a bounded regular nonsymlink file")
        with path.open("rb") as handle:
            raw = handle.read(MAX_SOURCE_BYTES + 1)
        result = extract_ghsa_candidates(
            raw, source_version_id=args.source_version_id,
            expected_sha256=args.expected_sha256,
        )
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({
            "status": "candidate_extraction_refused",
            "reason": str(exc),
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
