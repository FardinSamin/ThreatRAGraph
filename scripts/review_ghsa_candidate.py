"""Offline verified GHSA two-field review packet and isolated attestation CLI.

No source approval, sourced_claims or semantic_reviews insertion, web or cloud.
"""
from __future__ import annotations

from contextlib import closing
import argparse
import json
from pathlib import Path
import sqlite3

from src.threatragraph.ghsa_candidates import (
    MAX_SOURCE_BYTES, _no_duplicate_keys, _no_nonfinite,
)
from src.threatragraph.ghsa_review_packets import (
    CompoundCandidateReviewLedger, build_packet,
)

MAX_REVIEW_FILE = 16 * 1024


def bounded_file(path_text: str, limit: int) -> bytes:
    path = Path(path_text)
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("Require existing bounded regular nonsymlink input")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if not 0 < len(raw) <= limit:
        raise ValueError("Unbounded or empty input file")
    return raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-file", required=True)
    parser.add_argument("--source-version-id", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--candidate-id", required=True)
    parser.add_argument("--review-file", help="Human-declared review JSON; optional")
    parser.add_argument("--database", help="Separate local candidate-review SQLite store")
    args = parser.parse_args(argv)
    try:
        if bool(args.review_file) != bool(args.database):
            raise ValueError("Review and database must be explicitly provided together")
        raw = bounded_file(args.input_file, MAX_SOURCE_BYTES)
        packet = build_packet(
            raw, source_version_id=args.source_version_id,
            expected_sha256=args.expected_sha256, candidate_id=args.candidate_id,
        )
        if args.review_file:
            review = json.loads(
                bounded_file(args.review_file, MAX_REVIEW_FILE).decode("utf-8"),
                object_pairs_hook=_no_duplicate_keys, parse_constant=_no_nonfinite,
            )
            path = Path(args.database)
            if path.is_symlink() or (path.exists() and not path.is_file()):
                raise ValueError("Review database must be a regular nonsymlink file")
            with closing(sqlite3.connect(path)) as conn:
                result = CompoundCandidateReviewLedger(conn).record(
                    raw, source_version_id=args.source_version_id,
                    expected_sha256=args.expected_sha256,
                    candidate_id=args.candidate_id, review=review,
                )
        else:
            result = packet
    except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError,
            sqlite3.Error) as exc:
        print(json.dumps({
            "status": "compound_review_refused",
            "reason": str(exc), "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
