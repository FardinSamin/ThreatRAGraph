#!/usr/bin/env python3
"""Create deterministic, separated *source-level* historical research inputs.

No source text or held-out reference identities go into profiler-facing views.
This is NOT a claim/embedding/model-level time-leakage solution.
Dry-run is the default. Writing requires strict corpus readiness and matching
locally archived source bytes, with no network calls or cloud costs.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from scripts.audit_source_artifacts import audit_sources
from scripts.validate_research_manifests import load_json, validate

SCHEMA_VERSION = "1.0"
DEFAULT_OUTPUT = "artifacts/snapshots"
DEFAULT_ARCHIVES = "artifacts/source_versions/sha256"


def canonical_bytes(record):
    """Reproducible bytes across processes and insertion order of JSON keys."""
    return (json.dumps(
        record, sort_keys=True, ensure_ascii=False,
        separators=(",", ":"), allow_nan=False
    ) + "\n").encode("utf-8")


def snapshot_sha256(record):
    return hashlib.sha256(canonical_bytes(record)).hexdigest()


def source_entry(record, role):
    """Never include source body or later-reference metadata."""
    return {
        "role": role,
        "source_version_id": record["source_version_id"],
        "sha256": record["sha256"],
        "available_at": record["available_at"],
        "independence_group": record["independence_group"],
    }


def case_views(source_manifest, case_manifest, case_id):
    """Construct B0 and G1 input views only for a valid declared case.

    The caller must independently verify archived bytes and publication dates
    before using either view as an actual research experiment.
    """
    errors, _, _ = validate(source_manifest, case_manifest, strict=False)
    if errors:
        raise ValueError("Invalid source/case manifests: " + "; ".join(errors))

    matching = [case for case in case_manifest["cases"]
                if case["case_id"] == case_id]
    if len(matching) != 1:
        raise ValueError("Case ID not found or not unique")
    case = matching[0]
    index = {source["source_version_id"]: source
             for source in source_manifest["sources"]}

    early = [source_entry(index[x], "early")
             for x in case["early_source_version_ids"]]
    background = [source_entry(index[x], "background")
                  for x in case["background_source_version_ids"]]
    background.sort(key=lambda s: s["source_version_id"])

    common = {
        "schema_version": SCHEMA_VERSION,
        "artifact_kind": "historical_source_input",
        "dataset_id": source_manifest["dataset_id"],
        "dataset_version": source_manifest["dataset_version"],
        "case_id": case["case_id"],
        "target_entity_id": case["target_entity_id"],
        "cutoff_at": case["cutoff_at"],
        "scope_warning": (
            "Source-level historical eligibility from declared, verified-date "
            "metadata; does not time-filter extracted claims, aliases, models "
            "or embeddings. Publication-date evidence must be reviewed."
        ),
    }
    b0 = dict(common, method="B0_sparse_report_only", sources=early)
    g1 = dict(common, method="G1_early_plus_historical_background",
              sources=early + background)
    return {"B0": b0, "G1": g1}


def all_views(source_manifest, case_manifest):
    """Validate once and construct an explicitly ordered case set."""
    errors, warnings, counts = validate(
        source_manifest, case_manifest, strict=False
    )
    if errors:
        raise ValueError("Invalid research manifests: " + "; ".join(errors))
    return {
        case["case_id"]: case_views(source_manifest, case_manifest, case["case_id"])
        for case in sorted(case_manifest["cases"], key=lambda x: x["case_id"])
    }, warnings, counts


def write_immutable_view(view, output_root):
    """Create a content-addressed JSON file without overwriting past results."""
    output_root = Path(output_root).expanduser()
    if output_root.is_symlink():
        raise ValueError("Output directory must not be a symlink")
    if output_root.exists() and not output_root.is_dir():
        raise ValueError("Output root exists but is not a directory")

    data = canonical_bytes(view)
    digest = hashlib.sha256(data).hexdigest()
    output_root.mkdir(parents=True, exist_ok=True)
    dest = output_root / (digest + ".json")
    if dest.is_symlink():
        raise ValueError("Refusing symlinked snapshot output")
    if dest.exists():
        if not dest.is_file() or dest.read_bytes() != data:
            raise ValueError("Existing snapshot artifact differs from expected bytes")
        return digest, dest, False
    # Exclusive creation ensures a file already there is never overwritten.
    try:
        with dest.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError:
        if dest.is_symlink() or not dest.is_file() or dest.read_bytes() != data:
            raise ValueError("Concurrent snapshot artifact differs")
        return digest, dest, False

    return digest, dest, True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", help="Source-version metadata manifest")
    parser.add_argument("cases", help="Historical case manifest")
    parser.add_argument("--write", action="store_true",
                        help="Write immutable snapshots (strict corpus and byte audit required)")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT)
    parser.add_argument("--archive-dir", default=DEFAULT_ARCHIVES)
    args = parser.parse_args(argv)

    try:
        sources = load_json(args.sources)
        cases = load_json(args.cases)
        views, warnings, counts = all_views(sources, cases)
    except (ValueError, OSError, json.JSONDecodeError, TypeError) as exc:
        print(json.dumps({
            "status": "invalid", "error_type": type(exc).__name__,
            "error": str(exc),
        }, indent=2))
        return 2

    if args.write:
        errors, _, _ = validate(sources, cases, strict=True)
        if errors or not views:
            print(json.dumps({"status": "not_research_ready",
                              "errors": errors or ["No historical cases selected"]}, indent=2))
            return 2
        audit, integrity_errors, _ = audit_sources(
            sources, args.archive_dir, require_all=True
        )
        if (integrity_errors or
                audit["verified_bytes"] != counts["approved_sources"] or
                audit["approved"] == 0):
            print(json.dumps({
                "status": "source_integrity_failed",
                "errors": integrity_errors or ["Not all source versions verified"],
            }, indent=2))
            return 2

    result = {"status": "snapshots_written" if args.write else "metadata_preview",
              "scope": "source-level only", "counts": counts, "warnings": warnings,
              "case_views": []}
    try:
        for case_id, pair in views.items():
            entry = {"case_id": case_id}
            for method, view in pair.items():
                digest = snapshot_sha256(view)
                item = {"sha256": digest, "source_count": len(view["sources"])}
                if args.write:
                    actual, dest, created = write_immutable_view(
                        view, args.output_dir
                    )
                    if actual != digest:
                        raise ValueError("Snapshot SHA mismatch after writing")
                    item["path"] = str(dest)
                    item["created"] = created
                entry[method] = item
            result["case_views"].append(entry)
    except (OSError, ValueError) as exc:
        print(json.dumps({"status": "write_failed",
                          "error_type": type(exc).__name__}, indent=2))
        return 2
    if not views:
        result["status"] = "no_cases_yet"
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
