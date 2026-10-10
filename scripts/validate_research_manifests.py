#!/usr/bin/env python3
"""Offline validator for source-version and time-gated research case manifests.

No network access, external libraries, CTI processing, or cloud services.
Draft validation is intentionally different from strict pilot readiness.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlparse

SCHEMA_VERSION = "1.0"
SOURCE_KINDS = {
    "cti_report", "otx_pulse", "attack_stix", "falco_rule",
    "kubernetes_doc", "cve_advisory", "other",
}
STATUSES = {"candidate", "approved", "excluded"}
DATE_CONFIDENCE = {"verified", "approximate", "unknown"}
REDISTRIBUTION = {"allowed", "restricted", "unknown"}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
UTC_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def timestamp(value, where, errors, allow_none=False):
    """Require unambiguous UTC second-precision strings; no guessing dates."""
    if value is None and allow_none:
        return None
    if not isinstance(value, str) or not UTC_TIME.fullmatch(value):
        errors.append(f"{where}: expected UTC timestamp YYYY-MM-DDTHH:MM:SSZ")
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        errors.append(f"{where}: invalid calendar timestamp")
        return None


def nonempty(value):
    return isinstance(value, str) and bool(value.strip())


def require_string(obj, key, where, errors):
    value = obj.get(key)
    if not nonempty(value):
        errors.append(f"{where}.{key}: required nonempty string")
        return None
    return value


def require_list(obj, key, where, errors):
    value = obj.get(key)
    if not isinstance(value, list):
        errors.append(f"{where}.{key}: required array")
        return []
    return value


def check_envelope(obj, kind, errors):
    if not isinstance(obj, dict):
        errors.append(f"{kind}: root must be an object")
        return False
    for field in ("dataset_id", "dataset_version"):
        require_string(obj, field, kind, errors)
    if obj.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"{kind}.schema_version: expected {SCHEMA_VERSION}")
    return True


def validate(source_manifest, case_manifest, strict=False):
    """Return (errors, warnings, counts); all violations are human-readable."""
    errors = []
    warnings = []
    counts = {"sources": 0, "approved_sources": 0, "cases": 0}
    if not check_envelope(source_manifest, "sources", errors):
        return errors, warnings, counts
    if not check_envelope(case_manifest, "cases", errors):
        return errors, warnings, counts
    for f in ("dataset_id", "dataset_version"):
        if source_manifest.get(f) != case_manifest.get(f):
            errors.append(f"dataset.{f}: source/case manifests must match")

    records = require_list(source_manifest, "sources", "sources", errors)
    cases = require_list(case_manifest, "cases", "cases", errors)
    counts["sources"] = len(records)
    counts["cases"] = len(cases)
    index = {}

    for i, record in enumerate(records):
        where = f"sources.sources[{i}]"
        if not isinstance(record, dict):
            errors.append(f"{where}: expected object")
            continue

        version = require_string(record, "source_version_id", where, errors)
        for field in ("source_id", "title", "publisher", "date_evidence",
                      "independence_group", "selection_rationale"):
            # Evidence and rationale may remain blank on *draft candidates*.
            if field in ("date_evidence", "independence_group", "selection_rationale"):
                continue
            require_string(record, field, where, errors)

        if version in index and version is not None:
            errors.append(f"{where}.source_version_id: duplicate '{version}'")
        elif version is not None:
            index[version] = record

        kind = record.get("source_kind")
        if not isinstance(kind, str) or kind not in SOURCE_KINDS:
            errors.append(f"{where}.source_kind: unsupported value")

        status = record.get("status")
        if not isinstance(status, str) or status not in STATUSES:
            errors.append(f"{where}.status: candidate, approved or excluded required")
        if not isinstance(record.get("date_confidence"), str) or record.get("date_confidence") not in DATE_CONFIDENCE:
            errors.append(f"{where}.date_confidence: invalid value")
        if not isinstance(record.get("redistribution"), str) or record.get("redistribution") not in REDISTRIBUTION:
            errors.append(f"{where}.redistribution: invalid value")

        url = record.get("url")
        try:
            parsed_url = urlparse(url) if isinstance(url, str) else None
            url_ok = (parsed_url is not None and
                      parsed_url.scheme == "https" and bool(parsed_url.netloc))
        except ValueError:
            url_ok = False
        if not url_ok:
            errors.append(f"{where}.url: absolute https URL required")

        published = timestamp(record.get("published_at"), where + ".published_at",
                              errors, allow_none=True)
        available = timestamp(record.get("available_at"), where + ".available_at",
                              errors, allow_none=True)
        if published and available and available < published:
            errors.append(f"{where}: available_at before published_at; review version chronology")

        digest = record.get("sha256")
        if digest is not None and not (
            isinstance(digest, str) and SHA256.fullmatch(digest)
        ):
            errors.append(f"{where}.sha256: require full lowercase SHA-256 or null")

        if status == "approved":
            counts["approved_sources"] += 1
            if digest is None:
                errors.append(f"{where}.sha256: approved sources need immutable checksum")
            if available is None or record.get("date_confidence") != "verified":
                errors.append(f"{where}: approved sources need verified available_at")
            if not nonempty(record.get("date_evidence")):
                errors.append(f"{where}.date_evidence: required for approved source")
            if not nonempty(record.get("selection_rationale")):
                errors.append(f"{where}.selection_rationale: required for approved source")
            if not nonempty(record.get("independence_group")):
                errors.append(f"{where}.independence_group: required for approved source")

    case_ids = set()
    for i, case in enumerate(cases):
        where = f"cases.cases[{i}]"
        if not isinstance(case, dict):
            errors.append(f"{where}: expected object")
            continue
        case_id = require_string(case, "case_id", where, errors)
        require_string(case, "target_entity_id", where, errors)
        require_string(case, "selection_rationale", where, errors)
        if case_id in case_ids and case_id is not None:
            errors.append(f"{where}.case_id: duplicate '{case_id}'")
        if case_id:
            case_ids.add(case_id)

        cutoff = timestamp(case.get("cutoff_at"), where + ".cutoff_at", errors)
        early = require_list(case, "early_source_version_ids", where, errors)
        background = require_list(case, "background_source_version_ids", where, errors)
        later = require_list(case, "later_reference_source_version_ids", where, errors)

        if not 1 <= len(early) <= 2:
            errors.append(f"{where}.early_source_version_ids: expected 1 or 2 initial reports")
        if not later:
            errors.append(f"{where}.later_reference_source_version_ids: need held-out later sources")
        if strict and not background:
            errors.append(f"{where}.background_source_version_ids: strict pilot needs historical background")
        partitions = {"early": early, "background": background, "later": later}
        all_seen = set()
        group_partition = {}
        for partition, ids in partitions.items():
            for version in ids:
                if not nonempty(version):
                    errors.append(f"{where}.{partition}: source version ID must be nonempty")
                    continue
                if version in all_seen:
                    errors.append(f"{where}: source version '{version}' repeated across or within partitions")
                all_seen.add(version)
                record = index.get(version)
                if record is None:
                    errors.append(f"{where}.{partition}: unknown source version '{version}'")
                    continue
                if record.get("status") != "approved":
                    errors.append(f"{where}.{partition}: '{version}' is not approved")
                if record.get("date_confidence") != "verified":
                    errors.append(f"{where}.{partition}: '{version}' has unverified availability")
                available = timestamp(
                    record.get("available_at"),
                    where + f".{partition}['{version}'].available_at", errors,
                )
                if cutoff and available:
                    if partition in ("early", "background") and available > cutoff:
                        errors.append(f"{where}.{partition}: '{version}' is post-cutoff leakage")
                    if partition == "later" and available <= cutoff:
                        errors.append(f"{where}.later: '{version}' is not after cutoff")

                group = record.get("independence_group")
                if nonempty(group):
                    prev = group_partition.get(group)
                    if prev is not None and prev != partition:
                        errors.append(
                            f"{where}: source independence group '{group}' crosses "
                            f"{prev}/{partition} partition"
                        )
                    group_partition[group] = partition

    if not records:
        warnings.append("Draft corpus is empty; no real CTI sources have been curated")
    if not cases:
        warnings.append("Draft case registry is empty; no experiment cases selected")
    if strict:
        if not 25 <= counts["approved_sources"] <= 40:
            errors.append("strict: pilot needs 25–40 approved source versions")
        if not 4 <= counts["cases"] <= 6:
            errors.append("strict: pilot needs 4–6 reviewed historical cases")
    return errors, warnings, counts


def load_json(path):
    p = Path(path)
    if p.stat().st_size > 5 * 1024 * 1024:
        raise ValueError(f"{p}: manifest larger than 5 MiB")
    with p.open("r", encoding="utf-8") as stream:
        return json.load(stream)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", help="JSON source-version manifest")
    parser.add_argument("cases", help="JSON historical case manifest")
    parser.add_argument("--strict", action="store_true",
                        help="Reject incomplete pilot counts (25–40 sources, 4–6 cases)")
    args = parser.parse_args(argv)
    try:
        sources = load_json(args.sources)
        cases = load_json(args.cases)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "read_error", "detail": str(exc)}, indent=2))
        return 1
    errors, warnings, counts = validate(sources, cases, strict=args.strict)
    print(json.dumps({
        "status": "invalid" if errors else ("research_ready" if args.strict else "draft_valid"),
        "strict": args.strict, "counts": counts,
        "errors": errors, "warnings": warnings,
    }, indent=2))
    return 2 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
