#!/usr/bin/env python3
"""Validate *candidate-only* P1a case research provenance metadata.

This is NOT a source approval, archive audit, publication-time verifier,
case-manifest generator, or experimental readiness check. It refuses any
source-approval assertion without the missing independent study evidence.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import json
from pathlib import Path
import re
import sys

MAX_BYTES = 2 * 1024 * 1024
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
ROLES = {"early", "background", "later", "excluded"}
REQUIRED_RECORD = {
    "source_version_id", "source_id", "url", "publisher",
    "independence_group", "proposed_role", "observed_publication_date",
    "published_timestamp_observation", "date_observation_basis",
    "revision_risk", "triage_decision", "approved", "archived_sha256",
    "verified_available_at", "rights_review",
}


def _date(text: str, *, utc: bool = False):
    if not isinstance(text, str) or not (UTC if utc else DATE).fullmatch(text):
        raise ValueError("Historical date must be explicitly formatted as date or UTC seconds")
    try:
        if utc:
            return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return date.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("Invalid historical calendar date") from exc


def _plain(value, label):
    if not isinstance(value, str) or not value.strip() or len(value) > 1400:
        raise ValueError(f"{label} must be nonblank bounded text")
    return value


def load_json(path: str | Path):
    p = Path(path)
    if p.stat().st_size > MAX_BYTES:
        raise ValueError("Candidate metadata file too large")
    with p.open(encoding="utf-8") as stream:
        return json.load(stream)


def validate_screening(screen, sources, cases=None) -> dict:
    if not isinstance(screen, dict) or not isinstance(sources, dict):
        raise ValueError("Screening and source registry must be objects")
    if screen.get("schema_version") != "p1a-case-screen-v1":
        raise ValueError("Unsupported P1a screening schema")
    if screen.get("status") != "screening_only_not_approved":
        raise ValueError("P1a screening cannot certify or approve a case")
    if screen.get("cutoff_status") != "hypothesis_only_do_not_run_case":
        raise ValueError("Proposed cutoff must remain unverified and non-executable")
    if screen.get("admissibility") != "fail_closed":
        raise ValueError("Candidate must fail closed on unavailable evidence")
    if screen.get("dataset_id") != sources.get("dataset_id"):
        raise ValueError("Candidate and source registry disagree on dataset")
    if screen.get("registry_dataset_version") != sources.get("dataset_version"):
        raise ValueError("Source manifest version mismatch")
    candidate_id = _plain(screen.get("case_candidate_id"), "case candidate ID")
    _plain(screen.get("rationale"), "selection rationale")
    _plain(screen.get("population_caveat"), "population caveat")
    _date(screen.get("checked_on"))
    cutoff = _date(screen.get("proposed_cutoff_at"), utc=True)
    if not isinstance(screen.get("blockers"), list) or not screen["blockers"]:
        raise ValueError("Unresolved P1a evidence blockers must be listed")
    if any(not isinstance(b, str) or not b.strip() for b in screen["blockers"]):
        raise ValueError("Blank blocker is not permitted")
    state = screen.get("approval_state")
    if not isinstance(state, dict) or set(state) != {
        "verified_historical_source_versions", "source_archive_hashes_verified",
        "selected_historical_cases", "reviewer_signoff",
    } or any(state[k] != 0 for k in (
        "verified_historical_source_versions", "source_archive_hashes_verified",
        "selected_historical_cases",
    )) or state["reviewer_signoff"] is not None:
        raise ValueError("Candidate screening cannot assert researcher approval")
    ref = screen.get("git_provenance_anchor")
    if not isinstance(ref, dict):
        raise ValueError("Git provenance anchor missing")
    tag_ref = ref.get("official_tag_ref_api_url")
    if tag_ref != "https://api.github.com/repos/opencontainers/runc/git/ref/tags/v1.1.12":
        raise ValueError("Official upstream tag reference must match the reviewed source")
    release_date = _date(ref.get("github_release_published_at_observed"), utc=True)
    if release_date > cutoff:
        raise ValueError("Observed GitHub public release follows proposed cutoff")
    _plain(ref.get("warning"), "Git provenance caution")
    if not isinstance(sources.get("sources"), list):
        raise ValueError("Source registry missing sources list")
    index = {
        record["source_version_id"]: record
        for record in sources["sources"] if isinstance(record, dict)
        and isinstance(record.get("source_version_id"), str)
    }
    records = screen.get("sources")
    if not isinstance(records, list) or not 3 <= len(records) <= 20:
        raise ValueError("Candidate screening requires a bounded set of candidate versions")
    seen = set()
    group_roles = {}
    counts = {role: 0 for role in ROLES}
    for entry in records:
        if not isinstance(entry, dict) or set(entry) != REQUIRED_RECORD:
            raise ValueError("Candidate source entry has unexpected or missing fields")
        version = _plain(entry["source_version_id"], "source version")
        if version in seen:
            raise ValueError("Duplicate candidate source version")
        seen.add(version)
        candidate = index.get(version)
        if candidate is None:
            raise ValueError("Screening refers to source absent from registry")
        for name in ("source_id", "url", "publisher", "independence_group"):
            if entry[name] != candidate.get(name):
                raise ValueError(f"Candidate {name} differs from source registry")
        if (candidate.get("status") != "candidate"
                or candidate.get("available_at") is not None
                or candidate.get("sha256") is not None
                or candidate.get("date_confidence") != "unknown"
                or entry["approved"] is not False
                or entry["archived_sha256"] is not None
                or entry["verified_available_at"] is not None
                or entry["rights_review"] != "pending"):
            raise ValueError("Candidate cannot be presented as archived, dated or approved")
        role = entry["proposed_role"]
        if not isinstance(role, str) or role not in ROLES:
            raise ValueError("Unsupported screening role")
        counts[role] += 1
        observed = _date(entry["observed_publication_date"])
        instant = entry["published_timestamp_observation"]
        if instant is not None and _date(instant, utc=True).date() != observed:
            raise ValueError("Observed date conflicts with published timestamp metadata")
        if role in ("early", "background"):
            if observed >= cutoff.date():
                # Conservative: same calendar day is not enough to establish
                # availability before an exact time-of-day cutoff.
                if instant is None or _date(instant, utc=True) > cutoff:
                    raise ValueError("Early/background observation not demonstrably before cutoff")
        elif role == "later":
            if observed <= cutoff.date():
                if instant is None or _date(instant, utc=True) <= cutoff:
                    raise ValueError("Later reference observation is not after cutoff")
        group = _plain(entry["independence_group"], "publisher independence group")
        if role != "excluded":
            other = group_roles.get(group)
            if other is not None and other != role:
                raise ValueError("Same dependence group crosses research partitions")
            group_roles[group] = role
        for field in ("date_observation_basis", "revision_risk", "triage_decision"):
            _plain(entry[field], field)
    if not 1 <= counts["early"] <= 2 or not counts["background"] or not counts["later"]:
        raise ValueError("Need 1–2 early, at least one background and later candidate")
    if cases is not None:
        if not isinstance(cases, dict) or cases.get("dataset_id") != sources.get("dataset_id"):
            raise ValueError("Case registry mismatch")
        if any(case.get("case_id") == candidate_id
               for case in cases.get("cases", []) if isinstance(case, dict)):
            raise ValueError("Unapproved screening must not be an executable case manifest")
    return {
        "status": "valid_candidate_screen_only",
        "research_ready": False,
        "approved_case_count": 0,
        "approved_source_count": 0,
        "candidate_records_reviewed": len(records),
        "proposed_cutoff_at": screen["proposed_cutoff_at"],
        "role_counts": counts,
        "remaining_blockers": len(screen["blockers"]),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screening", default="datasets/research/p1a_leaky_vessels_screening.json")
    parser.add_argument("--sources", default="datasets/manifests/pilot.json")
    parser.add_argument("--cases", default="datasets/cases/pilot.json")
    args = parser.parse_args(argv)
    try:
        result = validate_screening(
            load_json(args.screening), load_json(args.sources), load_json(args.cases)
        )
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(json.dumps({"status": "invalid_candidate_screen", "reason": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
