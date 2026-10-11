"""Run isolated versioned compound GHSA evidence over approved historical views.

Experimental development plumbing, NOT G1 inference. The scientific v1 B0/G1
source graph and predictions are untouched. All approvals are manifest-declared
and require independent investigator inspection outside this CLI.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sqlite3

from scripts.audit_source_artifacts import audit_sources
from scripts.freeze_case_snapshots import case_views
from scripts.project_case_graph import load_claims
from scripts.validate_research_manifests import load_json, validate
from src.threatragraph.compound_claims import CompoundSourcedClaimLedger
from src.threatragraph.evidence_alignment import EvidenceVerifier
from src.threatragraph.evidence_graph import EvidenceGraph
from src.threatragraph.semantic_reviews import read_review_jsonl

MAX_REVIEWS = 10000


def run(sources: dict, cases: dict, case_id: str, claims_path: str | Path,
        archive_root: str | Path, *, reviews_path: str | Path | None = None,
        development_only: bool = False) -> dict:
    if type(development_only) is not bool:
        raise ValueError("development_only must be boolean")
    errors, warnings, counts = validate(sources, cases, strict=not development_only)
    if errors:
        raise ValueError("Historical manifest invalid: " + "; ".join(errors))
    views = case_views(sources, cases, case_id)
    audit, failures, _ = audit_sources(sources, archive_root, require_all=True)
    if failures or not counts["approved_sources"] or (
        audit["verified_bytes"] != counts["approved_sources"]
    ):
        raise ValueError("Exact bytes for every approved source version are required")
    allowed = {
        s["source_version_id"]
        for view in views.values() for s in view["sources"]
    }
    raw_claims = load_claims(claims_path, allowed)
    if not raw_claims:
        raise ValueError("No compound claims supplied")
    if not development_only and reviews_path is None:
        raise ValueError("Strict compound runs require separate semantic reviews")

    # No source body, held-out references, or reviewer file enters inference:
    # this produces a separate compound evidence view, never B0/G1 v1 input.
    with sqlite3.connect(":memory:") as db:
        graph = EvidenceGraph(db, evidence_verifier=EvidenceVerifier(sources, archive_root))
        graph.register_source_versions(sources)
        compound = CompoundSourcedClaimLedger(graph)
        ids = {compound.append(claim) for claim in raw_claims}
        if reviews_path is not None:
            reviews = read_review_jsonl(reviews_path)
            if len(reviews) > MAX_REVIEWS:
                raise ValueError("Review count exceeds bound")
            for review in reviews:
                if not isinstance(review, dict) or review.get("claim_id") not in ids:
                    raise ValueError("Unrecognized compound review or forbidden source")
                compound.review(review)
        b0 = compound.project(views["B0"], require_supported=not development_only)
        g1 = compound.project(views["G1"], require_supported=not development_only)
        if not {e["claim_id"] for e in b0["edges"]}.issubset(
            {e["claim_id"] for e in g1["edges"]}
        ):
            raise ValueError("B0 compound evidence is not a subset of G1")
        if not development_only and not b0["edges"]:
            raise ValueError("Strict compound evidence run must include early source claims")

    return {
        "status": "development_only" if development_only else "strict_compound_metadata_valid",
        "research_ready": False,
        "g1_ranker_input_eligible": False,
        "validation_mode": "development_only" if development_only else "strict_metadata_and_self_declared_review",
        "dataset_id": sources["dataset_id"],
        "case_id": case_id,
        "warnings": warnings,
        "B0_compound_evidence": b0,
        "G1_compound_evidence": g1,
        "limitations": (
            "Real case eligibility, independent public timestamps, source rights, "
            "reviewer authentication, multi-field G1 schema acceptance and "
            "held-out prediction scoring remain external; never call this an empirical result."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", default="datasets/manifests/pilot.json")
    parser.add_argument("--cases", default="datasets/cases/pilot.json")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--claims", required=True)
    parser.add_argument("--archive-root", default="artifacts/source_versions/sha256")
    parser.add_argument("--reviews", help="Versioned compound semantic-review JSONL")
    parser.add_argument("--development-only", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = run(
            load_json(args.sources), load_json(args.cases),
            args.case_id, args.claims, args.archive_root,
            reviews_path=args.reviews, development_only=args.development_only,
        )
    except (OSError, ValueError, TypeError, sqlite3.Error, json.JSONDecodeError) as exc:
        print(json.dumps({
            "status": "compound_projection_refused",
            "reason": str(exc)[:1200],
            "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
