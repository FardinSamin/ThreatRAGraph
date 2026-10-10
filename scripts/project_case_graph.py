#!/usr/bin/env python3
"""Run a *source-asserted* B0/G1 graph projection from curated claim JSONL.

This is NOT GraphRAG similarity/prediction. Source evidence locators and digests are checked against exact archive bytes
for supported UTF-8/JSON types; this runner also enforces source-byte integrity,
historical source partitions and restrictions on which claims may be loaded.
Strict structural runs require explicit manual semantic review of every claim;
development-only runs may emit visibly unreviewed/uncertain claims, but cannot
be labeled empirically research ready; even strict structural runs need
independent scientific approval outside this CLI. No network/model calls or raw report output.
"""
import argparse
import json
from pathlib import Path
import sqlite3
import sys

from scripts.audit_source_artifacts import audit_sources
from scripts.freeze_case_snapshots import case_views
from scripts.validate_research_manifests import load_json, validate
from src.threatragraph.evidence_graph import EvidenceGraph
from src.threatragraph.evidence_alignment import EvidenceVerifier
from src.threatragraph.semantic_reviews import SemanticReviewLedger, read_review_jsonl
from src.threatragraph.readiness import readiness_disclosure

MAX_CLAIMS_BYTES = 5 * 1024 * 1024
MAX_CLAIMS = 10000


def load_claims(path, allowed_versions):
    """Fail rather than silently skip out-of-cutoff source claim records."""
    path = Path(path)
    if path.stat().st_size > MAX_CLAIMS_BYTES:
        raise ValueError("Claim file exceeds input limit")
    claims = []
    with path.open("r", encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            if len(claims) >= MAX_CLAIMS:
                raise ValueError("Claim count exceeds allowed limit")
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON at claim line {line_number}") from exc
            if not isinstance(obj, dict):
                raise ValueError(f"Claim line {line_number} is not an object")
            if obj.get("source_version_id") not in allowed_versions:
                # Do NOT print the prohibited source ID: it may be held-out.
                raise ValueError(f"Disallowed historical source in claim line {line_number}")
            claims.append(obj)
    return claims


def run(sources, cases, case_id, raw_claims_path, archives, development=False,
        reviews_path=None):
    errors, warnings, counts = validate(sources, cases, strict=not development)
    if errors:
        raise ValueError("Source/case manifest validation failed: " + "; ".join(errors))
    views = case_views(sources, cases, case_id)
    integrity, integrity_errors, _ = audit_sources(sources, archives, require_all=True)
    if (integrity_errors or integrity["approved"] == 0 or
            integrity["verified_bytes"] != counts["approved_sources"]):
        raise ValueError("Source bytes not all verified against the frozen manifest")

    permitted = {
        item["source_version_id"]
        for view in views.values() for item in view["sources"]
    }
    claims = load_claims(raw_claims_path, permitted)
    with sqlite3.connect(":memory:") as conn:
        verifier = EvidenceVerifier(sources, archives)
        ledger = EvidenceGraph(conn, evidence_verifier=verifier)
        ledger.register_source_versions(sources)
        claim_ids = set()
        for record in claims:
            claim_ids.add(ledger.append_source_claim(record))
        reviews = SemanticReviewLedger(conn)
        if reviews_path is not None:
            for review in read_review_jsonl(reviews_path):
                reviews.record(review)
        decisions = reviews.status(claim_ids, require_supported=not development)
        b0, g1 = ledger.project(views["B0"]), ledger.project(views["G1"])
        for projection in (b0, g1):
            for edge in projection["edges"]:
                edge["semantic_review_status"] = decisions.get(
                    edge["claim_id"], "unreviewed"
                )
    if any(edge["evidence_status"] != "aligned"
           for graph in (b0, g1) for edge in graph["edges"]):
        raise ValueError("Refusing graph projection with unverified evidence")

    b0_ids = {edge["claim_id"] for edge in b0["edges"]}
    g1_ids = {edge["claim_id"] for edge in g1["edges"]}
    if not b0_ids.issubset(g1_ids):
        raise ValueError("B0 evidence is not a subset of G1 evidence")

    return {
        "status": "development_only" if development else "structurally_validated_graph",
        "research_ready": False,
        "readiness": readiness_disclosure(development_only=development),
        "case_id": case_id,
        "warnings": warnings,
        "scope": (
            "Archive-backed citation bytes can be aligned for approved source formats. "
            "Semantic approval is self-declared reviewer judgment, not independently "
            "authenticated truth, attack occurrence or model historical ignorance."
        ),
        "B0": b0,
        "G1": g1,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sources", default="datasets/manifests/pilot.json")
    parser.add_argument("--cases", default="datasets/cases/pilot.json")
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--claims", required=True, help="JSONL of claims with archive-verifiable text or JSON evidence")
    parser.add_argument("--archive-root", default="artifacts/source_versions/sha256")
    parser.add_argument("--reviews", help="JSONL human semantic evidence reviews; required for strict research runs")
    parser.add_argument(
        "--development-only", action="store_true",
        help="Relax only pilot counts for synthetic fixtures; neither mode grants scientific readiness",
    )
    args = parser.parse_args(argv)
    try:
        result = run(
            load_json(args.sources), load_json(args.cases),
            args.case_id, args.claims, args.archive_root,
            development=args.development_only, reviews_path=args.reviews,
        )
    except (OSError, ValueError, TypeError, sqlite3.Error) as exc:
        print(json.dumps({
            "status": "refused", "reason": type(exc).__name__,
            "message": str(exc)[:1200],
        }, indent=2))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
