"""B0 deterministic, early-report-only cold-start profile.

The B0 profiler accepts ONLY a B0 source view and its B0 sourced-graph
projection. It does not receive G1, background claim records, historical
similarity neighbors, held-out references or outcome labels.

Reported facts are early-source assertions with byte-aligned, semantically
reviewed citations, *not* confirmed world truth and not predictions.
No LLM, similarity score, probability estimate, or external service.
"""
from __future__ import annotations

import re
from typing import Any

from .evidence_graph import as_utc, fingerprint, require_id, require_sha, validate_triple

BASELINE_VERSION = "b0-assertions-v1"
PROFILE_SCHEMA_VERSION = "1.0"
B0_METHOD = "B0_sparse_report_only"
_ALLOWED_VIEW = {
    "schema_version", "artifact_kind", "dataset_id", "dataset_version",
    "case_id", "target_entity_id", "cutoff_at", "scope_warning",
    "method", "sources",
}
_ALLOWED_SOURCE = {
    "role", "source_version_id", "sha256", "available_at", "independence_group",
}
_ALLOWED_GRAPH = {
    "schema_version", "artifact_kind", "case_id", "method", "cutoff_at",
    "source_view_sha256", "nodes", "edges", "caveat",
}
_ALLOWED_EDGE = {
    "claim_id", "source_version_id", "subject_id", "predicate", "object_id",
    "assertion_kind", "polarity", "evidence_locator", "evidence_sha256",
    "extractor_version", "evidence_status", "semantic_review_status",
}
_CLAIM_ID = re.compile(r"^claim:[0-9a-f]{64}$")
_REVIEWS = {
    "supported_by_excerpt", "unsupported_by_excerpt", "uncertain", "unreviewed",
}
_ASSERTIONS = {"report_assertion", "rule_semantics"}


def _object(record: Any, keys: set[str], what: str) -> dict:
    if not isinstance(record, dict) or set(record) != keys:
        raise ValueError(f"{what} must contain exactly the B0 contract fields")
    return record


def build_b0_profile(view: dict, graph: dict, *, development_only=False) -> dict:
    """Generate a reproducible baseline from source-asserted target facts.

    Strict mode rejects even one unreviewed/unaligned claim. Development mode
    may count insufficiently reviewed claims but never present them as facts;
    its output explicitly remains research_ready=False.
    """
    if type(development_only) is not bool:
        raise ValueError("development_only must be a boolean")
    view = _object(view, _ALLOWED_VIEW, "B0 source view")
    graph = _object(graph, _ALLOWED_GRAPH, "B0 sourced graph")
    if (view["schema_version"] != PROFILE_SCHEMA_VERSION or
            view["artifact_kind"] != "historical_source_input" or
            view["method"] != B0_METHOD):
        raise ValueError("Report-only B0 source view required")
    if (graph["schema_version"] != PROFILE_SCHEMA_VERSION or
            graph["artifact_kind"] != "historical_sourced_graph" or
            graph["method"] != B0_METHOD):
        raise ValueError("Report-only B0 graph projection required")
    for field in ("case_id", "cutoff_at"):
        if view[field] != graph[field]:
            raise ValueError(f"Graph and B0 source view disagree on {field}")
    if not isinstance(view["case_id"], str) or not view["case_id"].strip():
        raise ValueError("Case ID required")
    if not isinstance(view["dataset_id"], str) or not view["dataset_id"].strip():
        raise ValueError("Dataset ID required")
    if not isinstance(view["dataset_version"], str) or not view["dataset_version"].strip():
        raise ValueError("Dataset version required")
    target = require_id(view["target_entity_id"], "target_entity_id")
    cutoff = as_utc(view["cutoff_at"])
    if fingerprint(view) != require_sha(graph["source_view_sha256"], "source_view_sha256"):
        raise ValueError("Graph is not bound to the exact B0 source-view snapshot")

    allowed: set[str] = set()
    sources = view["sources"]
    if not isinstance(sources, list) or len(sources) not in {1, 2}:
        raise ValueError("B0 requires exactly one or two early source versions")
    for item in sources:
        item = _object(item, _ALLOWED_SOURCE, "B0 source entry")
        if item["role"] != "early":
            raise ValueError("B0 cannot read background or held-out sources")
        version = item["source_version_id"]
        if not isinstance(version, str) or not version.strip() or version in allowed:
            raise ValueError("B0 source IDs must be distinct nonblank strings")
        require_sha(item["sha256"], "source.sha256")
        if as_utc(item["available_at"]) > cutoff:
            raise ValueError("B0 source is post-cutoff")
        if not isinstance(item["independence_group"], str):
            raise ValueError("Source independence group must be a string")
        allowed.add(version)

    edges = graph["edges"]
    if not isinstance(edges, list) or len(edges) > 10000:
        raise ValueError("B0 graph edges must be a bounded list")
    if not isinstance(graph["nodes"], list):
        raise ValueError("B0 graph nodes must be a list")

    seen_claims: set[str] = set()
    nodes: set[str] = set()
    positive: dict[tuple[str, str, str], list[dict]] = {}
    negative: set[tuple[str, str, str]] = set()
    ignored_unreviewed = 0
    ignored_uncertain = 0
    ignored_not_target = 0
    negative_claims = 0

    for raw in edges:
        edge = _object(raw, _ALLOWED_EDGE, "B0 sourced edge")
        cid = edge["claim_id"]
        if (not isinstance(cid, str) or not _CLAIM_ID.fullmatch(cid)
                or cid in seen_claims):
            raise ValueError("Invalid or duplicate B0 claim ID")
        seen_claims.add(cid)
        source_version = edge["source_version_id"]
        if not isinstance(source_version, str) or source_version not in allowed:
            raise ValueError("Future or non-early source in B0 graph edge")
        validate_triple(edge["subject_id"], edge["predicate"], edge["object_id"])
        nodes.update((edge["subject_id"], edge["object_id"]))
        if edge["assertion_kind"] not in _ASSERTIONS:
            raise ValueError("Predictions cannot enter B0 source assertions")
        if edge["polarity"] not in {"positive", "negative", "uncertain"}:
            raise ValueError("Invalid assertion polarity")
        require_sha(edge["evidence_sha256"], "evidence_sha256")
        if not isinstance(edge["evidence_locator"], dict):
            raise ValueError("Evidence locator missing from sourced claim")
        if edge["evidence_status"] != "aligned":
            raise ValueError("B0 cannot use a claim with unaligned original evidence")
        review = edge["semantic_review_status"]
        if not isinstance(review, str) or review not in _REVIEWS:
            raise ValueError("B0 semantic-review state is invalid")
        if not isinstance(edge["extractor_version"], str) or not edge["extractor_version"].strip():
            raise ValueError("Extractor version required")

        if review != "supported_by_excerpt":
            if not development_only:
                raise ValueError("Strict B0 requires semantic review of every claim")
            ignored_unreviewed += 1
            continue
        key = (edge["subject_id"], edge["predicate"], edge["object_id"])
        if target not in (edge["subject_id"], edge["object_id"]):
            ignored_not_target += 1
            continue
        if edge["polarity"] == "uncertain":
            ignored_uncertain += 1
        elif edge["polarity"] == "negative":
            negative.add(key)
            negative_claims += 1
        else:
            positive.setdefault(key, []).append(edge)

    if sorted(nodes) != graph["nodes"]:
        raise ValueError("B0 graph nodes do not equal the exact claim endpoints")
    facts = []
    conflicting = 0
    for key in sorted(positive):
        if key in negative:
            conflicting += 1
            continue
        support = sorted(
            positive[key], key=lambda x: (x["source_version_id"], x["claim_id"])
        )
        facts.append({
            "subject_id": key[0],
            "predicate": key[1],
            "object_id": key[2],
            "status": "asserted_in_early_reports",
            "assertion_kinds": sorted({x["assertion_kind"] for x in support}),
            "source_version_ids": sorted({x["source_version_id"] for x in support}),
            "supporting_claim_ids": [x["claim_id"] for x in support],
            "evidence_sha256s": sorted({x["evidence_sha256"] for x in support}),
            "confidence": None,
            "score": None,
            "score_kind": "not_estimated",
        })

    if facts:
        reason = None
    elif conflicting:
        reason = "conflicting_source_assertions"
    elif ignored_unreviewed:
        reason = "no_semantically_reviewed_target_evidence"
    else:
        reason = "no_supported_positive_target_assertions"

    output = {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "profile_kind": "cold_start_report_only",
        "method": "B0",
        "method_version": BASELINE_VERSION,
        "case_id": view["case_id"],
        "dataset_id": view["dataset_id"],
        "dataset_version": view["dataset_version"],
        "cutoff_at": view["cutoff_at"],
        "target_entity_id": target,
        "source_view_sha256": graph["source_view_sha256"],
        "early_source_version_ids": sorted(allowed),
        "facts": facts,
        "predictions": [],
        "abstention": {"abstained": not bool(facts), "reason": reason},
        "diagnostics": {
            "examined_early_claims": len(edges),
            "ignored_unreviewed_claims": ignored_unreviewed,
            "ignored_uncertain_claims": ignored_uncertain,
            "ignored_non_target_claims": ignored_not_target,
            "negative_target_claims": negative_claims,
            "conflicting_target_triples": conflicting,
        },
        "research_ready": not development_only,
        "limitations": (
            "Only evidence-aligned, review-supported assertions directly mentioning "
            "the target in the first one or two early source reports. No inference, "
            "similarity, probabilistic confidence, future aliases or outcome labels."
        ),
    }
    output["profile_id"] = "profile:" + fingerprint(output)
    return output
