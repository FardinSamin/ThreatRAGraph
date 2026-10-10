"""Bounded v1 source-view and graph-projection contract checks.

This checks *shape, types and declared source/cutoff consistency*, not
authentic publisher chronology, reviewers, semantics, or filesystem hashes.
Unknown schema versions, labels and undeclared fields FAIL CLOSED.
"""
from __future__ import annotations

import re
from typing import Any

from .evidence_graph import (
    KINDS, POLARITIES, SCHEMA_VERSION, VIEW_METHODS, as_utc,
    fingerprint, require_id, require_sha, validate_locator, validate_triple,
)

CLAIM = re.compile(r"^claim:[0-9a-f]{64}$")
SOURCE_VIEW_FIELDS = frozenset({
    "schema_version", "artifact_kind", "dataset_id", "dataset_version",
    "case_id", "target_entity_id", "cutoff_at", "scope_warning", "method",
    "sources",
})
SOURCE_FIELDS = frozenset({
    "role", "source_version_id", "sha256", "available_at", "independence_group",
})
GRAPH_FIELDS = frozenset({
    "schema_version", "artifact_kind", "case_id", "method", "cutoff_at",
    "source_view_sha256", "nodes", "edges", "caveat",
})
EDGE_FIELDS = frozenset({
    "claim_id", "source_version_id", "subject_id", "predicate", "object_id",
    "assertion_kind", "polarity", "evidence_locator", "evidence_sha256",
    "extractor_version", "evidence_status",
})
REVIEW_STATES = {"supported_by_excerpt", "unsupported_by_excerpt", "uncertain", "unreviewed"}
MAX_GRAPH_EDGES = 10000
MAX_VIEW_SOURCES = 1000


def _exact(record: Any, fields: frozenset[str], name: str) -> dict:
    if not isinstance(record, dict) or set(record) != fields:
        raise ValueError(f"{name} must contain exactly its v1 contract fields")
    return record


def _plain_text(value: Any, name: str, limit: int = 300) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{name} must be bounded nonblank text")
    return value


def validate_source_view(view: Any) -> set[str]:
    """Validate single B0/G1 view including complete type/role/time checks."""
    _exact(view, SOURCE_VIEW_FIELDS, "Historical source view")
    if view["schema_version"] != SCHEMA_VERSION or view["artifact_kind"] != "historical_source_input":
        raise ValueError("Unsupported historical view schema/version")
    method = view["method"]
    if not isinstance(method, str) or method not in VIEW_METHODS:
        raise ValueError("Unsupported historical method")
    for field in ("dataset_id", "dataset_version", "case_id", "scope_warning"):
        _plain_text(view[field], field, 1500 if field == "scope_warning" else 300)
    require_id(view["target_entity_id"], "target_entity_id")
    cutoff = as_utc(view["cutoff_at"])
    sources = view["sources"]
    if not isinstance(sources, list) or len(sources) > MAX_VIEW_SOURCES:
        raise ValueError("Historical source list must be bounded")
    seen = set()
    early = 0
    for source in sources:
        _exact(source, SOURCE_FIELDS, "Historical source entry")
        if source["role"] not in VIEW_METHODS[method]:
            raise ValueError("Unknown/held-out source role in historical view")
        version = _plain_text(source["source_version_id"], "source_version_id")
        if version in seen:
            raise ValueError("Duplicate source version ID")
        seen.add(version)
        require_sha(source["sha256"], "source.sha256")
        if as_utc(source["available_at"]) > cutoff:
            raise ValueError("Post-cutoff source in historical view")
        _plain_text(source["independence_group"], "independence_group")
        early += source["role"] == "early"
    if early not in (1, 2):
        raise ValueError("Historical view must contain 1–2 early sources")
    return seen


def validate_graph_projection(graph: Any, view: dict, *, reviewed: bool = False) -> None:
    """Check a source-attributed graph artifact against exact historical view.

    Caller must separately validate original bytes and source dates. Graph
    attribution review is checked here only for status syntax and provenance
    references; the reviewer ledger remains the source of authorization.
    """
    allowed = validate_source_view(view)
    _exact(graph, GRAPH_FIELDS, "Historical graph")
    if (graph["schema_version"] != SCHEMA_VERSION or
            graph["artifact_kind"] != "historical_sourced_graph"):
        raise ValueError("Unsupported graph artifact schema/version")
    if graph["case_id"] != view["case_id"] or graph["method"] != view["method"] or graph["cutoff_at"] != view["cutoff_at"]:
        raise ValueError("Graph does not match historical source view identity")
    if require_sha(graph["source_view_sha256"], "source_view_sha256") != fingerprint(view):
        raise ValueError("Graph source-view fingerprint mismatch")
    _plain_text(graph["caveat"], "graph caveat", 3000)
    edges = graph["edges"]
    if not isinstance(edges, list) or len(edges) > MAX_GRAPH_EDGES:
        raise ValueError("Graph requires bounded edge array")
    nodes = graph["nodes"]
    if not isinstance(nodes, list) or len(nodes) > 2 * MAX_GRAPH_EDGES:
        raise ValueError("Graph requires bounded node array")
    seen: set[str] = set()
    endpoints: set[str] = set()
    for edge in edges:
        required = EDGE_FIELDS | {"semantic_review_status"} if reviewed else EDGE_FIELDS
        _exact(edge, required, "Sourced graph edge")
        cid = edge["claim_id"]
        if not isinstance(cid, str) or not CLAIM.fullmatch(cid) or cid in seen:
            raise ValueError("Invalid or duplicate graph claim ID")
        seen.add(cid)
        if _plain_text(edge["source_version_id"], "edge source") not in allowed:
            raise ValueError("Graph claim from non-eligible or future source")
        validate_triple(edge["subject_id"], edge["predicate"], edge["object_id"])
        endpoints.update((edge["subject_id"], edge["object_id"]))
        if edge["assertion_kind"] not in KINDS or edge["polarity"] not in POLARITIES:
            raise ValueError("Graph includes unsupported assertion metadata")
        validate_locator(edge["evidence_locator"])
        require_sha(edge["evidence_sha256"], "graph evidence_sha256")
        _plain_text(edge["extractor_version"], "extractor_version", 200)
        if edge["evidence_status"] not in {"aligned", "unverified"}:
            raise ValueError("Unsupported graph evidence status")
        if reviewed and edge["semantic_review_status"] not in REVIEW_STATES:
            raise ValueError("Unsupported semantic review status")
    if nodes != sorted(endpoints):
        raise ValueError("Graph nodes differ from exact attributed edge endpoints")
