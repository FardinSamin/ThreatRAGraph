"""Candidate-only, historized typed alias records; NEVER rewrite B0/G1 inputs.

An as-of alias record is source-bound, not a certification of semantic identity
or reviewer credentials. Resolver returns *candidate diagnostics* only.
G1's exact-source-identifier policy remains unchanged.
"""
from __future__ import annotations

from .contracts import validate_source_view
from .evidence_graph import as_utc, fingerprint, require_id, require_sha

VERSION = "historical-typed-alias-candidates-v1"
KIND = "candidate_asof_alias_history"
POLICY = "source_bound_same_type_no_transitive_enrichment"
MAX_ENTRIES = 2000
FIELDS = frozenset({
    "schema_version", "artifact_kind", "policy", "case_id", "cutoff_at",
    "source_view_sha256", "entries", "research_ready", "history_id",
})
ENTRY_FIELDS = frozenset({
    "alias_id", "canonical_candidate_id", "source_version_id",
    "source_sha256", "first_known_at", "evidence_sha256",
    "reviewer_id_declared", "decision",
})
DECISIONS = frozenset({
    "candidate_supported", "candidate_rejected", "candidate_uncertain",
})


def _prepare(view, records):
    validate_source_view(view)
    if not isinstance(records, list) or len(records) > MAX_ENTRIES:
        raise ValueError("Bounded alias history list required")
    allowed = {v["source_version_id"]: v for v in view["sources"]}
    cutoff = as_utc(view["cutoff_at"])
    seen = set()
    ordered = []
    accepted_edges = set()
    for item in records:
        if not isinstance(item, dict) or set(item) != ENTRY_FIELDS:
            raise ValueError("Exact candidate-alias evidence fields required")
        alias = require_id(item["alias_id"], "alias_id")
        candidate = require_id(item["canonical_candidate_id"], "canonical_candidate_id")
        if alias == candidate:
            raise ValueError("Trivial alias/self-identity is not an evidence relation")
        if alias.split(":", 1)[0] != candidate.split(":", 1)[0]:
            raise ValueError("Cross-type alias conflation prohibited")
        version = item["source_version_id"]
        if type(version) is not str or version not in allowed:
            raise ValueError("Alias must cite a declared source version")
        source = allowed[version]
        if require_sha(item["source_sha256"], "alias source digest") != source["sha256"]:
            raise ValueError("Alias source byte digest differs from source view")
        require_sha(item["evidence_sha256"], "alias evidence digest")
        known = as_utc(item["first_known_at"])
        if (known != as_utc(source["available_at"]) or known > cutoff):
            raise ValueError("Future or retrospectively dated alias forbidden")
        reviewer = item["reviewer_id_declared"]
        if type(reviewer) is not str or not reviewer.strip() or len(reviewer) > 200:
            raise ValueError("Named candidate reviewer required, not authenticated")
        if item["decision"] not in DECISIONS:
            raise ValueError("Unknown alias candidate decision")
        identity = (alias, candidate, version, item["evidence_sha256"])
        if identity in seen:
            raise ValueError("Duplicated candidate alias decision")
        seen.add(identity)
        ordered.append(identity)
        if item["decision"] == "candidate_supported":
            accepted_edges.add((alias, candidate))
    if ordered != sorted(ordered):
        raise ValueError("Alias evidence rows must be deterministically ordered")
    # Even provisional two-step/cyclic mappings are never inferred.
    if any(candidate in {a for a, _ in accepted_edges}
           for _, candidate in accepted_edges):
        raise ValueError("Chained or cyclic alias candidates require manual review")
    return accepted_edges


def create_history(view, entries):
    """Seal a candidate index, NOT a trusted identity registry."""
    _prepare(view, entries)
    record = {
        "schema_version": "1.0",
        "artifact_kind": KIND,
        "policy": POLICY,
        "case_id": view["case_id"],
        "cutoff_at": view["cutoff_at"],
        "source_view_sha256": fingerprint(view),
        "entries": [dict(x) for x in entries],
        "research_ready": False,
    }
    record["history_id"] = "alias-history:" + fingerprint(record)
    return record


def validate_history(view, history):
    validate_source_view(view)
    if not isinstance(history, dict) or set(history) != FIELDS:
        raise ValueError("Exact source-bound candidate history fields required")
    if (history["schema_version"] != "1.0"
            or history["artifact_kind"] != KIND
            or history["policy"] != POLICY
            or history["research_ready"] is not False
            or history["case_id"] != view["case_id"]
            or history["cutoff_at"] != view["cutoff_at"]
            or require_sha(history["source_view_sha256"], "history view digest")
            != fingerprint(view)):
        raise ValueError("Alias history does not match this as-of source view")
    unsigned = {k: v for k, v in history.items() if k != "history_id"}
    if history["history_id"] != "alias-history:" + fingerprint(unsigned):
        raise ValueError("Alias history fingerprint differs from content")
    return _prepare(view, history["entries"])


def inspect_alias(view, history, typed_id):
    """Return explanatory candidate status; no canonicalization or graph writes."""
    require_id(typed_id, "query_entity_id")
    accepted_edges = validate_history(view, history)
    candidates = sorted({b for a, b in accepted_edges if a == typed_id})
    disputed = sorted({
        item["canonical_candidate_id"] for item in history["entries"]
        if item["alias_id"] == typed_id
        and item["decision"] != "candidate_supported"
    })
    conflicting = bool(set(candidates) & set(disputed))
    result = {
        "schema_version": "1.0",
        "artifact_kind": "unapproved_asof_alias_inspection",
        "history_id": history["history_id"],
        "case_id": view["case_id"],
        "cutoff_at": view["cutoff_at"],
        "query_entity_id": typed_id,
        "candidate_canonical_ids": candidates,
        "disputed_or_uncertain_ids": disputed,
        "status": (
            "no_candidate" if not candidates else
            "conflicting_evidence_requires_adjudication" if conflicting else
            "ambiguous_candidates_require_adjudication" if len(candidates) > 1
            else "single_candidate_still_unapproved"
        ),
        "automatic_entity_rewrite_allowed": False,
        "g1_feature_lineage_enrichment_allowed": False,
        "reviewer_identity_authenticated": False,
        "research_ready": False,
    }
    result["inspection_id"] = "alias-inspection:" + fingerprint(result)
    return result
