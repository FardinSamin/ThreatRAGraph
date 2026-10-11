"""M5.2 fail-closed source-level feature lineage contract.

An analyst-supplied artifact asserts that each *exact* sourced graph edge is
derived from its own pre-cutoff source, with no alias resolution or external
taxonomy/Falco version enrichment. This module can verify the contract and
graph binding, NOT the original source quotation, authenticated reviewer,
actual publisher date, or factual correctness of the claimed identity.

This deliberately has NO feature-lineage creator for real data: generating
self-attestations from an untrusted graph would create false assurance.
"""
from __future__ import annotations

from .contracts import validate_graph_projection
from .evidence_graph import as_utc, fingerprint, require_sha

CONTRACT_VERSION = "asof-exact-claim-lineage-v1"
ARTIFACT_KIND = "g1_asof_feature_lineage"
IDENTITY_POLICY = "exact_source_assertion_no_alias_or_external_enrichment"
EXTRACTION = "direct_source_claim_only_v1"
FIELDS = frozenset({
    "schema_version", "artifact_kind", "case_id", "cutoff_at",
    "g1_source_view_sha256", "g1_graph_sha256",
    "identity_policy", "claim_lineage", "limitations",
})
ENTRY_FIELDS = frozenset({
    "claim_id", "source_version_id", "source_sha256",
    "source_available_at", "claim_evidence_sha256",
    "subject_id", "predicate", "object_id",
    "feature_known_at", "derivation",
})


def validate_asof_lineage(lineage: dict, g1_view: dict, g1_graph: dict) -> dict:
    """Bind EVERY reviewed source assertion to its own frozen source-version metadata.

    The exact-only policy categorically refuses *declared* aliases, taxonomy
    lookups, external embedding transforms and inferred Falco rule mappings.
    It does not prove that fabricated source-native identifiers are truthful.
    """
    validate_graph_projection(g1_graph, g1_view, reviewed=True)
    if not isinstance(lineage, dict) or set(lineage) != FIELDS:
        raise ValueError("As-of lineage must have exact v1 artifact fields")
    if (lineage["schema_version"] != CONTRACT_VERSION
            or lineage["artifact_kind"] != ARTIFACT_KIND
            or lineage["identity_policy"] != IDENTITY_POLICY):
        raise ValueError("Unsupported as-of feature/alias policy or schema")
    if (lineage["case_id"] != g1_view["case_id"]
            or lineage["cutoff_at"] != g1_view["cutoff_at"]):
        raise ValueError("As-of lineage case/cutoff binding mismatch")
    if (require_sha(lineage["g1_source_view_sha256"], "lineage source view hash")
            != fingerprint(g1_view)
            or require_sha(lineage["g1_graph_sha256"], "lineage graph hash")
            != fingerprint(g1_graph)):
        raise ValueError("As-of lineage differs from exact historical graph/view hashes")
    caveat = lineage["limitations"]
    if not isinstance(caveat, str) or not caveat.strip() or len(caveat) > 2400:
        raise ValueError("As-of lineage limitation disclosure required")
    actual = {e["claim_id"]: e for e in g1_graph["edges"]}
    sources = {s["source_version_id"]: s for s in g1_view["sources"]}
    entries = lineage["claim_lineage"]
    if not isinstance(entries, list) or len(entries) != len(actual):
        raise ValueError("One as-of lineage record required per reviewed graph claim")
    if len(entries) > 10000:
        raise ValueError("Too many claim lineage records")
    seen = set()
    cutoff = as_utc(g1_view["cutoff_at"])
    for row in entries:
        if not isinstance(row, dict) or set(row) != ENTRY_FIELDS:
            raise ValueError("Claim lineage contains missing/foreign fields")
        cid = row["claim_id"]
        if not isinstance(cid, str) or cid not in actual or cid in seen:
            raise ValueError("Missing, duplicate or unauthorized claim lineage")
        seen.add(cid)
        edge = actual[cid]
        source = sources[edge["source_version_id"]]
        expected = {
            "claim_id": edge["claim_id"],
            "source_version_id": edge["source_version_id"],
            "source_sha256": source["sha256"],
            "source_available_at": source["available_at"],
            "claim_evidence_sha256": edge["evidence_sha256"],
            "subject_id": edge["subject_id"],
            "predicate": edge["predicate"],
            "object_id": edge["object_id"],
        }
        if any(row[key] != value or type(row[key]) is not str
               for key, value in expected.items()):
            raise ValueError("Claim lineage not bound to exact evidence/source bytes and graph edge")
        if row["derivation"] != EXTRACTION:
            raise ValueError("Alias, post-cutoff taxonomy, Falco mapping or derived feature forbidden")
        # Exact-only transformations have *no* external dependency or alias:
        # hence effective source availability is precisely the source version's
        # declared available_at. Later feature dates cannot pass.
        if (row["feature_known_at"] != source["available_at"]
                or as_utc(row["feature_known_at"]) > cutoff):
            raise ValueError("Feature availability violates exact-only historical source cutoff")
    return {
        "schema_version": CONTRACT_VERSION,
        "lineage_sha256": fingerprint(lineage),
        "validated_claim_lineage_count": len(entries),
        "resolution_policy": IDENTITY_POLICY,
        "source_available_at_is_independently_verified": False,
        "alias_mapping_permitted": False,
        "external_taxonomy_lookup_permitted": False,
        "later_rule_enrichment_permitted": False,
        "authenticated_source_and_reviewer_attestation": False,
        "research_ready": False,
    }
