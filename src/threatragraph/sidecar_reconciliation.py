"""Read-only reconciliation of frozen B0/G1 graphs with optional sidecars.

Portable exchanges and historically dated *candidate* aliases are checked
against the original source views, not injected into B0/G1 computations.
This cannot authenticate historical sources, labels or reviewer identity.
"""
from __future__ import annotations

from .alias_history import inspect_alias, validate_history
from .contracts import validate_graph_projection
from .evidence_graph import fingerprint
from .portable_exchange import verify_bundle

SIDE_CAR_VERSION = "offline-graph-sidecar-reconciliation-v1"


def reconcile_sidecars(b0_view, b0_graph, g1_view, g1_graph,
                       b0_bundle, g1_bundle, *, alias_history=None):
    """Compare read-only sidecar metadata against exact frozen profile inputs."""
    validate_graph_projection(b0_graph, b0_view, reviewed=True)
    validate_graph_projection(g1_graph, g1_view, reviewed=True)
    if (b0_view["method"] != "B0_sparse_report_only"
            or g1_view["method"] != "G1_early_plus_historical_background"
            or any(b0_view[key] != g1_view[key] for key in (
                "dataset_id", "dataset_version", "case_id",
                "target_entity_id", "cutoff_at",
            ))):
        raise ValueError("B0/G1 source-view identities are inconsistent")

    b0_early = {s["source_version_id"]: s for s in b0_view["sources"]}
    g1_early = {s["source_version_id"]: s for s in g1_view["sources"]
                if s["role"] == "early"}
    if b0_early != g1_early:
        raise ValueError("G1 early sources differ from B0")
    early_claims = {e["claim_id"]: e for e in b0_graph["edges"]}
    g1_early_claims = {e["claim_id"]: e for e in g1_graph["edges"]
                       if e["source_version_id"] in b0_early}
    if early_claims != g1_early_claims:
        raise ValueError("G1 graph early facts differ from B0")

    for method, view, graph, bundle in (
        ("B0", b0_view, b0_graph, b0_bundle),
        ("G1", g1_view, g1_graph, g1_bundle),
    ):
        verify_bundle(bundle)
        if (bundle["reviewed"] is not True
                or bundle["source_view"] != view
                or bundle["sourced_graph"] != graph
                or bundle["view_sha256"] != fingerprint(view)
                or bundle["graph_sha256"] != fingerprint(graph)):
            raise ValueError("Portable " + method + " evidence sidecar drift")

    alias_candidates = 0
    alias_conflicts = 0
    alias_digest = None
    if alias_history is not None:
        # Candidate aliases are never used to rebuild graphs or predictions.
        validate_history(b0_view, alias_history)
        alias_digest = alias_history["history_id"]
        aliases = sorted({x["alias_id"] for x in alias_history["entries"]})
        alias_candidates = len(aliases)
        alias_conflicts = sum(
            inspect_alias(b0_view, alias_history, name)["status"]
            == "ambiguous_candidates_require_adjudication"
            for name in aliases
        )

    receipt = {
        "schema_version": "1.0",
        "artifact_kind": "read_only_graph_sidecar_reconciliation",
        "contract_version": SIDE_CAR_VERSION,
        "case_id": b0_view["case_id"],
        "cutoff_at": b0_view["cutoff_at"],
        "b0_view_sha256": fingerprint(b0_view),
        "b0_graph_sha256": fingerprint(b0_graph),
        "g1_view_sha256": fingerprint(g1_view),
        "g1_graph_sha256": fingerprint(g1_graph),
        "portable_b0_id": b0_bundle["bundle_id"],
        "portable_g1_id": g1_bundle["bundle_id"],
        "alias_history_id": alias_digest,
        "alias_names_inspected": alias_candidates,
        "ambiguous_alias_names": alias_conflicts,
        "automatic_alias_rewrites": False,
        "g1_feature_lineage_modified": False,
        "historical_origins_authenticated": False,
        "semantic_review_authenticity_verified": False,
        "heldout_labels_read": False,
        "research_ready": False,
    }
    receipt["reconciliation_id"] = "sidecars:" + fingerprint(receipt)
    return receipt
