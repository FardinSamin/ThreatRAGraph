"""M5 G1 v1: deterministic, non-probabilistic graph-analogy hypotheses.

G1 receives paired sealed B0/G1 source views and attributed graphs. It never
loads original corpus text, reference labels, model weights, embeddings, or
newer ontology/alias revisions. Source provenance and *as-of feature lineage*
must also be independently audited upstream; this module alone cannot certify
historical authenticity, reviewer identity or empirical readiness.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from .baseline_b0 import build_b0_profile
from .contracts import validate_graph_projection
from .evidence_graph import fingerprint, require_id, validate_triple
from .feature_lineage import validate_asof_lineage
from .readiness import readiness_disclosure

METHOD = "g1-historical-typed-jaccard-v2-lineage"
G1_VIEW_METHOD = "G1_early_plus_historical_background"
B0_VIEW_METHOD = "B0_sparse_report_only"
# No actor attribution, runtime-observed execution, CVE exploitation, or Falco
# detection is extrapolated. Only structurally analogous source assertions.
FEATURE_PREDICATES = frozenset({"USES", "HAS_BEHAVIOR"})
PREDICTABLE_PREDICATES = frozenset({"USES", "HAS_BEHAVIOR"})
MAX_TOP_K = 25
MAX_PATHS = 24


def _source_groups(view):
    result = {}
    for record in view["sources"]:
        result[record["source_version_id"]] = (
            record["role"], record["independence_group"]
        )
    return result


def _support(edge, group):
    return {
        "claim_id": edge["claim_id"],
        "source_version_id": edge["source_version_id"],
        "independence_group": group,
        "evidence_sha256": edge["evidence_sha256"],
        "evidence_locator": edge["evidence_locator"],
    }


def _sorted_support(edges, groups):
    return [
        _support(e, groups[e["source_version_id"]][1])
        for e in sorted(edges, key=lambda e: (e["source_version_id"], e["claim_id"]))
    ][:MAX_PATHS]


def build_g1_profile(
    b0_view: dict, b0_graph: dict, g1_view: dict, g1_graph: dict,
    *, feature_lineage: dict, top_k: int = 5, min_overlap: int = 1,
    min_background_groups: int = 2,
    max_peers_per_feature: int = 10, development_only: bool = False,
) -> dict:
    """Rank historically eligible analogies; abstain on weak corroboration.

    Structurally valid JSON and synthetic semantic review tags are NOT
    independent historical/corpus certification.
    """
    if (type(development_only) is not bool or type(top_k) is not int
            or type(min_overlap) is not int or type(min_background_groups) is not int
            or type(max_peers_per_feature) is not int
            or not 1 <= top_k <= MAX_TOP_K or not 1 <= min_overlap <= 10
            or not 2 <= min_background_groups <= 10
            or not 1 <= max_peers_per_feature <= 100):
        raise ValueError("Invalid bounded G1 configuration")
    validate_graph_projection(b0_graph, b0_view, reviewed=True)
    validate_graph_projection(g1_graph, g1_view, reviewed=True)
    lineage_report = validate_asof_lineage(feature_lineage, g1_view, g1_graph)
    if b0_view["method"] != B0_VIEW_METHOD or g1_view["method"] != G1_VIEW_METHOD:
        raise ValueError("Sealed B0 and G1 source views required")
    for key in ("dataset_id", "dataset_version", "case_id", "target_entity_id", "cutoff_at"):
        if b0_view[key] != g1_view[key]:
            raise ValueError(f"Paired early-input identity mismatch: {key}")
    target = require_id(b0_view["target_entity_id"], "target_entity_id")
    # Existing B0 contract verifies every early evidence claim. Reuse it
    # unchanged, rather than reimplementing a softer "report-only" baseline.
    observed = build_b0_profile(
        b0_view, b0_graph, development_only=development_only
    )
    b0_sources = {x["source_version_id"]: x for x in b0_view["sources"]}
    g1_early = {x["source_version_id"]: x for x in g1_view["sources"]
                if x["role"] == "early"}
    if b0_sources != g1_early or len(g1_early) != len(b0_view["sources"]):
        raise ValueError("G1 early source metadata differs from B0 input")
    b0_claims = {e["claim_id"]: e for e in b0_graph["edges"]}
    g1_early_claims = {
        e["claim_id"]: e for e in g1_graph["edges"]
        if e["source_version_id"] in b0_sources
    }
    if b0_claims != g1_early_claims or len(b0_graph["edges"]) != len(g1_early_claims):
        raise ValueError("G1 early reviewed claims differ from exact B0 projection")

    source_groups = _source_groups(g1_view)
    early_groups = {x["independence_group"] for x in b0_view["sources"]}
    bg_versions = {k for k, (role, _) in source_groups.items() if role == "background"}
    background_groups = {
        source_groups[version][1] for version in bg_versions
    }
    if early_groups & background_groups:
        raise ValueError("Correlated early/background source independence group")
    early_edges = list(b0_graph["edges"])
    bg_edges = [e for e in g1_graph["edges"]
                if e["source_version_id"] in bg_versions]
    if len(bg_edges) + len(early_edges) != len(g1_graph["edges"]):
        raise ValueError("G1 graph references forbidden source partition")
    if any(target in (e["subject_id"], e["object_id"]) for e in bg_edges):
        raise ValueError("Target-specific evidence leaked into historical background")
    for e in bg_edges:
        if e["evidence_status"] != "aligned":
            raise ValueError("G1 refuses historically unaligned source evidence")
        if not development_only and e["semantic_review_status"] != "supported_by_excerpt":
            raise ValueError("G1 strict run requires reviewed historical claims")

    # Only positive, supported *report assertions* supply an analogy.
    # Falco rule semantics are not observations of incidents and must never
    # be lifted from the rule plane into threat-actor facts.
    def eligible(edge):
        return (edge["assertion_kind"] == "report_assertion"
                and edge["evidence_status"] == "aligned"
                and edge["semantic_review_status"] == "supported_by_excerpt"
                and edge["polarity"] == "positive")

    early_all = {(e["subject_id"], e["predicate"], e["object_id"])
                 for e in early_edges}
    # Reuse B0's *conflict-resolved* feature decisions. A positive early claim
    # contradicted by another reviewed negative must not seed G1 similarity.
    accepted_early = {
        (f["subject_id"], f["predicate"], f["object_id"])
        for f in observed["facts"]
    }
    # A supported negative/uncertain historical report on a peer's relation
    # defeats that peer edge as positive analogy or inferred target behavior.
    disputed_background = {
        (e["subject_id"], e["predicate"], e["object_id"])
        for e in bg_edges
        if (e["assertion_kind"] == "report_assertion"
            and e["evidence_status"] == "aligned"
            and e["semantic_review_status"] == "supported_by_excerpt"
            and e["polarity"] in {"negative", "uncertain"})
    }
    target_features = defaultdict(list)
    for e in early_edges:
        if (eligible(e) and e["subject_id"] == target
                and e["predicate"] in FEATURE_PREDICATES
                and (e["subject_id"], e["predicate"], e["object_id"]) in accepted_early):
            target_features[(e["predicate"], e["object_id"])].append(e)

    peer_type = target.split(":", 1)[0]
    peer_features = defaultdict(lambda: defaultdict(list))
    for e in bg_edges:
        if (eligible(e) and e["subject_id"] != target
                and e["subject_id"].split(":", 1)[0] == peer_type
                and e["predicate"] in FEATURE_PREDICATES
                and (e["subject_id"], e["predicate"], e["object_id"]) not in disputed_background):
            peer_features[e["subject_id"]][(e["predicate"], e["object_id"])].append(e)

    counts = Counter(k for features in peer_features.values() for k in features)
    active = {
        k for k in target_features
        if counts.get(k, 0) <= max_peers_per_feature
    }
    proposals = {}
    peers_considered = 0
    weak_corroboration = 0
    for peer in sorted(peer_features):
        features = peer_features[peer]
        shared = active & set(features)
        if len(shared) < min_overlap:
            continue
        union = active | set(features)
        if not union:
            continue
        peers_considered += 1
        # Stable uncalibrated weighted-Jaccard v1 with equal feature weights.
        score = round(len(shared) / len(union), 6)
        matching = [
            {
                "feature": {"predicate": k[0], "object_id": k[1]},
                "early_support": _sorted_support(target_features[k], source_groups),
                "historical_support": _sorted_support(features[k], source_groups),
            }
            for k in sorted(shared)
        ]
        for candidate in sorted(features):
            if candidate in target_features or candidate[0] not in PREDICTABLE_PREDICATES:
                continue
            triple = (target, candidate[0], candidate[1])
            validate_triple(*triple)
            if triple in early_all:
                # Prevent contradiction and duplicate/source-confirmed inference,
                # including negative and uncertain early target assertions.
                continue
            proposed_edges = features[candidate]
            groups = {
                source_groups[e["source_version_id"]][1] for e in proposed_edges
            }
            groups.update(
                source_groups[e["source_version_id"]][1]
                for feature in shared for e in features[feature]
            )
            if len(groups) < min_background_groups:
                weak_corroboration += 1
                continue
            key = triple
            hypothesis = {
                "subject_id": target,
                "predicate": candidate[0],
                "object_id": candidate[1],
                "status": "provisional_graph_analogy_not_sourced_fact",
                "analog_peer_id": peer,
                "ranking_score": score,
                "score_kind": "uncalibrated_jaccard_not_probability",
                "historical_independence_groups": sorted(groups),
                "matching_features": matching,
                "proposed_relation_historical_support": _sorted_support(
                    proposed_edges, source_groups
                ),
            }
            proposals.setdefault(key, []).append(hypothesis)

    ranked = []
    for key, hypotheses in sorted(proposals.items()):
        # A candidate is never upgraded to sourced truth, even if multiple
        # peers independently propose the same triple.
        hypotheses.sort(key=lambda h: (-h["ranking_score"], h["analog_peer_id"]))
        winner = hypotheses[0]
        ranked.append({
            **winner,
            "alternative_peer_ids": sorted({
                h["analog_peer_id"] for h in hypotheses[1:]
            }),
        })
    ranked.sort(key=lambda h: (-h["ranking_score"], h["predicate"], h["object_id"], h["analog_peer_id"]))
    predictions = ranked[:top_k]
    reason = None if predictions else (
        "no_reviewed_early_target_features" if not target_features
        else "no_eligible_historical_analogy_with_independent_support"
    )
    output = {
        "schema_version": "1.0",
        "profile_kind": "graph_assisted_provisional_hypotheses",
        "method": "G1",
        "method_version": METHOD,
        "dataset_id": b0_view["dataset_id"],
        "dataset_version": b0_view["dataset_version"],
        "case_id": b0_view["case_id"],
        "target_entity_id": target,
        "cutoff_at": b0_view["cutoff_at"],
        "b0_profile_id": observed["profile_id"],
        "b0_source_view_sha256": b0_graph["source_view_sha256"],
        "g1_source_view_sha256": g1_graph["source_view_sha256"],
        "feature_lineage_sha256": lineage_report["lineage_sha256"],
        "feature_lineage_contract": lineage_report,
        "early_source_version_ids": sorted(b0_sources),
        "observed_early_facts": observed["facts"],
        "predictions": predictions,
        "abstention": {"abstained": not bool(predictions), "reason": reason},
        "configuration": {
            "top_k": top_k, "min_overlap": min_overlap,
            "min_background_groups": min_background_groups,
            "max_peers_per_feature": max_peers_per_feature,
        },
        "diagnostics": {
            "reviewed_target_feature_count": len(target_features),
            "historical_background_source_count": len(bg_versions),
            "historical_peer_count": len(peer_features),
            "eligible_peer_count": peers_considered,
            "candidate_count_before_top_k": len(ranked),
            "weak_independence_rejections": weak_corroboration,
            "popular_target_features_discarded": len(target_features) - len(active),
        },
        "readiness": readiness_disclosure(development_only=development_only),
        "research_ready": False,
        "limitations": (
            "Synthetic-tested exact-only as-of lineage is asserted by supplied "
            "metadata, not independently authenticated or verified against original "
            "archive bytes, source-native identifiers or external reviewer identity. "
            "Rank score is not a probability, future outcome or observed attack."
        ),
    }
    output["profile_id"] = "profile:" + fingerprint(output)
    return output
