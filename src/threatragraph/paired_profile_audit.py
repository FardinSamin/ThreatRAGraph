"""Strict, offline B0/G1 *output* parity check for future paired studies.

This module deliberately does not load held-out labels, original article text,
or untrusted archive URLs. It checks deterministic profile identities and
cross-method early-input parity; it cannot authenticate historical chronology,
researcher independence, reviewer identities, or ground truth.
"""
from __future__ import annotations

import math
from typing import Any

from .evidence_graph import fingerprint, require_sha, validate_triple

AUDIT_VERSION = "paired-profile-output-audit-v1"
MAX_EARLY_FACTS = 10000
MAX_PROPOSALS = 25
FORBIDDEN_CONTEXT = frozenset({
    "gold_labels", "outcome_labels", "heldout_labels",
    "later_reference_sources", "evaluation_answers", "ground_truth",
})


def _object(value: Any, description: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(description + " must be an object")
    return value


def _list(value: Any, description: str, limit: int) -> list:
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(description + " must be a bounded list")
    return value


def _profile_identity(profile: dict, method: str, kind: str) -> str:
    if profile.get("schema_version") != "1.0":
        raise ValueError("Unknown profile schema")
    if profile.get("method") != method or profile.get("profile_kind") != kind:
        raise ValueError("Incorrect method or output contract")
    if FORBIDDEN_CONTEXT.intersection(profile):
        raise ValueError("Held-out reference context cannot enter profiles")
    if profile.get("research_ready") is not False:
        raise ValueError("Unreviewed paired profiles cannot claim research readiness")
    claimed = profile.get("profile_id")
    unsigned = {key: value for key, value in profile.items()
                if key != "profile_id"}
    expected = "profile:" + fingerprint(unsigned)
    if claimed != expected:
        raise ValueError("Profile content differs from claimed digest")
    return claimed


def _triple(record: Any, *, target: str, kind: str,
            outgoing_only: bool = False) -> tuple:
    item = _object(record, kind)
    subject = item.get("subject_id")
    predicate = item.get("predicate")
    obj = item.get("object_id")
    validate_triple(subject, predicate, obj)
    if ((outgoing_only and subject != target)
            or (not outgoing_only and target not in (subject, obj))):
        raise ValueError(kind + " must describe the fixed target entity")
    if FORBIDDEN_CONTEXT.intersection(item):
        raise ValueError("Held-out reference fields cannot enter claim output")
    return subject, predicate, obj


def _observed(profile: dict, ids: set[str]) -> tuple:
    facts = _list(profile.get("facts"), "B0 facts", MAX_EARLY_FACTS)
    seen = set()
    for fact in facts:
        triple = _triple(fact, target=profile["target_entity_id"],
                         kind="B0 early-source assertion")
        if triple in seen:
            raise ValueError("Duplicate B0 observed triple")
        seen.add(triple)
        if fact.get("status") != "asserted_in_early_reports":
            raise ValueError("B0 must not promote hypotheses into observed facts")
        sources = _list(fact.get("source_version_ids"),
                        "B0 fact sources", MAX_EARLY_FACTS)
        claims = _list(fact.get("supporting_claim_ids"),
                       "B0 fact claim paths", MAX_EARLY_FACTS)
        if (not sources or len(sources) != len(set(sources))
                or not set(sources) <= ids or not claims):
            raise ValueError("Observed fact lacks exact early-source provenance")
        if fact.get("score") is not None or fact.get("confidence") is not None:
            raise ValueError("B0 facts must not be assigned inferred probabilities")
    return facts, seen


def audit_paired_profiles(b0_profile: dict, g1_profile: dict) -> dict:
    """Audit only structural output parity; never score or inspect later labels."""
    b0 = _object(b0_profile, "B0 profile")
    g1 = _object(g1_profile, "G1 profile")
    b0_id = _profile_identity(b0, "B0", "cold_start_report_only")
    g1_id = _profile_identity(g1, "G1", "graph_assisted_provisional_hypotheses")

    for key in ("dataset_id", "dataset_version", "case_id",
                "target_entity_id", "cutoff_at"):
        if not isinstance(b0.get(key), str) or not b0[key]:
            raise ValueError("Missing case identity in B0: " + key)
        if g1.get(key) != b0[key]:
            raise ValueError("B0/G1 case identity differs: " + key)
    if g1.get("b0_profile_id") != b0_id:
        raise ValueError("G1 is not bound to this exact B0 profile")

    b0_view = require_sha(b0.get("source_view_sha256"), "B0 source view")
    g1_b0_view = require_sha(g1.get("b0_source_view_sha256"),
                             "G1-bound B0 source view")
    require_sha(g1.get("g1_source_view_sha256"), "G1 source view")
    require_sha(g1.get("feature_lineage_sha256"), "G1 feature lineage")
    if b0_view != g1_b0_view:
        raise ValueError("B0/G1 initial source-view digest differs")

    early = _list(b0.get("early_source_version_ids"), "Early source IDs", 2)
    early_g1 = _list(g1.get("early_source_version_ids"),
                     "G1 early source IDs", 2)
    if (len(early) not in (1, 2) or len(early) != len(set(early))
            or not all(isinstance(s, str) and s for s in early)):
        raise ValueError("B0 must contain one or two distinct early versions")
    if early_g1 != early:
        raise ValueError("B0/G1 early source-version IDs differ")

    if b0.get("predictions") != []:
        raise ValueError("B0 must never produce inferred predictions")
    facts, observed_triples = _observed(b0, set(early))
    if g1.get("observed_early_facts") != facts:
        raise ValueError("G1 early facts differ from exact B0 facts")

    proposals = _list(g1.get("predictions"), "G1 predictions", MAX_PROPOSALS)
    config = _object(g1.get("configuration"), "G1 configuration")
    top_k = config.get("top_k")
    if type(top_k) is not int or not 1 <= top_k <= MAX_PROPOSALS:
        raise ValueError("G1 top-k must be a bounded positive integer")
    if len(proposals) > top_k:
        raise ValueError("G1 emitted more predictions than declared top-k")
    seen = set()
    for proposal in proposals:
        triple = _triple(proposal, target=b0["target_entity_id"],
                         kind="G1 provisional prediction",
                         outgoing_only=True)
        if triple in seen or triple in observed_triples:
            raise ValueError("Duplicate or already-observed G1 prediction")
        seen.add(triple)
        if (proposal.get("status") !=
                "provisional_graph_analogy_not_sourced_fact"
                or proposal.get("score_kind") !=
                "uncalibrated_jaccard_not_probability"):
            raise ValueError("G1 predictions must remain uncalibrated hypotheses")
        score = proposal.get("ranking_score")
        if (type(score) not in (int, float) or not math.isfinite(score)
                or not 0 <= score <= 1):
            raise ValueError("G1 ranking score is invalid")
        groups = _list(proposal.get("historical_independence_groups"),
                       "G1 background independence groups", 100)
        support = _list(proposal.get("proposed_relation_historical_support"),
                        "G1 source paths", 100)
        matched = _list(proposal.get("matching_features"),
                        "G1 matching features", 100)
        if (len(groups) < 2 or len(groups) != len(set(groups))
                or not support or not matched):
            raise ValueError("G1 lacks distinct support groups or source paths")

    abstention = _object(g1.get("abstention"), "G1 abstention")
    if abstention.get("abstained") is not (len(proposals) == 0):
        raise ValueError("G1 prediction count contradicts abstention flag")

    receipt = {
        "schema_version": "1.0",
        "artifact_kind": "paired_profile_output_parity_audit",
        "audit_version": AUDIT_VERSION,
        "case_id": b0["case_id"],
        "cutoff_at": b0["cutoff_at"],
        "b0_profile_id": b0_id,
        "g1_profile_id": g1_id,
        "common_early_source_view_sha256": b0_view,
        "early_source_version_ids": list(early),
        "early_fact_set_sha256": fingerprint({"facts": facts}),
        "observed_early_fact_count": len(facts),
        "g1_provisional_prediction_count": len(proposals),
        "early_output_parity_verified": True,
        "heldout_labels_accessed": False,
        "historical_source_authenticity_verified": False,
        "independent_study_approval": "not_verified",
        "empirical_evaluation": "not_performed",
        "research_ready": False,
    }
    receipt["audit_id"] = "audit:" + fingerprint(receipt)
    return receipt
