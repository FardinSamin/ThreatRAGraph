"""Offline B0/G1 paired-run generator and content-addressed *engineering* lock.

No held-out references, source acquisition or evaluation. The lock binds
declared metadata and deterministic input/output digests; it is NOT an
independent historical/source-rights/reviewer or study certification.
"""
from __future__ import annotations

import re

from .baseline_b0 import build_b0_profile
from .evidence_graph import fingerprint
from .paired_profile_audit import audit_paired_profiles
from .similarity_g1 import build_g1_profile

RUN_LOCK_VERSION = "paired-run-engineering-lock-v1"
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_META_FIELDS = frozenset({
    "git_commit_sha", "dependency_lock_sha256", "source_manifest_sha256",
    "case_manifest_sha256", "review_set_sha256", "ontology_version",
    "extractor_version", "ruleset_version", "random_seed",
})
_G1_CONFIG_FIELDS = frozenset({
    "top_k", "min_overlap", "min_background_groups", "max_peers_per_feature",
})


def _metadata(record):
    if not isinstance(record, dict) or set(record) != _META_FIELDS:
        raise ValueError("Run metadata requires exact reproducibility fields")
    sha = record["git_commit_sha"]
    if type(sha) is not str or _SHA40.fullmatch(sha) is None:
        raise ValueError("Full lowercase immutable Git commit SHA required")
    for key in ("dependency_lock_sha256", "source_manifest_sha256",
                "case_manifest_sha256", "review_set_sha256"):
        value = record[key]
        if type(value) is not str or _SHA256.fullmatch(value) is None:
            raise ValueError("Pinned SHA-256 required: " + key)
    for key in ("ontology_version", "extractor_version", "ruleset_version"):
        value = record[key]
        if (type(value) is not str or not value.strip() or len(value) > 160
                or any(c in value for c in "\r\n\x00")):
            raise ValueError("Nonempty bounded research version required: " + key)
    if record["random_seed"] is not None:
        raise ValueError("B0/G1 v1 engines use no RNG; random_seed must be null")
    return dict(record)


def _json_object(value, name):
    if not isinstance(value, dict):
        raise ValueError(name + " must be a JSON object")
    if any(not isinstance(key, str) for key in value):
        raise ValueError(name + " must have string keys")
    return value


def build_paired_run(
    b0_view, b0_graph, g1_view, g1_graph, feature_lineage,
    *, metadata, g1_config, development_only=False,
):
    """Compute both profiles without labels, audit parity, seal a reproducible receipt.

    This is a structural engineering build step. External source dates, review
    attestations, original bytes and rights remain unverified.
    """
    if type(development_only) is not bool:
        raise ValueError("development_only must be a boolean")
    attrs = _metadata(metadata)
    config = _json_object(g1_config, "G1 configuration")
    if set(config) != _G1_CONFIG_FIELDS:
        raise ValueError("G1 config must declare exactly four algorithm parameters")
    inputs = {
        "b0_view": _json_object(b0_view, "B0 source view"),
        "b0_graph": _json_object(b0_graph, "B0 sourced graph"),
        "g1_view": _json_object(g1_view, "G1 source view"),
        "g1_graph": _json_object(g1_graph, "G1 sourced graph"),
        "feature_lineage": _json_object(feature_lineage, "As-of feature lineage"),
    }
    b0 = build_b0_profile(
        inputs["b0_view"], inputs["b0_graph"],
        development_only=development_only,
    )
    g1 = build_g1_profile(
        inputs["b0_view"], inputs["b0_graph"],
        inputs["g1_view"], inputs["g1_graph"],
        feature_lineage=inputs["feature_lineage"],
        development_only=development_only,
        **config,
    )
    audited = audit_paired_profiles(b0, g1)
    if not audited["early_output_parity_verified"]:
        raise ValueError("Cross-method initial evidence parity not established")
    if g1.get("configuration") != config:
        raise ValueError("Runtime G1 configuration differs from frozen config")
    if g1["b0_profile_id"] != b0["profile_id"]:
        raise ValueError("Runtime G1 did not consume identical B0")

    lock = {
        "schema_version": "1.0",
        "artifact_kind": "paired_run_engineering_lock",
        "lock_version": RUN_LOCK_VERSION,
        "case_id": b0["case_id"],
        "dataset_id": b0["dataset_id"],
        "dataset_version": b0["dataset_version"],
        "target_entity_id": b0["target_entity_id"],
        "cutoff_at": b0["cutoff_at"],
        "declared_provenance": attrs,
        "development_only": development_only,
        "g1_algorithm_config": dict(config),
        "input_artifact_sha256": {
            key: fingerprint(value) for key, value in sorted(inputs.items())
        },
        "b0_profile_id": b0["profile_id"],
        "g1_profile_id": g1["profile_id"],
        "paired_audit_id": audited["audit_id"],
        "early_source_version_ids": audited["early_source_version_ids"],
        "observed_fact_count": audited["observed_early_fact_count"],
        "provisional_prediction_count": audited["g1_provisional_prediction_count"],
        "gold_labels_read": False,
        "predictions_sealed_before_gold_access": True,
        "historical_dates_and_rights_independently_verified": False,
        "reviewer_identities_independently_verified": False,
        "source_manifest_bytes_verified_by_this_module": False,
        "empirical_evaluation": "not_performed",
        "independent_study_approval": "not_verified",
        "research_ready": False,
    }
    lock["run_id"] = "run:" + fingerprint(lock)
    return {
        "b0_profile": b0,
        "g1_profile": g1,
        "paired_audit": audited,
        "run_lock": lock,
    }
