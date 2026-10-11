"""Separate, offline held-out-reference evaluation for *already frozen* B0/G1.

The profiling path never imports this module. This evaluator requires an
unchanged paired engineering run and only then admits a later-reference
partition. No original publisher/date/reviewer authentication is implied.
"""
from __future__ import annotations

from .evidence_graph import as_utc, fingerprint, require_sha, validate_triple
from .paired_profile_audit import audit_paired_profiles

REFERENCE_VERSION = "heldout-reference-partition-v1"
SCORER_VERSION = "independent-paired-label-scorer-v1"
DECISIONS = frozenset({
    "supported", "contradicted", "not_assessable", "duplicate", "out_of_scope",
})
_ROOT_FIELDS = frozenset({
    "schema_version", "artifact_kind", "case_id", "target_entity_id",
    "cutoff_at", "reference_window_end_at", "review_protocol_version",
    "review_status", "sources", "adjudications", "partition_id",
})
_SOURCE_FIELDS = frozenset({
    "source_version_id", "available_at", "sha256", "independence_group",
})
_LABEL_FIELDS = frozenset({
    "subject_id", "predicate", "object_id", "decision", "source_version_ids",
    "reviewer_ids", "rationale",
})
MAX_LABELS = 10000
MAX_REFERENCE_SOURCES = 1000


def _strict_dict(value, fields, where):
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(where + " requires exact versioned fields")
    return value


def _bounded_id(raw, what):
    if type(raw) is not str or not 0 < len(raw) <= 200 or not raw.strip():
        raise ValueError("Missing or excessive " + what)
    return raw


def _triple(item):
    key = (item["subject_id"], item["predicate"], item["object_id"])
    validate_triple(*key)
    return key


def seal_reference_partition(record):
    """Add a content hash to a *draft*, without certifying source review."""
    if not isinstance(record, dict) or "partition_id" in record:
        raise ValueError("Seal only an unsigned candidate partition")
    candidate = {**record, "partition_id": "reference:" + fingerprint(record)}
    validate_reference_partition(candidate)
    return candidate


def validate_reference_partition(partition):
    """Validate independent *metadata structure*, not reviewer authenticity."""
    obj = _strict_dict(partition, _ROOT_FIELDS, "Reference partition")
    if (obj["schema_version"] != "1.0"
            or obj["artifact_kind"] != "heldout_reference_adjudications"
            or obj["review_status"] != "candidate_unapproved"):
        raise ValueError("Unsupported or prematurely approved reference partition")
    for name in ("case_id", "target_entity_id", "review_protocol_version"):
        _bounded_id(obj[name], name)
    cutoff = as_utc(obj["cutoff_at"])
    end = as_utc(obj["reference_window_end_at"])
    if end <= cutoff:
        raise ValueError("Later reference window must follow target cutoff")
    source_items = obj["sources"]
    if (not isinstance(source_items, list)
            or len(source_items) > MAX_REFERENCE_SOURCES):
        raise ValueError("Reference sources are unbounded")
    sources = {}
    for row in source_items:
        item = _strict_dict(row, _SOURCE_FIELDS, "Reference source")
        sid = _bounded_id(item["source_version_id"], "reference version")
        if sid in sources:
            raise ValueError("Duplicate reference source version")
        require_sha(item["sha256"], "reference source SHA")
        _bounded_id(item["independence_group"], "reference publisher group")
        when = as_utc(item["available_at"])
        if not cutoff < when <= end:
            raise ValueError("Reference source must be later than cutoff and within window")
        sources[sid] = item

    entries = obj["adjudications"]
    if not isinstance(entries, list) or not 0 < len(entries) <= MAX_LABELS:
        raise ValueError("At least one bounded adjudication is required")
    labels = {}
    order = []
    for row in entries:
        item = _strict_dict(row, _LABEL_FIELDS, "Reference adjudication")
        key = _triple(item)
        if obj["target_entity_id"] not in (key[0], key[2]):
            raise ValueError("Reference label is not for the target entity")
        if key in labels:
            raise ValueError("Duplicate relation in reference adjudications")
        if item["decision"] not in DECISIONS:
            raise ValueError("Unsupported held-out adjudication decision")
        witness = item["source_version_ids"]
        reviewers = item["reviewer_ids"]
        if (not isinstance(witness, list)
                or len(witness) > MAX_REFERENCE_SOURCES
                or len(witness) != len(set(witness))
                or any(type(s) is not str or s not in sources for s in witness)):
            raise ValueError("Invalid or future reference witness set")
        if item["decision"] in ("supported", "contradicted") and not witness:
            raise ValueError("Assessable decision requires an explicit later reference")
        if (not isinstance(reviewers, list) or len(reviewers) != 2
                or any(type(s) is not str or not s.strip() or len(s) > 200
                       for s in reviewers)
                or len(set(reviewers)) != 2):
            raise ValueError("Two distinct declared reviewers required")
        rationale = item["rationale"]
        if type(rationale) is not str or not 0 < len(rationale.strip()) <= 1200:
            raise ValueError("Bounded manual adjudication rationale required")
        labels[key] = item
        order.append(key)
    if order != sorted(order):
        raise ValueError("Reference adjudications must have canonical triple ordering")
    unsigned = {k: v for k, v in obj.items() if k != "partition_id"}
    if obj["partition_id"] != "reference:" + fingerprint(unsigned):
        raise ValueError("Reference partition digest does not match content")
    return labels


def validate_frozen_pair(b0, g1, audit, lock):
    """Check the profiling artifact boundary BEFORE accessing any labels."""
    expected = audit_paired_profiles(b0, g1)
    if audit != expected:
        raise ValueError("Sealed paired audit is missing or altered")
    if not isinstance(lock, dict):
        raise ValueError("Frozen run-lock object required")
    if (lock.get("schema_version") != "1.0"
            or lock.get("artifact_kind") != "paired_run_engineering_lock"
            or lock.get("lock_version") != "paired-run-engineering-lock-v1"):
        raise ValueError("Unsupported frozen engineering run")
    if lock.get("run_id") != "run:" + fingerprint(
            {k: v for k, v in lock.items() if k != "run_id"}):
        raise ValueError("Frozen run-lock fingerprint differs from content")
    for name, expected_value in (
        ("case_id", b0["case_id"]),
        ("target_entity_id", b0["target_entity_id"]),
        ("cutoff_at", b0["cutoff_at"]),
        ("dataset_id", b0["dataset_id"]),
        ("dataset_version", b0["dataset_version"]),
        ("b0_profile_id", b0["profile_id"]),
        ("g1_profile_id", g1["profile_id"]),
        ("paired_audit_id", expected["audit_id"]),
        ("early_source_version_ids", expected["early_source_version_ids"]),
        ("observed_fact_count", expected["observed_early_fact_count"]),
        ("provisional_prediction_count", expected["g1_provisional_prediction_count"]),
        ("g1_algorithm_config", g1["configuration"]),
        ("gold_labels_read", False),
        ("predictions_sealed_before_gold_access", True),
        ("research_ready", False),
    ):
        if lock.get(name) != expected_value:
            raise ValueError("Frozen run-lock identity/access guard differs: " + name)
    inputs = lock.get("input_artifact_sha256")
    if (not isinstance(inputs, dict)
            or set(inputs) != {
                "b0_view", "b0_graph", "g1_view", "g1_graph", "feature_lineage",
            }):
        raise ValueError("Run-lock input hash set missing")
    for name, digest in inputs.items():
        require_sha(digest, "run input " + name)
    if lock.get("independent_study_approval") != "not_verified":
        raise ValueError("Run lock cannot claim independent research approval")
    if lock.get("empirical_evaluation") != "not_performed":
        raise ValueError("Run lock already contains evaluation state")
    return expected


def _score_items(items, label_map):
    rows = []
    counts = dict.fromkeys((
        "supported", "contradicted", "not_assessable",
        "duplicate", "out_of_scope",
    ), 0)
    for item in items:
        key = _triple(item)
        adjudication = label_map.get(key)
        verdict = adjudication["decision"] if adjudication else "not_assessable"
        counts[verdict] += 1
        rows.append({
            "subject_id": key[0], "predicate": key[1], "object_id": key[2],
            "profile_item_sha256": fingerprint(item),
            "decision": verdict,
            "decision_origin": (
                "explicit_heldout_adjudication" if adjudication
                else "unlabeled_not_assessable_no_negative_imputation"
            ),
            "reference_source_version_ids": (
                list(adjudication["source_version_ids"])
                if adjudication else []
            ),
        })
    assessable = counts["supported"] + counts["contradicted"]
    return {
        "submitted_relation_count": len(items),
        "supported_count": counts["supported"],
        "contradicted_count": counts["contradicted"],
        "not_assessable_count": counts["not_assessable"],
        "duplicate_count": counts["duplicate"],
        "out_of_scope_count": counts["out_of_scope"],
        "assessable_denominator": assessable,
        "assessable_precision": (
            counts["supported"] / assessable if assessable else None
        ),
        "rows": rows,
    }


def score_frozen_pair(b0, g1, audit, lock, reference_partition):
    """Score later labels, never revise any frozen profiler artifacts."""
    validated = validate_frozen_pair(b0, g1, audit, lock)
    labels = validate_reference_partition(reference_partition)
    if (reference_partition["case_id"] != b0["case_id"]
            or reference_partition["target_entity_id"] != b0["target_entity_id"]
            or reference_partition["cutoff_at"] != b0["cutoff_at"]):
        raise ValueError("Held-out label partition belongs to a different case/cutoff")
    early = b0["facts"]
    hypotheses = g1["predictions"]
    known_supported = {key for key, item in labels.items()
                       if item["decision"] == "supported"}
    b0_keys = {_triple(item) for item in early}
    g1_keys = b0_keys | {_triple(item) for item in hypotheses}
    denominator = len(known_supported)

    result = {
        "schema_version": "1.0",
        "artifact_kind": "candidate_paired_reference_evaluation",
        "scorer_version": SCORER_VERSION,
        "case_id": b0["case_id"],
        "cutoff_at": b0["cutoff_at"],
        "frozen_run_id": lock["run_id"],
        "paired_audit_id": validated["audit_id"],
        "reference_partition_id": reference_partition["partition_id"],
        "label_partition_review_status": "candidate_unapproved",
        "methods": {
            "B0_observed": _score_items(early, labels),
            "G1_observed": _score_items(g1["observed_early_facts"], labels),
            "G1_novel_proposals": _score_items(hypotheses, labels),
            "G1_combined_profile": _score_items([*early, *hypotheses], labels),
        },
        "supported_reference_denominator": denominator,
        "supported_reference_coverage": {
            "B0": {
                "matched": len(b0_keys & known_supported),
                "denominator": denominator,
                "fraction": (
                    len(b0_keys & known_supported) / denominator
                    if denominator else None
                ),
            },
            "G1": {
                "matched": len(g1_keys & known_supported),
                "denominator": denominator,
                "fraction": (
                    len(g1_keys & known_supported) / denominator
                    if denominator else None
                ),
            },
        },
        "g1_abstained": g1["abstention"]["abstained"],
        "evaluator_saw_later_reference_only_after_frozen_run_validation": True,
        "external_prediction_freeze_authenticated": False,
        "reference_source_rights_and_reviewer_identity_authenticated": False,
        "label_set_exhaustiveness_verified": False,
        "research_ready": False,
        "empirical_evaluation": "candidate_or_synthetic_only",
        "caveat": (
            "Unmentioned relations are not false. Precision denominator is "
            "explicitly supported+contradicted only; reference coverage is "
            "limited to positively labeled subset, not proven population recall. "
            "No trusted timestamps, source rights or reviewer identity verified."
        ),
    }
    result["evaluation_id"] = "evaluation:" + fingerprint(result)
    return result


def aggregate_candidate_evaluations(reports):
    """Micro descriptive totals only; no significance claims or fake cases."""
    if not isinstance(reports, list) or not reports or len(reports) > 100:
        raise ValueError("Bounded nonempty case evaluation list required")
    case_ids = set()
    keys = ("B0_observed", "G1_novel_proposals", "G1_combined_profile")
    tallies = {name: {"supported": 0, "contradicted": 0,
                       "not_assessable": 0, "cases_with_assessable": 0}
               for name in keys}
    for report in reports:
        if (not isinstance(report, dict)
                or report.get("artifact_kind") != "candidate_paired_reference_evaluation"
                or report.get("research_ready") is not False
                or report.get("evaluation_id") != "evaluation:" + fingerprint(
                    {k: v for k, v in report.items() if k != "evaluation_id"}
                )):
            raise ValueError("Tampered or unsupported case evaluation")
        case_id = report["case_id"]
        if not isinstance(case_id, str) or case_id in case_ids:
            raise ValueError("Duplicate or invalid case in evaluation aggregate")
        case_ids.add(case_id)
        for name in keys:
            line = report["methods"][name]
            count = line["supported_count"] + line["contradicted_count"]
            if count != line["assessable_denominator"]:
                raise ValueError("Case precision denominator inconsistent")
            agg = tallies[name]
            agg["supported"] += line["supported_count"]
            agg["contradicted"] += line["contradicted_count"]
            agg["not_assessable"] += line["not_assessable_count"]
            agg["cases_with_assessable"] += int(count > 0)
    for agg in tallies.values():
        d = agg["supported"] + agg["contradicted"]
        agg["assessable_denominator"] = d
        agg["micro_assessable_precision"] = (
            agg["supported"] / d if d else None
        )
    out = {
        "schema_version": "1.0",
        "artifact_kind": "candidate_paired_reference_aggregate",
        "scorer_version": SCORER_VERSION,
        "case_ids": sorted(case_ids),
        "case_count": len(case_ids),
        "methods": tallies,
        "inferential_significance_claimed": False,
        "reference_population_completeness_verified": False,
        "research_ready": False,
    }
    out["aggregate_id"] = "aggregate:" + fingerprint(out)
    return out
