"""Offline structural replay verification of an already written unscored batch.

Never opens original publisher bytes, held-out labels, network locations or
evaluation reports. Checks canonical artifact files, batch/case receipts,
B0/G1 source and graph integrity, prediction parity, run bindings, and
declared hashes. This is NOT a source re-acquisition, computation rerun,
authentication of external chronology, or scientific approval.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

from scripts.freeze_case_snapshots import canonical_bytes
from scripts.run_offline_case_batch import ARTIFACT_NAMES, MAX_CASES, VERSION
from src.threatragraph.baseline_b0 import build_b0_profile
from src.threatragraph.contracts import validate_graph_projection
from src.threatragraph.evidence_graph import fingerprint, require_sha
from src.threatragraph.paired_profile_audit import audit_paired_profiles
from src.threatragraph.paired_run_freeze import RUN_LOCK_VERSION, _metadata
from src.threatragraph.similarity_g1 import build_g1_profile
from src.threatragraph.local_file_inputs import (
    is_linked_path_component, read_local_text,
)

REPLAY_VERSION = "unscored-batch-integrity-replay-v1"
MAX_ARTIFACT_BYTES = 8 * 1024 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
BATCH_FIELDS = frozenset({
    "schema_version", "artifact_kind", "batch_version", "dataset_id",
    "dataset_version", "plan_sha256", "case_count", "cases",
    "later_reference_labels_accessed", "empirical_evaluation",
    "independent_study_approval", "research_ready", "batch_id",
})
CASE_FIELDS = frozenset({
    "case_id", "pipeline_id", "run_id", "b0_profile_id",
    "g1_profile_id", "paired_audit_id", "g1_novel_proposal_count",
    "g1_abstained", "artifacts", "research_ready",
})
RUN_FIELDS = frozenset({
    "schema_version", "artifact_kind", "lock_version", "case_id",
    "dataset_id", "dataset_version", "target_entity_id", "cutoff_at",
    "declared_provenance", "development_only", "g1_algorithm_config",
    "input_artifact_sha256", "b0_profile_id", "g1_profile_id",
    "paired_audit_id", "early_source_version_ids", "observed_fact_count",
    "provisional_prediction_count", "gold_labels_read",
    "predictions_sealed_before_gold_access",
    "historical_dates_and_rights_independently_verified",
    "reviewer_identities_independently_verified",
    "source_manifest_bytes_verified_by_this_module",
    "empirical_evaluation", "independent_study_approval",
    "research_ready", "run_id",
})
PIPELINE_FIELDS = frozenset({
    "schema_version", "artifact_kind", "pipeline_version", "case_id",
    "cutoff_at", "run_id", "paired_audit_id", "b0_profile_id",
    "g1_profile_id", "input_file_sha256", "source_manifest_sha256",
    "case_manifest_sha256", "feature_lineage_sha256",
    "graph_sha256", "early_source_version_ids",
    "raw_claim_records", "semantic_review_records",
    "source_archive_bytes_checked_by_projection",
    "historical_publication_dates_independently_authenticated",
    "semantic_reviewer_identities_independently_authenticated",
    "original_source_rights_independently_approved",
    "heldout_labels_opened", "empirical_evaluation", "research_ready",
    "pipeline_id",
})


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object fields forbidden")
        result[key] = value
    return result


def _no_constants(value):
    raise ValueError("Nonfinite JSON values forbidden")


def _root_directory(path):
    root = Path(path).expanduser()
    # Reject explicit symlinks in root/ancestor components. Full traversal
    # must not rely on an implicit symlinked directory being safe.
    node = root.absolute()
    for segment in (node, *node.parents):
        if is_linked_path_component(segment):
            raise ValueError("Symlinked or reparse batch artifact root/ancestor")
    if not node.is_dir():
        raise ValueError("Batch artifact root must be a directory")
    # Keep the checked lexical path. Calling resolve() here creates a
    # check-then-resolve race: a newly swapped symlink could be followed
    # after the component checks. Each subsequent artifact open walks this
    # path with the dedicated no-follow descriptor reader instead.
    return node


def _read_canonical(path, *, expected_hash=None):
    """Load a canonical JSON artifact from one no-follow bounded descriptor.

    Avoid separate lstat/path.read_bytes checks: the shared reader opens
    every POSIX path component without following symlinks, checks regular
    file type and stable byte length around the read, and refuses non-UTF8.
    No caller may treat a separate existence check as proof of safety.
    """
    try:
        body = read_local_text(path, max_bytes=MAX_ARTIFACT_BYTES).encode("utf-8")
    except FileNotFoundError as error:
        raise ValueError("Missing, nonregular or symlinked batch artifact") from error
    except UnicodeDecodeError as error:
        raise ValueError("Batch artifact must be UTF-8") from error
    actual = hashlib.sha256(body).hexdigest()
    if expected_hash is not None and actual != expected_hash:
        raise ValueError("Batch artifact bytes differ from declared SHA-256")
    parsed = json.loads(
        body.decode("utf-8"),
        object_pairs_hook=_unique_keys,
        parse_constant=_no_constants,
    )
    if not isinstance(parsed, dict) or canonical_bytes(parsed) != body:
        raise ValueError("Noncanonical or nonobject batch artifact")
    return parsed, actual

def _load_named(root, digest):
    if type(digest) is not str or not HEX64.fullmatch(digest):
        raise ValueError("Invalid digest in batch artifact pointer")
    return _read_canonical(root / (digest + ".json"), expected_hash=digest)[0]


def _self_sealed(obj, prefix, key, kind):
    if not isinstance(obj, dict) or obj.get(key) != prefix + fingerprint(
            {k: v for k, v in obj.items() if k != key}):
        raise ValueError("Tampered or malformed " + kind + " identity")


def _check_support_path(records, edge_index, groups, *,
                        expected_subject, expected_relation):
    """Bind each declared G1 evidence citation to exact stored sourced edges."""
    if not isinstance(records, list) or not records:
        raise ValueError("Empty or malformed G1 historical support path")
    for support in records:
        if not isinstance(support, dict) or set(support) != {
                "claim_id", "source_version_id", "independence_group",
                "evidence_sha256", "evidence_locator"}:
            raise ValueError("Unexpected G1 historical support fields")
        edge = edge_index.get(support["claim_id"])
        if edge is None or (
                edge["subject_id"] != expected_subject
                or (edge["predicate"], edge["object_id"]) != expected_relation
                or edge["assertion_kind"] != "report_assertion"
                or edge["polarity"] != "positive"
                or edge["evidence_status"] != "aligned"
                or edge["semantic_review_status"] != "supported_by_excerpt"):
            raise ValueError("G1 support not backed by an eligible graph claim")
        expected = {
            "claim_id": edge["claim_id"],
            "source_version_id": edge["source_version_id"],
            "independence_group": groups[edge["source_version_id"]],
            "evidence_sha256": edge["evidence_sha256"],
            "evidence_locator": edge["evidence_locator"],
        }
        if support != expected:
            raise ValueError("G1 support citation differs from exact graph evidence")


def _check_g1_support(g1, b0v, g1v, b0g, g1g):
    """Verify reported support paths; does not recompute G1 ranking."""
    target = b0v["target_entity_id"]
    early_versions = {source["source_version_id"] for source in b0v["sources"]}
    all_groups = {s["source_version_id"]: s["independence_group"]
                  for s in g1v["sources"]}
    early_claims = {edge["claim_id"]: edge for edge in b0g["edges"]}
    historical_claims = {
        edge["claim_id"]: edge for edge in g1g["edges"]
        if edge["source_version_id"] not in early_versions
    }
    possible_groups = {
        all_groups[edge["source_version_id"]]
        for edge in historical_claims.values()
    }
    for proposal in g1["predictions"]:
        peer = proposal.get("analog_peer_id")
        if (type(peer) is not str or peer == target
                or peer.split(":", 1)[0] != target.split(":", 1)[0]):
            raise ValueError("G1 analogy peer has unsupported identity")
        relation = (proposal["predicate"], proposal["object_id"])
        _check_support_path(
            proposal["proposed_relation_historical_support"],
            historical_claims, all_groups,
            expected_subject=peer, expected_relation=relation,
        )
        matching = proposal.get("matching_features")
        if not isinstance(matching, list) or not matching:
            raise ValueError("G1 matching feature paths must be nonempty")
        for feature in matching:
            if not isinstance(feature, dict) or set(feature) != {
                    "feature", "early_support", "historical_support"}:
                raise ValueError("G1 matching feature structure differs")
            detail = feature["feature"]
            if not isinstance(detail, dict) or set(detail) != {
                    "predicate", "object_id"}:
                raise ValueError("G1 matching feature relation differs")
            relation_feature = (detail["predicate"], detail["object_id"])
            _check_support_path(
                feature["early_support"], early_claims, all_groups,
                expected_subject=target, expected_relation=relation_feature,
            )
            _check_support_path(
                feature["historical_support"], historical_claims, all_groups,
                expected_subject=peer, expected_relation=relation_feature,
            )
        declared_groups = proposal.get("historical_independence_groups")
        if (not isinstance(declared_groups, list)
                or not set(declared_groups) <= possible_groups):
            raise ValueError("G1 declares unsupported historical publisher group")


def _check_case(item, artifacts, batch):
    case_id = item["case_id"]
    b0v, g1v = artifacts["b0_view"], artifacts["g1_view"]
    b0g, g1g = artifacts["b0_graph"], artifacts["g1_graph"]
    b0, g1 = artifacts["b0_profile"], artifacts["g1_profile"]
    audit, lock = artifacts["paired_audit"], artifacts["run_lock"]
    lineage = artifacts["feature_lineage"]
    pipe = artifacts["pipeline_receipt"]

    for artifact in (b0v, g1v, b0g, g1g, b0, g1, audit, lock, pipe):
        if artifact.get("case_id") != case_id:
            raise ValueError("Cross-case artifact contamination")
    for view, graph in ((b0v, b0g), (g1v, g1g)):
        if view.get("dataset_id") != batch["dataset_id"] or (
                view.get("dataset_version") != batch["dataset_version"]):
            raise ValueError("Batch and source-view dataset differ")
        validate_graph_projection(graph, view, reviewed=True)
        if any(edge["evidence_status"] != "aligned" for edge in graph["edges"]):
            raise ValueError("Unaligned source claim in persisted graph")
    if (b0v["cutoff_at"] != g1v["cutoff_at"]
            or b0v["target_entity_id"] != g1v["target_entity_id"]
            or b0v["method"] != "B0_sparse_report_only"
            or g1v["method"] != "G1_early_plus_historical_background"):
        raise ValueError("B0 and G1 case identity differs")
    b0_early = {src["source_version_id"]: src for src in b0v["sources"]}
    g1_early_sources = {
        src["source_version_id"]: src for src in g1v["sources"]
        if src["role"] == "early"
    }
    if g1_early_sources != b0_early or len(g1_early_sources) != len(b0_early):
        raise ValueError("G1 early source metadata differs from B0")
    g1_background = [src for src in g1v["sources"]
                     if src["role"] == "background"]
    if (not g1_background
            or {src["independence_group"] for src in g1_background}
               & {src["independence_group"] for src in b0v["sources"]}):
        raise ValueError("G1 historical background cannot overlap early publisher")
    background_ids = {src["source_version_id"] for src in g1_background}
    if any(
        edge["source_version_id"] in background_ids
        and b0v["target_entity_id"] in (
            edge["subject_id"], edge["object_id"]
        ) for edge in g1g["edges"]
    ):
        raise ValueError("Target-specific evidence entered historical background")
    g1_early = {edge["claim_id"]: edge for edge in g1g["edges"]
                if edge["source_version_id"] in {
                    source["source_version_id"] for source in b0v["sources"]
                }}
    if (len(g1_early) != len(b0g["edges"])
            or {edge["claim_id"]: edge for edge in b0g["edges"]} != g1_early):
        raise ValueError("Frozen graph early-source evidence parity lost")

    expected_audit = audit_paired_profiles(b0, g1)
    if audit != expected_audit:
        raise ValueError("Paired B0/G1 audit differs from regenerated structure")
    if (b0.get("source_view_sha256") != fingerprint(b0v)
            or g1.get("b0_source_view_sha256") != fingerprint(b0v)
            or g1.get("g1_source_view_sha256") != fingerprint(g1v)):
        raise ValueError("Profile source-view binding failed")

    if not isinstance(lock, dict) or set(lock) != RUN_FIELDS:
        raise ValueError("Unexpected or missing run-lock fields")
    _metadata(lock["declared_provenance"])
    _self_sealed(lock, "run:", "run_id", "run lock")
    if (lock["schema_version"] != "1.0"
            or lock["artifact_kind"] != "paired_run_engineering_lock"
            or lock["lock_version"] != RUN_LOCK_VERSION
            or type(lock["development_only"]) is not bool
            or lock["gold_labels_read"] is not False
            or lock["predictions_sealed_before_gold_access"] is not True
            or lock["research_ready"] is not False
            or lock["historical_dates_and_rights_independently_verified"] is not False
            or lock["reviewer_identities_independently_verified"] is not False
            or lock["source_manifest_bytes_verified_by_this_module"] is not False
            or lock["empirical_evaluation"] != "not_performed"
            or lock["independent_study_approval"] != "not_verified"):
        raise ValueError("Run-lock contract or scientific limitations violated")
    for field, expected in (
        ("dataset_id", batch["dataset_id"]),
        ("dataset_version", batch["dataset_version"]),
        ("target_entity_id", b0v["target_entity_id"]),
        ("cutoff_at", b0v["cutoff_at"]),
        ("b0_profile_id", b0["profile_id"]),
        ("g1_profile_id", g1["profile_id"]),
        ("paired_audit_id", audit["audit_id"]),
        ("early_source_version_ids", audit["early_source_version_ids"]),
        ("observed_fact_count", len(b0["facts"])),
        ("provisional_prediction_count", len(g1["predictions"])),
        ("g1_algorithm_config", g1["configuration"]),
    ):
        if lock[field] != expected:
            raise ValueError("Run-lock/profile identity mismatch: " + field)
    hashes = lock["input_artifact_sha256"]
    if not isinstance(hashes, dict) or set(hashes) != {
            "b0_view", "b0_graph", "g1_view", "g1_graph",
            "feature_lineage"}:
        raise ValueError("Wrong run-lock input hash inventory")
    for name in hashes:
        require_sha(hashes[name], name)
        if name != "feature_lineage" and hashes[name] != fingerprint(
                artifacts[name]):
            raise ValueError("Run-lock source/graph digest mismatch")
    if b0 != build_b0_profile(
            b0v, b0g, development_only=lock["development_only"]):
        raise ValueError("Saved B0 facts differ from deterministic source graph")
    if hashes["feature_lineage"] != fingerprint(lineage):
        raise ValueError("Frozen feature lineage differs from run-lock digest")
    # Check exact citations first, so forged witnesses receive a specific
    # refusal even when a malicious operator also rehashes the full profile.
    _check_g1_support(g1, b0v, g1v, b0g, g1g)
    # Recompute the FULL G1 profile from frozen graph/view/lineage records
    # and the stored deterministic config. No reference labels are accessed.
    expected_g1 = build_g1_profile(
        b0v, b0g, g1v, g1g, feature_lineage=lineage,
        development_only=lock["development_only"],
        **lock["g1_algorithm_config"],
    )
    if g1 != expected_g1:
        raise ValueError("Saved G1 profile differs from deterministic recomputation")
    if g1["feature_lineage_sha256"] != hashes["feature_lineage"]:
        raise ValueError("Lineage hash differs between G1 and run lock")
    lineage_report = g1.get("feature_lineage_contract")
    if (not isinstance(lineage_report, dict)
            or lineage_report.get("lineage_sha256") != hashes["feature_lineage"]
            or lineage_report.get("alias_mapping_permitted") is not False
            or lineage_report.get("external_taxonomy_lookup_permitted") is not False
            or lineage_report.get("later_rule_enrichment_permitted") is not False
            or lineage_report.get("research_ready") is not False):
        raise ValueError("G1 lineage contract not exact-only or digest-bound")

    if not isinstance(pipe, dict) or set(pipe) != PIPELINE_FIELDS:
        raise ValueError("Pipeline receipt includes unknown fields")
    _self_sealed(pipe, "pipeline:", "pipeline_id", "pipeline")
    file_hashes = pipe["input_file_sha256"]
    if not isinstance(file_hashes, dict) or set(file_hashes) != {
            "claims_jsonl", "semantic_reviews_jsonl", "dependencies"}:
        raise ValueError("Unexpected pipeline input-file hashes")
    for value in file_hashes.values():
        require_sha(value, "declared pipeline input")
    for field in ("source_manifest_sha256", "case_manifest_sha256",
                  "feature_lineage_sha256"):
        require_sha(pipe[field], field)
    if (file_hashes["semantic_reviews_jsonl"] !=
            lock["declared_provenance"]["review_set_sha256"]
            or file_hashes["dependencies"] !=
            lock["declared_provenance"]["dependency_lock_sha256"]
            or pipe["source_manifest_sha256"] !=
            lock["declared_provenance"]["source_manifest_sha256"]
            or pipe["case_manifest_sha256"] !=
            lock["declared_provenance"]["case_manifest_sha256"]
            or pipe["feature_lineage_sha256"] != hashes["feature_lineage"]
            or pipe["graph_sha256"] != {
                "B0": fingerprint(b0g), "G1": fingerprint(g1g)}
            or pipe["cutoff_at"] != b0v["cutoff_at"]
            or pipe["early_source_version_ids"] != audit["early_source_version_ids"]
            or type(pipe["raw_claim_records"]) is not int
            or type(pipe["semantic_review_records"]) is not int
            or not 0 <= pipe["semantic_review_records"] <=
                     pipe["raw_claim_records"] <= 10000
            or pipe["source_archive_bytes_checked_by_projection"] is not True
            or pipe["historical_publication_dates_independently_authenticated"] is not False
            or pipe["semantic_reviewer_identities_independently_authenticated"] is not False
            or pipe["original_source_rights_independently_approved"] is not False
            or pipe["heldout_labels_opened"] is not False
            or pipe["empirical_evaluation"] != "not_performed"
            or pipe["research_ready"] is not False):
        raise ValueError("Pipeline provenance, graph or no-label assertions differ")

    if (pipe["pipeline_id"] != item["pipeline_id"]
            or lock["run_id"] != item["run_id"]
            or b0["profile_id"] != item["b0_profile_id"]
            or g1["profile_id"] != item["g1_profile_id"]
            or audit["audit_id"] != item["paired_audit_id"]
            or len(g1["predictions"]) != item["g1_novel_proposal_count"]
            or g1["abstention"]["abstained"] is not item["g1_abstained"]):
        raise ValueError("Batch case pointers differ from exact persisted artifacts")
    return {
        "case_id": case_id, "run_id": lock["run_id"],
        "prediction_count": len(g1["predictions"]),
        "artifact_count": len(ARTIFACT_NAMES),
        "structural_integrity": "verified",
        "research_ready": False,
    }


def _verify_batch_payload(base, batch, *, receipt_published):
    """Validate one sealed receipt and every referenced persisted case artifact."""
    if not isinstance(batch, dict) or set(batch) != BATCH_FIELDS:
        raise ValueError("Unexpected batch receipt keys (possibly later labels)")
    _self_sealed(batch, "batch:", "batch_id", "batch")
    if (batch["schema_version"] != "1.0"
            or batch["artifact_kind"] != "unscored_multicase_engineering_receipt"
            or batch["batch_version"] != VERSION
            or batch["later_reference_labels_accessed"] is not False
            or batch["empirical_evaluation"] != "not_performed"
            or batch["independent_study_approval"] != "not_verified"
            or batch["research_ready"] is not False):
        raise ValueError("Unsupported or prematurely approved batch")
    for name in ("dataset_id", "dataset_version"):
        if type(batch[name]) is not str or not batch[name].strip():
            raise ValueError("Missing declared batch dataset identity")
    require_sha(batch["plan_sha256"], "batch plan fingerprint")
    records = batch["cases"]
    if (not isinstance(records, list) or type(batch["case_count"]) is not int
            or not 1 <= len(records) == batch["case_count"] <= MAX_CASES):
        raise ValueError("Incorrect batch case count")
    identifiers = []
    seen_runs = set()
    statuses = []
    for item in records:
        if not isinstance(item, dict) or set(item) != CASE_FIELDS:
            raise ValueError("Wrong per-case batch receipt fields")
        cid = item["case_id"]
        if type(cid) is not str or not cid or len(cid) > 200:
            raise ValueError("Wrong batch case identifier")
        identifiers.append(cid)
        if (type(item["g1_novel_proposal_count"]) is not int
                or type(item["g1_abstained"]) is not bool
                or item["research_ready"] is not False):
            raise ValueError("Invalid candidate case status")
        hashes = item["artifacts"]
        if not isinstance(hashes, dict) or set(hashes) != set(ARTIFACT_NAMES):
            raise ValueError("Missing or unexpected per-case artifacts")
        artifacts = {name: _load_named(base, hashes[name])
                     for name in ARTIFACT_NAMES}
        result = _check_case(item, artifacts, batch)
        if result["run_id"] in seen_runs:
            raise ValueError("Duplicate run identity across batch cases")
        seen_runs.add(result["run_id"])
        statuses.append(result)
    if identifiers != sorted(set(identifiers)):
        raise ValueError("Unsorted or duplicate batch case IDs")
    return {
        "schema_version": "1.0",
        "artifact_kind": "unscored_batch_replay_verification",
        "replay_version": REPLAY_VERSION,
        "batch_id": batch["batch_id"],
        "case_count": len(records),
        "artifact_count": len(records) * len(ARTIFACT_NAMES)
                          + int(receipt_published),
        "receipt_published": receipt_published,
        "case_results": statuses,
        "canonical_hashes_checked": True,
        "cross_case_linkage_checked": True,
        "b0_deterministically_recomputed": True,
        "g1_historical_citations_checked": True,
        "g1_ranking_recomputed": True,
        "feature_lineage_artifact_reloaded": True,
        "raw_archive_bytes_reread": False,
        "feature_lineage_original_bytes_reread": False,
        "batch_plan_bytes_reread": False,
        "outside_publication_dates_authenticated": False,
        "human_reviewers_authenticated": False,
        "external_freeze_attested": False,
        "heldout_labels_accessed": False,
        "empirical_evaluation": "not_performed",
        "research_ready": False,
    }


def verify_unpublished_batch(root, receipt):
    """Validate all stored leaves before making a final receipt visible.

    The caller supplies the already sealed in-memory receipt; this check
    intentionally does NOT require that its digest-named receipt file exists.
    """
    base = _root_directory(root)
    return _verify_batch_payload(base, receipt, receipt_published=False)


def replay_batch(root, receipt_digest):
    """Require the exact final receipt AND all sealed per-case artifacts."""
    base = _root_directory(root)
    batch = _load_named(base, receipt_digest)
    return _verify_batch_payload(base, batch, receipt_published=True)
