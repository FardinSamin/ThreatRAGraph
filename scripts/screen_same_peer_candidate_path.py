"""Conservative G1 same-peer candidate chain screening; never approves evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.threatragraph.evidence_graph import as_utc, validate_triple

VERSION = "g1-prospective-same-peer-chain-v1"
ROOT_KEYS = {
    "schema_version", "screen_id", "target_entity_id", "proposed_cutoff_at",
    "historical_peer_id", "early_source_version_id", "early_matching_feature",
    "historical_matching_feature_support", "historical_proposed_relation_support",
    "source_original_bytes_approved", "date_and_rights_reviewed",
    "same_peer_chain_semantically_reviewed", "novel_target_relation_verified",
    "case_approved", "research_ready", "later_reference_preview_exposure",
}
FEATURE_KEYS = {
    "subject_id", "predicate", "object_id", "source_version_id",
    "evidence_location_note", "evidence_byte_aligned", "semantic_reviewed",
}


def _require(ok: bool, msg: str) -> None:
    if not ok:
        raise ValueError(msg)


def _feature(feature, *, subject, known, allow=None):
    _require(isinstance(feature, dict) and set(feature) == FEATURE_KEYS,
             "Exact bounded candidate feature fields required")
    _require(feature["subject_id"] == subject, "Wrong feature subject type or peer")
    validate_triple(feature["subject_id"], feature["predicate"], feature["object_id"])
    _require(feature["predicate"] == "USES", "Only supported typed outgoing USES proposals")
    sid = feature["source_version_id"]
    _require(isinstance(sid, str) and sid in known, "Undeclared candidate source role")
    if allow is not None:
        _require(sid in allow, "Wrong source version partition")
    note = feature["evidence_location_note"]
    _require(isinstance(note, str) and 8 <= len(note) <= 250,
             "Bounded primary investigation location cue required")
    _require(feature["evidence_byte_aligned"] is False and
             feature["semantic_reviewed"] is False,
             "Prospect cannot predeclare aligned or semantically reviewed evidence")
    return (feature["predicate"], feature["object_id"]), sid


def assess_chain(screen: dict, registry: dict) -> dict:
    _require(isinstance(screen, dict) and set(screen) == ROOT_KEYS,
             "Prospective chain JSON fields are missing or unsupported")
    _require(screen["schema_version"] == VERSION, "Unknown candidate chain schema")
    _require(isinstance(screen["screen_id"], str) and screen["screen_id"].startswith("screen:")
             and len(screen["screen_id"]) <= 150, "Invalid screen identifier")
    _require(screen["target_entity_id"] == "campaign:SCARLETEEL"
             and screen["historical_peer_id"] == "campaign:Kiss-a-dog",
             "This screen is scoped to real distinct same-type campaign subjects")
    as_utc(screen["proposed_cutoff_at"])
    _require(screen["proposed_cutoff_at"] == "2023-03-01T00:00:00Z",
             "Unreviewed case cutoff must not change")
    for key in ("source_original_bytes_approved", "date_and_rights_reviewed",
                "same_peer_chain_semantically_reviewed", "novel_target_relation_verified",
                "case_approved", "research_ready"):
        _require(screen[key] is False, "Candidate screen cannot self-approve: " + key)
    _require(screen["later_reference_preview_exposure"] == "search_result_summary_exposed",
             "Prior later-reference preview exposure must not be hidden")
    _require(isinstance(registry, dict) and isinstance(registry.get("sources"), list),
             "Source registry missing")
    records = {}
    for source in registry["sources"]:
        _require(isinstance(source, dict) and isinstance(source.get("source_version_id"), str)
                 and source["source_version_id"] not in records,
                 "Invalid or duplicate candidate source record")
        records[source["source_version_id"]] = source

    early_id = screen["early_source_version_id"]
    _require(early_id == "candidate:scarleteel-sysdig-20230228:unfrozen",
             "Early source must be frozen separately, not substituted")
    early = screen["early_matching_feature"]
    first_key, first_sid = _feature(early, subject=screen["target_entity_id"],
                                     known=records, allow={early_id})
    _require(first_sid == early_id, "Early feature must cite early source")
    matches = screen["historical_matching_feature_support"]
    proposals = screen["historical_proposed_relation_support"]
    _require(isinstance(matches, list) and 2 <= len(matches) <= 6
             and isinstance(proposals, list) and len(proposals) == 1,
             "Two supported matching leads and one proposed new relation are required")
    matching_ids = set()
    for feature in matches:
        key, sid = _feature(feature, subject=screen["historical_peer_id"], known=records)
        _require(key == first_key, "Exact early-feature overlap required")
        _require(sid not in matching_ids, "Duplicate matching source/version cannot count twice")
        matching_ids.add(sid)
    proposal_key, proposal_id = _feature(
        proposals[0], subject=screen["historical_peer_id"], known=records
    )
    _require(proposal_key not in {first_key}, "Proposed relation already known to early case")
    _require(proposal_key == ("USES", "tool:xhide"),
             "No ad hoc predicted relation changes without preregistration")
    _require(matching_ids == {
        "candidate:kissadog-crowdstrike-20221026:unfrozen",
        "candidate:kissadog-cado-202212:unfrozen",
    } and proposal_id == "candidate:kissadog-cado-202212:unfrozen",
             "Fixed CrowdStrike/Cado per-peer relation provenance required")

    roles = matching_ids | {proposal_id} | {early_id}
    for sid in roles:
        row = records[sid]
        _require(row.get("status") == "candidate"
                 and row.get("sha256") is None and row.get("available_at") is None
                 and row.get("published_at") is None
                 and row.get("date_confidence") == "unknown"
                 and row.get("redistribution") == "unknown",
                 "Only unapproved and undated original-research sources eligible for candidate gate")
        _require(isinstance(row.get("independence_group"), str)
                 and bool(row["independence_group"]), "Declared research publisher group required")
    early_group = records[early_id]["independence_group"]
    crowdstrike_group = records["candidate:kissadog-crowdstrike-20221026:unfrozen"]["independence_group"]
    cado_group = records["candidate:kissadog-cado-202212:unfrozen"]["independence_group"]
    _require(len({early_group, crowdstrike_group, cado_group}) == 3,
             "Early publisher must not overlap independent historical publishers")
    # Critical G1 semantics: support groups are collected on ONE historical
    # peer's matching feature + proposed relation, not across distinct peers.
    per_peer_groups = {records[s]["independence_group"] for s in matching_ids | {proposal_id}}
    _require(len(per_peer_groups) >= 2,
             "G1 per-peer relation path needs two distinct declared source groups")
    return {
        "schema_version": VERSION,
        "screen_id": screen["screen_id"],
        "target_entity_id": screen["target_entity_id"],
        "historical_peer_id": screen["historical_peer_id"],
        "status": "unapproved_same_peer_two_group_relation_shape_plausible",
        "prospective_per_peer_matching_plus_relation_groups": len(per_peer_groups),
        "prospective_shared_feature": {"predicate": first_key[0], "object_id": first_key[1]},
        "prospective_additional_peer_relation": {"predicate": proposal_key[0],
                                                 "object_id": proposal_key[1]},
        "exact_same_peer_path_shape_plausible": True,
        "source_independence_verified": False,
        "actual_primary_2022_source_bytes_approved": False,
        "candidate_claims_byte_aligned_and_reviewed": False,
        "historical_source_availability_verified": False,
        "later_labels_blinded_and_reconciled": False,
        "independent_blinded_later_labeling_required": True,
        "scored_g1_predictions": 0,
        "case_approved": False,
        "g1_evaluation_eligible": False,
        "research_ready": False,
        "next_gate": (
            "Acquire original pre-cutoff CrowdStrike and Cado bytes, prove dates/rights "
            "and independence, review same campaign/variant relation scopes and original "
            "Sysdig early feature; then blinded gold evaluation after preregistration."
        ),
    }


def _no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value
    return result


def _load(path, limit):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or not 0 < p.stat().st_size <= limit:
        raise ValueError("Required bounded regular non-symlink JSON file")
    with p.open("rb") as fp:
        raw = fp.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("JSON is too large")
    try:
        return json.loads(raw.decode("utf-8", "strict"),
                          object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Malformed UTF-8 JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screen", default="datasets/case_screenings/scarleteel_kissadog_chain_v1.json")
    parser.add_argument("--manifest", default="datasets/manifests/pilot.json")
    args = parser.parse_args(argv)
    try:
        result = assess_chain(_load(args.screen, 128 * 1024), _load(args.manifest, 5 * 1024 * 1024))
    except (ValueError, TypeError, OSError) as exc:
        print(json.dumps({"status": "same_peer_candidate_chain_refused",
                          "reason": str(exc)[:500], "research_ready": False}, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
