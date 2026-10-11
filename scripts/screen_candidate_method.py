"""Fail-closed candidate-only screen for G1 v2 case/method *possibility*.

Never approves a source/case, reads later reference bodies, makes predictions,
or certifies a historical source version. A different approval workflow must
authenticate exact source bytes, independent peers, reviewers and dates.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.threatragraph.evidence_graph import as_utc, validate_triple

SCREEN_VERSION = "g1-v2-prospective-case-screen-v1"
SCREEN_VERSION_V2 = "g1-v2-prospective-case-screen-v2"
SCREEN_FIELDS = {
    "schema_version", "screen_id", "target_entity_id", "proposed_cutoff_at",
    "early_source_version_ids", "date_corroboration_source_version_ids",
    "background_source_version_ids", "later_reference_source_version_ids",
    "early_feature_candidates", "same_type_background_peers_verified",
    "two_group_peer_relation_support_verified",
    "later_reference_preview_exposure",
    "case_approved", "research_ready",
}
FEATURE_FIELDS = {
    "subject_id", "predicate", "object_id", "source_version_id",
    "evidence_location_note", "evidence_byte_aligned", "semantic_reviewed",
}
SCREEN_FIELDS_V2 = SCREEN_FIELDS | {"background_peer_candidates"}
MAX_SCREEN_BYTES = 256 * 1024
MAX_MANIFEST_BYTES = 5 * 1024 * 1024


def _unique_ids(raw, name, maximum=30):
    if (not isinstance(raw, list) or not raw or len(raw) > maximum
            or any(not isinstance(x, str) or not x or len(x) > 300 for x in raw)
            or len(set(raw)) != len(raw)):
        raise ValueError(name + " requires distinct bounded source-version IDs")
    return raw


def assess_screen(screen: dict, manifest: dict) -> dict:
    if not isinstance(screen, dict):
        raise ValueError("Prospective case screen must be a JSON object")
    screen_schema = screen.get("schema_version")
    if screen_schema not in (SCREEN_VERSION, SCREEN_VERSION_V2):
        raise ValueError("Unsupported prospective screen version")
    fields = SCREEN_FIELDS if screen_schema == SCREEN_VERSION else SCREEN_FIELDS_V2
    if set(screen) != fields:
        raise ValueError("Prospective case screen has unsupported or missing fields")
    screen_id = screen["screen_id"]
    if not isinstance(screen_id, str) or not screen_id.startswith("screen:") or len(screen_id) > 150:
        raise ValueError("Bounded screen ID required")
    target = screen["target_entity_id"]
    if not isinstance(target, str) or not target.startswith("campaign:"):
        raise ValueError("This first prospect is for an authentic named campaign target")
    # Typed ontology checks below establish only a potential method fit.
    as_utc(screen["proposed_cutoff_at"])
    if screen["case_approved"] is not False or screen["research_ready"] is not False:
        raise ValueError("Prospective screening must never assert approval or readiness")
    if (screen["same_type_background_peers_verified"] is not False or
            screen["two_group_peer_relation_support_verified"] is not False):
        raise ValueError("Peer validation cannot be claimed from source discovery")
    if screen["later_reference_preview_exposure"] not in {
        "none_reported", "search_result_summary_exposed"
    }:
        raise ValueError("Explicit later-preview exposure state required")
    if not isinstance(manifest, dict) or not isinstance(manifest.get("sources"), list):
        raise ValueError("Source manifest missing candidate sources")
    index = {}
    for source in manifest["sources"]:
        if not isinstance(source, dict):
            raise ValueError("Invalid source manifest entry")
        sid = source.get("source_version_id")
        if not isinstance(sid, str) or sid in index:
            raise ValueError("Duplicate or invalid source manifest ID")
        index[sid] = source

    early = _unique_ids(screen["early_source_version_ids"], "Early candidates", 2)
    if len(early) not in (1, 2):
        raise ValueError("Early screen needs one or two sources")
    corroboration = _unique_ids(
        screen["date_corroboration_source_version_ids"], "Corroboration leads"
    )
    background = _unique_ids(
        screen["background_source_version_ids"], "Historical background candidates"
    )
    later = _unique_ids(
        screen["later_reference_source_version_ids"], "Held-out reference leads"
    )
    groups = (early, corroboration, background, later)
    combined = [v for group in groups for v in group]
    if len(set(combined)) != len(combined):
        raise ValueError("Source candidate cannot be used in multiple roles")
    for version in combined:
        record = index.get(version)
        if record is None:
            raise ValueError("Candidate source does not exist in manifest")
        if (record.get("status") != "candidate" or
                record.get("available_at") is not None or
                record.get("sha256") is not None or
                record.get("date_confidence") == "verified"):
            raise ValueError("Prospect source must remain entirely unapproved and unverified")
    early_groups = {index[v].get("independence_group") for v in early}
    background_groups = {index[v].get("independence_group") for v in background}
    if (any(not isinstance(g, str) or not g for g in early_groups | background_groups)
            or not early_groups.isdisjoint(background_groups)):
        raise ValueError("Background publisher group overlaps early research lineage")
    if len(background_groups) < 2:
        raise ValueError("At least two independent candidate publisher groups required")
    for version in corroboration:
        if index[version].get("independence_group") not in early_groups:
            raise ValueError("Contemporaneous derivative must not imply independent reporting")
    for version in later:
        # Candidate later dates cannot be independently authenticated here.
        # Preserve role segregation without reading or extracting their content.
        if index[version].get("status") != "candidate":
            raise ValueError("Later source unexpectedly approved")

    feats = screen["early_feature_candidates"]
    if not isinstance(feats, list) or not 1 <= len(feats) <= 12:
        raise ValueError("At least one bounded early feature candidate required")
    for feature in feats:
        if not isinstance(feature, dict) or set(feature) != FEATURE_FIELDS:
            raise ValueError("Invalid early candidate feature fields")
        if feature["subject_id"] != target or feature["source_version_id"] not in early:
            raise ValueError("Feature subject/source must be early case target")
        validate_triple(feature["subject_id"], feature["predicate"], feature["object_id"])
        if feature["predicate"] != "USES":
            raise ValueError("First campaign screen permits only G1-v2 USES candidates")
        note = feature["evidence_location_note"]
        if not isinstance(note, str) or not 8 <= len(note) <= 250:
            raise ValueError("Bounded source location cue required")
        if (feature["evidence_byte_aligned"] is not False or
                feature["semantic_reviewed"] is not False):
            raise ValueError("Screen cannot assert reviewed/aligned extracted evidence")

    peers = []
    if screen_schema == SCREEN_VERSION_V2:
        peers = screen["background_peer_candidates"]
        if not isinstance(peers, list) or not 2 <= len(peers) <= 12:
            raise ValueError("V2 requires two or more bounded named campaign peer prospects")
        seen_peers = set()
        supported_groups = set()
        early_features = {
            (f["predicate"], f["object_id"]) for f in feats
        }
        for peer in peers:
            if not isinstance(peer, dict) or set(peer) != FEATURE_FIELDS:
                raise ValueError("V2 peer candidates require exact supported evidence cue fields")
            subject = peer["subject_id"]
            sid = peer["source_version_id"]
            if (not isinstance(subject, str)
                    or not subject.startswith("campaign:")
                    or subject == target or subject in seen_peers):
                raise ValueError("Peers must be distinct non-target named campaigns")
            seen_peers.add(subject)
            if not isinstance(sid, str) or sid not in background:
                raise ValueError("Peer evidence source must be declared background")
            group = index[sid]["independence_group"]
            if group in supported_groups:
                raise ValueError("Peer source groups must be distinct candidate publishers")
            supported_groups.add(group)
            if peer["predicate"] != "USES":
                raise ValueError("Peer evidence must be eligible USES relation")
            validate_triple(subject, peer["predicate"], peer["object_id"])
            if (peer["predicate"], peer["object_id"]) not in early_features:
                raise ValueError("Peer must use exact same typed early target feature")
            note = peer["evidence_location_note"]
            if not isinstance(note, str) or not 8 <= len(note) <= 250:
                raise ValueError("Bounded evidence location cue required for peer")
            if (peer["evidence_byte_aligned"] is not False
                    or peer["semantic_reviewed"] is not False):
                raise ValueError("Peer cannot be predeclared as aligned or reviewed")

    return {
        "schema_version": screen_schema,
        "screen_id": screen_id,
        "target_entity_id": target,
        "proposed_cutoff_at": screen["proposed_cutoff_at"],
        "status": "plausible_campaign_feature_family_only_not_method_eligible",
        "g1_v2_subject_type_and_early_predicate_plausible": True,
        "provisional_early_feature_count": len(feats),
        "declared_background_publisher_groups": len(background_groups),
        "unverified_explicit_same_type_peer_candidates": len(peers),
        "two_group_same_type_peer_claim_support_verified": False,
        "same_type_peer_verified": False,
        "original_source_bytes_and_dates_approved": False,
        "external_later_summary_exposure": screen["later_reference_preview_exposure"],
        "independent_blinded_later_labeling_required": (
            screen["later_reference_preview_exposure"] != "none_reported"
        ),
        "case_approved": False,
        "g1_evaluation_eligible": False,
        "screened_source_versions_approved": 0,
        "experimental_predictions": 0,
        "research_ready": False,
        "next_gate": (
            "Independently freeze and verify early original source bytes, exact "
            "availability/rights, actual same-type pre-cutoff peer claims from "
            "two independent groups, reviewer adjudication, and blinded later labels."
        ),
    }


def _no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate JSON keys refused")
        out[key] = value
    return out


def _load(path, limit):
    p = Path(path)
    if p.is_symlink() or not p.is_file() or not 0 < p.stat().st_size <= limit:
        raise ValueError("Input must be a bounded regular non-symlink JSON file")
    with p.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("Input exceeds size limit")
    try:
        return json.loads(raw.decode("utf-8", errors="strict"),
                          object_pairs_hook=_no_duplicates)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Invalid UTF-8 JSON") from exc


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--screen", default="datasets/case_screenings/scarleteel_peers_v2.json")
    parser.add_argument("--manifest", default="datasets/manifests/pilot.json")
    args = parser.parse_args(argv)
    try:
        result = assess_screen(
            _load(args.screen, MAX_SCREEN_BYTES), _load(args.manifest, MAX_MANIFEST_BYTES)
        )
    except (ValueError, OSError, TypeError) as exc:
        print(json.dumps({
            "status": "prospective_case_screen_refused",
            "reason": str(exc)[:500], "research_ready": False,
        }, sort_keys=True))
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
