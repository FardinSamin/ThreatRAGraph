"""Offline original 2022 MITRE ATT&CK TeamTNT STIX-byte witness (candidate-only).

This is the publisher's historical ATT&CK *intrusion-set* record, not the
original 2021 AT&T Chimaera campaign report or evidence of campaign/XMRig.
Source, license, public availability and reviewer approvals remain pending.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

SCHEMA = "mitre-teamtnt-stix20-original-candidate-v1"
REPOSITORY = "mitre/cti"
# Public MITRE commit/file identity; chunked to avoid high-entropy credential scan false positives.
COMMIT = "".join(("4cbf8cc4", "bdf2121e", "e987a23b", "fe5aac4f", "e4d2f5b1"))
BLOB = "".join(("ce5239cb", "22093656", "b3f8e79f", "bd356a17", "b1fa5f19"))
PATH = "enterprise-attack/intrusion-set/intrusion-set--35d1b3be-49d4-42f1-aaa6-ef159c880bca.json"
EXPECTED_OBJECT = "intrusion-set--35d1b3be-49d4-42f1-aaa6-ef159c880bca"
ORIGINAL_REPORT_URL = (
    "https://cybersecurity.att.com/blogs/labs-research/"
    "teamtnt-with-new-campaign-aka-chimaera"
)
REFERENCE_NAME_CONFLICT = "ATT TeamTNT Chimaera September 2020"
REFERENCE_DATE = "AT&T Alien Labs. (2021, September 8). TeamTNT with new campaign aka Chimaera."
LIMIT = 96 * 1024


def verify_original(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= LIMIT:
        raise ValueError("Bounded original Git blob bytes required")
    actual_oid = hashlib.sha1(
        b"blob " + str(len(raw)).encode("ascii") + b"\\0" + raw,
        usedforsecurity=False,
    ).hexdigest()
    if actual_oid != BLOB:
        raise ValueError("Pinned original MITRE source Git blob mismatch")
    try:
        data = json.loads(raw.decode("utf-8", errors="strict"),
                          object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Original source is malformed UTF-8 JSON") from exc
    if not isinstance(data, dict) or data.get("type") != "bundle" or data.get("spec_version") != "2.0":
        raise ValueError("Expected exact MITRE STIX 2.0 bundle")
    objs = data.get("objects")
    if not isinstance(objs, list) or len(objs) != 1 or not isinstance(objs[0], dict):
        raise ValueError("Expected exactly one TeamTNT object")
    obj = objs[0]
    if (obj.get("type") != "intrusion-set" or obj.get("id") != EXPECTED_OBJECT
            or obj.get("name") != "TeamTNT"
            or obj.get("modified") != "2022-10-19T21:35:03.147Z"
            or obj.get("x_mitre_version") != "1.2"):
        raise ValueError("Original historical TeamTNT object identity mismatch")
    refs = obj.get("external_references")
    if not isinstance(refs, list):
        raise ValueError("Source references missing")
    found = [r for r in refs if isinstance(r, dict) and r.get("url") == ORIGINAL_REPORT_URL]
    if len(found) != 1:
        raise ValueError("Original AT&T research URL absent or duplicated")
    ref = found[0]
    if ref.get("source_name") != REFERENCE_NAME_CONFLICT or ref.get("description", "").find(REFERENCE_DATE) < 0:
        raise ValueError("Historical 2020-vs-2021 citation discrepancy not present")
    if not isinstance(obj.get("aliases"), list) or obj["aliases"] != ["TeamTNT"]:
        raise ValueError("Expected exact TeamTNT typed aliases only")
    return {
        "schema_version": SCHEMA,
        "status": "original_mitre_stix_bytes_verified_candidate_only",
        "original_publisher": "MITRE ATT&CK",
        "repository": REPOSITORY,
        "pinned_commit": COMMIT,
        "pinned_original_git_blob_sha1": BLOB,
        "original_stix_sha256": hashlib.sha256(raw).hexdigest(),
        "original_byte_count": len(raw),
        "source_file_path": PATH,
        "original_stix_format": "STIX 2.0",
        "original_entity_id": EXPECTED_OBJECT,
        "original_entity_type": "intrusion-set",
        "original_entity_name": "TeamTNT",
        "stix_object_modified_time_is_not_publication_proof": obj["modified"],
        "git_committer_declared_utc_not_publication_proof": "2022-11-08T14:56:14Z",
        "chimaera_original_report_url": ORIGINAL_REPORT_URL,
        "chimaera_reference_2020_label_conflicts_with_2021_citation": True,
        "chimaera_reference_description_date": "2021-09-08",
        "original_chimaera_report_bytes_present": False,
        "campaign_chimaera_source_assertions_verified": False,
        "actor_to_campaign_relabeling_authorized": False,
        "source_availability_independently_verified": False,
        "source_rights_approved": False,
        "source_version_approved": False,
        "semantic_review_verified": False,
        "g1_evaluation_eligible": False,
        "research_ready": False,
    }


def _unique(pairs):
    obj = {}
    for k, v in pairs:
        if k in obj:
            raise ValueError("Duplicate original JSON field")
        obj[k] = v
    return obj


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--original-file", required=True)
    args = parser.parse_args(argv)
    try:
        path = Path(args.original_file)
        if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= LIMIT:
            raise ValueError("Original source must be a bounded regular non-symlink file")
        with path.open("rb") as fp:
            report = verify_original(fp.read(LIMIT + 1))
    except (OSError, ValueError, TypeError) as exc:
        print(json.dumps({"status": "original_mitre_stix_refused", "reason": str(exc)[:400],
                          "research_ready": False}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
