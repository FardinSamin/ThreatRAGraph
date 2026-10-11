"""Offline, conservative GitHub Security Advisory JSON candidate extraction.

This module accepts exact, explicitly SHA-256-pinned local source bytes.
It extracts only structured CVE-to-Go-package *review candidates*, never
free-text attack claims, automatic approvals, scored predictions or graph inserts.
Independent public-date/rights checks and human semantic review are external.
"""
from __future__ import annotations

import hashlib
import json
import re

from .evidence_graph import fingerprint, require_id, require_sha, validate_locator, validate_triple

ADAPTER_VERSION = "ghsa-go-package-candidates-v1"
OUTPUT_VERSION = "ghsa-review-candidates-v1"
SUPPORTED_GHSA_SCHEMA = "1.4.0"
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_AFFECTED = 128
MAX_ALIASES = 32
_GHSA = re.compile(r"^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$")
_CVE = re.compile(r"^CVE-(?:19|20)[0-9]{2}-[0-9]{4,}$")
_GO_PACKAGE = re.compile(r"^[a-z0-9][a-z0-9._/\-]{0,199}$")


def _no_duplicate_keys(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate JSON object key refused")
        obj[key] = value
    return obj


def _no_nonfinite(value):
    raise ValueError("Non-finite JSON constant refused")


def _field(path, value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Referenced GHSA evidence must be a nonblank scalar")
    locator = {"kind": "json_pointer", "path": path}
    validate_locator(locator)
    return {
        "evidence_locator": locator,
        "evidence_sha256": hashlib.sha256(value.encode("utf-8")).hexdigest(),
    }


def extract_ghsa_candidates(raw: bytes, *, source_version_id: str,
                            expected_sha256: str) -> dict:
    """Build deterministic unapproved review-queue entries from GHSA 1.4 JSON.

    Evidence is two separate scalar pointers: the explicit CVE alias and
    affected package name. Existing one-locator sourced_claims must NOT ingest
    this as an automatically approved claim; a reviewer must choose/verify
    any supported full assertion first.
    """
    require_id(source_version_id, "source_version_id")
    require_sha(expected_sha256, "expected_sha256")
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_SOURCE_BYTES:
        raise ValueError("Require bounded nonempty GHSA source bytes")
    source_sha256 = hashlib.sha256(raw).hexdigest()
    if source_sha256 != expected_sha256:
        raise ValueError("Source bytes differ from explicitly pinned SHA-256")
    try:
        advisory = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_no_nonfinite,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("Source is not valid bounded UTF-8 GHSA JSON") from exc
    if not isinstance(advisory, dict) or advisory.get("schema_version") != SUPPORTED_GHSA_SCHEMA:
        raise ValueError("Only GHSA schema 1.4.0 is supported by this adapter")
    if not isinstance(advisory.get("id"), str) or not _GHSA.fullmatch(advisory["id"]):
        raise ValueError("Invalid GHSA identifier")
    aliases = advisory.get("aliases")
    if not isinstance(aliases, list) or not 1 <= len(aliases) <= MAX_ALIASES:
        raise ValueError("GHSA aliases missing or unbounded")
    cves = []
    for index, alias in enumerate(aliases):
        if not isinstance(alias, str) or len(alias) > 128:
            raise ValueError("Invalid advisory alias")
        if _CVE.fullmatch(alias):
            cves.append((index, alias))
    if len(cves) != 1:
        raise ValueError("Exactly one explicit CVE alias required; ambiguous advisory refused")
    alias_index, cve = cves[0]
    target = "vulnerability:" + cve
    affected = advisory.get("affected")
    if not isinstance(affected, list) or not 1 <= len(affected) <= MAX_AFFECTED:
        raise ValueError("GHSA affected package list absent or unbounded")
    candidates = []
    seen = set()
    for index, item in enumerate(affected):
        if not isinstance(item, dict) or not isinstance(item.get("package"), dict):
            raise ValueError("Malformed affected package entry")
        package = item["package"]
        if package.get("ecosystem") != "Go":
            raise ValueError("This initial adapter accepts only explicit Go packages")
        name = package.get("name")
        if not isinstance(name, str) or not _GO_PACKAGE.fullmatch(name):
            raise ValueError("Invalid or unnormalized Go package identifier")
        obj = "software-product:go/" + name
        validate_triple(target, "AFFECTS", obj)
        if obj in seen:
            continue
        seen.add(obj)
        fields = [
            _field("/aliases/" + str(alias_index), cve),
            _field("/affected/" + str(index) + "/package/name", name),
        ]
        candidate = {
            "source_version_id": source_version_id,
            "subject_id": target,
            "predicate": "AFFECTS",
            "object_id": obj,
            "assertion_kind": "report_assertion",
            "polarity": "positive",
            "supporting_source_fields": fields,
            "candidate_status": "unapproved_requires_human_semantic_review",
            "reviewed": False,
            "ledger_inserted": False,
        }
        candidate["candidate_id"] = "candidate:" + fingerprint({
            "adapter_version": ADAPTER_VERSION,
            "source_sha256": source_sha256,
            **candidate,
        })
        candidates.append(candidate)
    candidates.sort(key=lambda x: (x["object_id"], x["candidate_id"]))
    return {
        "schema_version": OUTPUT_VERSION,
        "adapter_version": ADAPTER_VERSION,
        "status": "structured_candidates_pending_review",
        "source_version_id": source_version_id,
        "source_sha256": source_sha256,
        "original_ghsa_id": advisory["id"],
        "cve_target_id": target,
        "candidates": candidates,
        "approved_source": False,
        "approved_claims": 0,
        "human_review_completed": False,
        "g1_v2_target_method_eligible": False,
        "research_ready": False,
        "limitations": (
            "Structured aliases and affected Go package names only. "
            "No affected-version interpretation, prose relationship extraction, "
            "historical availability certification, rights approval, reviewer "
            "authentication, automatically supported claims, or G1 predictions."
        ),
    }
