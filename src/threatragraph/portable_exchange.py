"""Bounded, versioned JSON/CSV exchange for a sourced historical graph.

This serializes vetted-shape metadata, NOT original CTI publisher bodies,
verified reviewer identity, labels, or research approval. The import validator
does not update SQLite or promote unverified evidence.
"""
from __future__ import annotations

from copy import deepcopy
import csv
import hashlib
import io
import json

from .contracts import validate_graph_projection, validate_source_view
from .evidence_graph import fingerprint, require_sha

CONTRACT_VERSION = "portable-evidence-graph-v1"
ARTIFACT_KIND = "portable_sourced_graph_bundle"
MAX_BYTES = 8 * 1024 * 1024
MAX_CLAIMS = 10000
BUNDLE_FIELDS = frozenset({
    "schema_version", "artifact_kind", "contract_version", "reviewed",
    "source_view", "sourced_graph", "view_sha256", "graph_sha256",
    "claim_count", "research_ready", "limitations", "bundle_id",
})
CSV_FIELDS = (
    "claim_id", "source_version_id", "subject_id", "predicate", "object_id",
    "assertion_kind", "polarity", "evidence_locator_json",
    "evidence_sha256", "extractor_version", "evidence_status",
    "semantic_review_status",
)
LIMITATIONS = (
    "Portable metadata only. Original bytes, source rights, independent "
    "publisher dates, relation semantics, and reviewers are unverified. "
    "Not an approved historical study or confirmed cyberattack."
)


def _unique_fields(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate JSON field")
        out[key] = value
    return out


def _serialize(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


def create_bundle(view, graph, *, reviewed):
    """Envelope an already source-scoped graph without inventing claims."""
    if type(reviewed) is not bool:
        raise ValueError("Explicit reviewed boolean required")
    validate_source_view(view)
    validate_graph_projection(graph, view, reviewed=reviewed)
    bundle = {
        "schema_version": "1.0",
        "artifact_kind": ARTIFACT_KIND,
        "contract_version": CONTRACT_VERSION,
        "reviewed": reviewed,
        "source_view": deepcopy(view),
        "sourced_graph": deepcopy(graph),
        "view_sha256": fingerprint(view),
        "graph_sha256": fingerprint(graph),
        "claim_count": len(graph["edges"]),
        "research_ready": False,
        "limitations": LIMITATIONS,
    }
    bundle["bundle_id"] = "bundle:" + fingerprint(bundle)
    return bundle


def verify_bundle(bundle):
    """Fail closed on unknown fields, altered content or future material."""
    if not isinstance(bundle, dict) or set(bundle) != BUNDLE_FIELDS:
        raise ValueError("Exact v1 bundle fields required; labels forbidden")
    if (bundle["schema_version"] != "1.0"
            or bundle["artifact_kind"] != ARTIFACT_KIND
            or bundle["contract_version"] != CONTRACT_VERSION
            or type(bundle["reviewed"]) is not bool
            or bundle["research_ready"] is not False
            or bundle["limitations"] != LIMITATIONS):
        raise ValueError("Unsupported or falsely approved bundle version")
    unsigned = {k: v for k, v in bundle.items() if k != "bundle_id"}
    if bundle["bundle_id"] != "bundle:" + fingerprint(unsigned):
        raise ValueError("Bundle content fingerprint mismatch")
    view = bundle["source_view"]
    graph = bundle["sourced_graph"]
    validate_source_view(view)
    validate_graph_projection(graph, view, reviewed=bundle["reviewed"])
    if (require_sha(bundle["view_sha256"], "bundle view digest")
            != fingerprint(view)
            or require_sha(bundle["graph_sha256"], "bundle graph digest")
            != fingerprint(graph)
            or type(bundle["claim_count"]) is not int
            or bundle["claim_count"] != len(graph["edges"])
            or bundle["claim_count"] > MAX_CLAIMS):
        raise ValueError("Bundle source/graph contents differ from sealed hashes")
    return {
        "schema_version": "1.0",
        "artifact_kind": "portable_graph_verification_receipt",
        "bundle_id": bundle["bundle_id"],
        "case_id": view["case_id"],
        "method": view["method"],
        "source_version_ids": sorted(
            src["source_version_id"] for src in view["sources"]
        ),
        "claim_count": bundle["claim_count"],
        "original_source_bytes_verified": False,
        "reviewer_identities_verified": False,
        "research_ready": False,
    }


def bundle_json(bundle):
    verify_bundle(bundle)
    return _serialize(bundle) + "\n"


def parse_bundle_json(text):
    if (type(text) is not str or not 0 < len(text.encode("utf-8"))
            <= MAX_BYTES):
        raise ValueError("Bounded UTF-8 JSON bundle required")
    value = json.loads(text, object_pairs_hook=_unique_fields)
    verify_bundle(value)
    return value


def _claim_rows(bundle):
    records = []
    for item in sorted(bundle["sourced_graph"]["edges"],
                       key=lambda edge: edge["claim_id"]):
        row = {key: item[key] for key in CSV_FIELDS
               if key not in {"evidence_locator_json", "semantic_review_status"}}
        row["evidence_locator_json"] = _serialize(item["evidence_locator"])
        row["semantic_review_status"] = (
            item["semantic_review_status"] if bundle["reviewed"] else ""
        )
        # Quoting does not prevent some spreadsheets from executing formula
        # cells. Refuse dangerous prefixes without modifying evidence text.
        for cell in row.values():
            if (type(cell) is not str
                    or cell.lstrip().startswith(("=", "+", "-", "@"))):
                raise ValueError("Unsafe or non-text CSV evidence value")
        records.append(row)
    return records


def export_claims_csv(bundle):
    verify_bundle(bundle)
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS, lineterminator="\n",
                            quoting=csv.QUOTE_ALL, extrasaction="raise")
    writer.writeheader()
    writer.writerows(_claim_rows(bundle))
    content = stream.getvalue()
    if len(content.encode("utf-8")) > MAX_BYTES:
        raise ValueError("CSV output exceeds bounded limit")
    return content


def verify_claims_csv(text, bundle):
    """Compare imported CSV fields to the sealed JSON, never insert claims."""
    receipt = verify_bundle(bundle)
    if (type(text) is not str or not 0 < len(text.encode("utf-8"))
            <= MAX_BYTES or "\x00" in text):
        raise ValueError("Bounded nonempty CSV required")
    reader = csv.DictReader(io.StringIO(text, newline=""), restkey="__extra__")
    if reader.fieldnames != list(CSV_FIELDS):
        raise ValueError("CSV field names/order differ from v1 contract")
    actual = []
    for row in reader:
        if (len(actual) >= MAX_CLAIMS or set(row) != set(CSV_FIELDS)
                or any(type(v) is not str for v in row.values())):
            raise ValueError("Malformed CSV record or excessive rows")
        locator = json.loads(row["evidence_locator_json"],
                             object_pairs_hook=_unique_fields)
        if not isinstance(locator, dict):
            raise ValueError("CSV locator must be a JSON object")
        row["evidence_locator_json"] = _serialize(locator)
        actual.append(row)
    if actual != _claim_rows(bundle):
        raise ValueError("CSV claims differ from exact bundled graph evidence")
    receipt["csv_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    receipt["csv_claim_count"] = len(actual)
    receipt["csv_matches_bundle"] = True
    return receipt
