"""Verify claim citations against the *actual* bytes of approved source archives.

Supported v1 evidence:
* text_span: one UTF-8 plain-text source, segment_id == "seg:" + source version ID.
  start/end are zero-based Python Unicode code-point positions in original text;
  no implicit OCR, whitespace changes, newline folding, or normalization.
* json_pointer: RFC 6901 path to scalar in raw JSON.
* html_text_span: versioned derived visible-text span recomputed from original
  approved HTML source bytes on every check.
* yaml_path: scalar field in a Falco rules YAML source, using the pinned
  strict SafeLoader. Conditions are rule semantics, never incident telemetry.

PDF/OCR and external normalized text segments still FAIL CLOSED until their
source-byte lineage and extractor versions can be checked.

This proves exact-byte alignment, NOT whether prose semantically supports a
relationship, whether the publisher is correct, or when it became public.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any

from .evidence_graph import require_sha, validate_locator
from .normalized_sources import (
    HTML_NORMALIZER_VERSION, normalize_html,
    normalize_falco_yaml, yaml_scalar_from_path,
)

MAX_ARCHIVE_BYTES = 50 * 1024 * 1024
MAX_EVIDENCE_BYTES = 128 * 1024


@dataclass(frozen=True)
class Alignment:
    source_version_id: str
    source_sha256: str
    evidence_sha256: str
    evidence_kind: str
    status: str = "aligned"


def _json_pointer_value(obj: Any, pointer: str) -> Any:
    if not pointer.startswith("/") or pointer == "/":
        raise ValueError("JSON pointer must point to a non-root field")
    cursor = obj
    for escaped in pointer[1:].split("/"):
        # RFC 6901 only permits ~0 and ~1 sequences.
        if any(escaped[i] == "~" and
               (i + 1 == len(escaped) or escaped[i + 1] not in "01")
               for i in range(len(escaped))):
            raise ValueError("Malformed JSON pointer escape")
        token = escaped.replace("~1", "/").replace("~0", "~")
        if isinstance(cursor, dict):
            if token not in cursor:
                raise ValueError("JSON pointer field does not exist")
            cursor = cursor[token]
        elif isinstance(cursor, list):
            if (not token.isascii() or not token.isdecimal() or
                    (len(token) > 1 and token[0] == "0")):
                raise ValueError("Invalid JSON array index")
            index = int(token)
            if index >= len(cursor):
                raise ValueError("JSON pointer index out of bounds")
            cursor = cursor[index]
        else:
            raise ValueError("JSON pointer traverses non-container")
    return cursor


def _evidence_bytes(raw: bytes, locator: dict[str, Any],
                    source_version_id: str, source_kind: str = "") -> bytes:
    kind = locator["kind"]
    if kind == "yaml_path":
        if source_kind != "falco_rule":
            raise ValueError("YAML locators require falco_rule source type")
        return yaml_scalar_from_path(normalize_falco_yaml(raw), locator["path"])
    if kind == "html_text_span":
        if source_kind not in {"cti_report", "kubernetes_doc", "cve_advisory", "other"}:
            raise ValueError("HTML locator not permitted for this source type")
        if locator["normalizer_version"] != HTML_NORMALIZER_VERSION:
            raise ValueError("HTML normalizer version mismatch")
        if locator["segment_id"] != "seg:" + source_version_id + ":" + HTML_NORMALIZER_VERSION:
            raise ValueError("HTML segment ID does not match source/version")
        normalized = normalize_html(raw)
        a, b = locator["start"], locator["end"]
        if a < 0 or b > len(normalized) or b <= a:
            raise ValueError("HTML text span out of bounds")
        selected = normalized[a:b]
        if not selected.strip():
            raise ValueError("HTML text evidence must be nonblank")
        return selected.encode("utf-8")
    if kind == "text_span":
        if raw.startswith(b"%PDF-") or re.match(
            rb"\s*<(?:!doctype\s+html|html|body|article|div|p)\b",
            raw[:256], flags=re.I
        ):
            raise ValueError("Binary/HTML source requires a versioned normalizer")
        if locator["segment_id"] != "seg:" + source_version_id:
            raise ValueError("Text segment ID does not match source version")
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise ValueError("Text evidence source is not UTF-8") from exc
        a, b = locator["start"], locator["end"]
        if a < 0 or b > len(text) or b <= a:
            raise ValueError("Text evidence span out of bounds")
        selected = text[a:b]
        if not selected.strip():
            raise ValueError("Blank evidence span is not valid")
        return selected.encode("utf-8")

    if kind == "json_pointer":
        try:
            obj = json.loads(raw.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Evidence source is not valid UTF-8 JSON") from exc
        value = _json_pointer_value(obj, locator["path"])
        if isinstance(value, (dict, list)):
            raise ValueError("JSON pointer evidence must address a scalar value")
        if isinstance(value, str):
            if not value.strip():
                raise ValueError("Blank JSON string is not valid evidence")
            return value.encode("utf-8")
        return json.dumps(
            value, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")

    raise ValueError("Unsupported evidence locator kind")


class EvidenceVerifier:
    def __init__(self, manifest: dict[str, Any], archive_root: str | Path):
        records = manifest.get("sources") if isinstance(manifest, dict) else None
        if not isinstance(records, list):
            raise ValueError("Source manifest requires sources list")
        self.versions: dict[str, dict[str, Any]] = {}
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("Invalid source manifest record")
            if record.get("status") != "approved":
                continue
            version = record.get("source_version_id")
            if not isinstance(version, str) or not version.strip():
                raise ValueError("Approved source version ID required")
            if version in self.versions:
                raise ValueError("Duplicate approved source version ID")
            require_sha(record.get("sha256"), "source.sha256")
            self.versions[version] = record
        self.root = Path(archive_root).expanduser()
        if self.root.is_symlink():
            raise ValueError("Archive root cannot be symlinked")

    def verify(self, claim: dict[str, Any]) -> Alignment:
        if not isinstance(claim, dict):
            raise ValueError("Claim must be an object")
        version = claim.get("source_version_id")
        if not isinstance(version, str) or version not in self.versions:
            raise ValueError("Claim source has no approved archived version")
        record = self.versions[version]
        digest = require_sha(record["sha256"], "source.sha256")
        locator = json.loads(validate_locator(claim.get("evidence_locator")))
        if (locator["kind"] == "yaml_path" and
                claim.get("assertion_kind") != "rule_semantics"):
            raise ValueError("Falco rule YAML field is rule semantics, not incident observation")
        expected = require_sha(claim.get("evidence_sha256"), "evidence_sha256")
        folder = self.root / digest[:2]
        path = folder / digest
        if folder.is_symlink() or path.is_symlink():
            raise ValueError("Refusing symlinked archive path")
        if not path.is_file():
            raise ValueError("Claim's original archived source not found")
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("Source archive exceeds size limit")
        with path.open("rb") as src:
            raw = src.read(MAX_ARCHIVE_BYTES + 1)
        if len(raw) > MAX_ARCHIVE_BYTES:
            raise ValueError("Source archive exceeds size limit")
        if hashlib.sha256(raw).hexdigest() != digest:
            raise ValueError("Source archive differs from approved version digest")

        evidence = _evidence_bytes(
            raw, locator, version, source_kind=record.get("source_kind", "")
        )
        if len(evidence) > MAX_EVIDENCE_BYTES:
            raise ValueError("Evidence span exceeds size limit")
        actual = hashlib.sha256(evidence).hexdigest()
        if actual != expected:
            raise ValueError("Evidence hash does not match cited source bytes")

        return Alignment(version, digest, actual, locator["kind"])
