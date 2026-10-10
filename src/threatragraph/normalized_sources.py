"""Reproducible normalization from byte-verified original source documents.

No fetching, LLM, JavaScript execution, external entity resolution or reports.
The generated text is always recomputed from exact approved archive bytes.

HTML parser v1 deliberately emits *visible text only*, with deterministic
whitespace collapsing. Offsets address this derived text, never raw HTML.
Falco YAML v1 uses PyYAML 6.0.3 SafeLoader rules with stricter input checks.
"""
from __future__ import annotations

from html.parser import HTMLParser
import re
from typing import Any

HTML_NORMALIZER_VERSION = "html-visible-v1"
FALCO_NORMALIZER_VERSION = "falco-safe-yaml-v1-pyyaml-6.0.3"
MAX_NORMALIZER_INPUT = 4 * 1024 * 1024
MAX_HTML_OUTPUT = 4 * 1024 * 1024
_BLOCKED = {"head", "script", "style", "template", "iframe", "svg", "noscript"}
_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input",
         "link", "meta", "param", "source", "track", "wbr"}


class _VisibleHTML(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.blocked_tags: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() in _VOID:
            return
        if self.blocked_tags or tag.lower() in _BLOCKED:
            self.blocked_tags.append(tag.lower())

    def handle_startendtag(self, tag, attrs):
        # Self-closing elements do not affect the blocked subtree.
        pass

    def handle_endtag(self, tag):
        if self.blocked_tags and self.blocked_tags[-1] == tag.lower():
            self.blocked_tags.pop()

    def handle_data(self, data):
        if not self.blocked_tags and data.strip():
            self.parts.append(data)


def normalize_html(raw: bytes) -> str:
    """Compute deterministic normalized visible text from an archived HTML file.

    Unsupported malformed/oversized sources fail instead of fabricating spans.
    This is a readability normalizer, not full DOM or original-byte mapping.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_NORMALIZER_INPUT:
        raise ValueError("HTML must be bounded original bytes")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("HTML source is not valid UTF-8") from exc
    if "\x00" in text or not re.search(r"<(?:!doctype\s+html|html\b|body\b|article\b|p\b|div\b)", text, re.I):
        raise ValueError("Source is not recognized HTML v1")
    parser = _VisibleHTML()
    try:
        parser.feed(text)
        parser.close()
    except (ValueError, AssertionError) as exc:
        raise ValueError("Malformed HTML source") from exc
    if parser.blocked_tags:
        raise ValueError("Unclosed blocked HTML subtree")
    normalized = " ".join(" ".join(parser.parts).split())
    if not normalized or len(normalized.encode("utf-8")) > MAX_HTML_OUTPUT:
        raise ValueError("No bounded visible HTML content")
    return normalized


def _falco_yaml_loader():
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("PyYAML==6.0.3 is required for Falco YAML verification") from exc
    if getattr(yaml, "__version__", None) != "6.0.3":
        raise ValueError("Falco YAML parser version mismatch; require PyYAML==6.0.3")

    class StrictFalcoLoader(yaml.SafeLoader):
        def __init__(self, stream):
            super().__init__(stream)
            self._tree_depth = 0

        def compose_node(self, parent, index):
            # Reject aliases even if harmless; recursive alias bombs are unsafe.
            if self.check_event(yaml.AliasEvent):
                raise ValueError("YAML aliases are not accepted in evidence documents")
            self._tree_depth += 1
            if self._tree_depth > 40:
                raise ValueError("Falco YAML nesting limit exceeded")
            try:
                return super().compose_node(parent, index)
            finally:
                self._tree_depth -= 1

        def construct_mapping(self, node, deep=False):
            if not isinstance(node, yaml.MappingNode):
                raise ValueError("Expected YAML mapping node")
            found = set()
            for key, _ in node.value:
                if not isinstance(key, yaml.ScalarNode):
                    raise ValueError("Falco mapping keys must be scalar")
                if key.value == "<<":
                    raise ValueError("YAML merges are not accepted")
                if key.value in found:
                    raise ValueError("Duplicate YAML field")
                found.add(key.value)
            return super().construct_mapping(node, deep=deep)

    return yaml, StrictFalcoLoader


def normalize_falco_yaml(raw: bytes) -> list[dict[str, Any]]:
    """Parse a Falco rules file safely, retaining its structured string fields.

    This does not compile conditions, resolve macros or run Falco telemetry.
    """
    if not isinstance(raw, bytes) or len(raw) > MAX_NORMALIZER_INPUT:
        raise ValueError("Falco YAML source exceeds parser limit")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("Falco YAML must be UTF-8") from exc
    yaml, loader = _falco_yaml_loader()
    try:
        result = yaml.load(text, Loader=loader)
    except (yaml.YAMLError, RecursionError) as exc:
        raise ValueError("Malformed or unsafe Falco YAML") from exc
    if not isinstance(result, list) or not result or len(result) > 2000:
        raise ValueError("Falco rules source must be a bounded nonempty YAML list")
    for item in result:
        if not isinstance(item, dict) or not any(
            name in item for name in ("rule", "macro", "list")
        ):
            raise ValueError("Each Falco YAML entry must be rule/macro/list")
        for name in ("rule", "macro", "list"):
            if name in item and (not isinstance(item[name], str) or not item[name].strip()):
                raise ValueError("Falco entry name must be nonblank string")
        if "rule" in item or "macro" in item:
            if not isinstance(item.get("condition"), str) or not item["condition"].strip():
                raise ValueError("Falco rule/macro requires a textual condition")
    return result


def yaml_scalar_from_path(data: list[dict[str, Any]], path: str) -> bytes:
    """Resolve /0/condition etc. Never execute the condition or treat as telemetry."""
    # Structured paths share the JSON Pointer token/array conventions.
    from .evidence_alignment import _json_pointer_value
    scalar = _json_pointer_value(data, path)
    if not isinstance(scalar, str) or not scalar.strip():
        raise ValueError("Falco evidence must reference a nonempty scalar string")
    return scalar.encode("utf-8")
