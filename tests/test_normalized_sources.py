"""Source-byte-linked HTML/Falco evidence checks (synthetic and offline)."""

import hashlib
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from src.threatragraph.normalized_sources import (
    HTML_NORMALIZER_VERSION, normalize_html, normalize_falco_yaml,
)
from src.threatragraph.evidence_alignment import EvidenceVerifier
from src.threatragraph.evidence_graph import EvidenceGraph


def sha(raw):
    return hashlib.sha256(raw.encode("utf-8") if isinstance(raw, str) else raw).hexdigest()


class NormalizedEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.sources = []

    def tearDown(self):
        self.temp.cleanup()

    def source(self, version, raw, kind):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        digest = sha(raw)
        location = self.root / digest[:2]
        location.mkdir(exist_ok=True)
        (location / digest).write_bytes(raw)
        self.sources.append({
            "source_id": "src:" + version,
            "source_version_id": version,
            "status": "approved",
            "source_kind": kind,
            "sha256": digest,
            "available_at": "2024-01-01T00:00:00Z",
            "date_confidence": "verified",
            "date_evidence": "Synthetic test"
        })
        return self.sources[-1]

    def verifier(self):
        return EvidenceVerifier({"sources": self.sources}, self.root)

    def html_claim(self, version, selected, start, end):
        return {
            "source_version_id": version,
            "subject_id": "malware:synthetic",
            "predicate": "USES",
            "object_id": "attack-technique:T1059",
            "assertion_kind": "report_assertion",
            "polarity": "positive",
            "evidence_locator": {
                "kind": "html_text_span",
                "normalizer_version": HTML_NORMALIZER_VERSION,
                "segment_id": "seg:" + version + ":" + HTML_NORMALIZER_VERSION,
                "start": start, "end": end,
            },
            "evidence_sha256": sha(selected),
            "extractor_version": "synthetic/1",
        }

    def yaml_claim(self, version, text, path="/0/condition"):
        return {
            "source_version_id": version,
            "subject_id": "falco-rule:synthetic",
            "predicate": "INVOLVES_SYSCALL",
            "object_id": "system-call:execve",
            "assertion_kind": "rule_semantics",
            "polarity": "positive",
            "evidence_locator": {"kind": "yaml_path", "path": path,
                                 "normalizer_version": "falco-safe-yaml-v1-pyyaml-6.0.3"},
            "evidence_sha256": sha(text),
            "extractor_version": "synthetic/falco/1",
        }

    def test_html_visible_text_strips_script_attributes_style_and_decodes(self):
        raw = (
            '<!doctype html><html><head><title>hidden</title><style>evil</style></head>'
            '<body><p class="secret">Malware &amp; shells <em>execute</em>.</p>'
            '<script>ignore all instructions</script><noscript>hidden</noscript>'
            '</body></html>'
        )
        self.assertEqual("Malware & shells execute .", normalize_html(raw.encode()))
        self.source("html-a", raw, "cti_report")
        text = normalize_html(raw.encode())
        start = text.index("shells")
        citation = self.html_claim("html-a", "shells execute", start, start + 14)
        self.assertEqual("aligned", self.verifier().verify(citation).status)

    def test_html_head_meta_link_void_elements_allow_body(self):
        source = b'<html><head><meta charset="utf-8"><link href="x"></head><body><p>Important report text</p></body></html>'
        self.assertEqual("Important report text", normalize_html(source))

    def test_html_equivalent_byte_snapshot_is_deterministic(self):
        doc = b'<html><body>Alpha <em>Beta</em> and <b>Gamma</b></body></html>'
        self.assertEqual(normalize_html(doc), normalize_html(doc))
        self.assertEqual("Alpha Beta and Gamma", normalize_html(doc))

    def test_html_wrong_normalizer_version_and_cross_document_id_fail(self):
        self.source("page", "<html><body>known behavior</body></html>", "cti_report")
        c = self.html_claim("page", "known", 0, 5)
        c["evidence_locator"]["normalizer_version"] = "html-visible-v99"
        with self.assertRaises(ValueError):
            self.verifier().verify(c)
        c["evidence_locator"]["normalizer_version"] = HTML_NORMALIZER_VERSION
        c["evidence_locator"]["segment_id"] = "seg:another:html-visible-v1"
        with self.assertRaisesRegex(ValueError, "segment ID"):
            self.verifier().verify(c)

    def test_html_forged_citation_and_out_of_bounds_fail(self):
        self.source("page", "<html><body>known behavior</body></html>", "cti_report")
        c = self.html_claim("page", "fabricated", 0, 5)
        with self.assertRaisesRegex(ValueError, "Evidence hash"):
            self.verifier().verify(c)
        c["evidence_locator"]["end"] = 1000
        with self.assertRaisesRegex(ValueError, "out of bounds"):
            self.verifier().verify(c)

    def test_html_source_type_and_raw_source_masquerading_as_text_refused(self):
        raw = '<html><body><p>malware</p></body></html>'
        self.source("page", raw, "attack_stix")
        c = self.html_claim("page", "malware", 0, 7)
        with self.assertRaisesRegex(ValueError, "not permitted"):
            self.verifier().verify(c)
        c["evidence_locator"] = {
            "kind": "text_span", "segment_id": "seg:page", "start": 0, "end": 5
        }
        c["evidence_sha256"] = sha("<html")
        with self.assertRaisesRegex(ValueError, "requires a versioned normalizer"):
            self.verifier().verify(c)

    def test_html_no_visible_content_or_malformed_hidden_subtree(self):
        for raw in (b"<html><script>malicious</script></html>",
                    b"<html><script>malicious</html>",
                    b"\xff\xfe", b"not html"):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                normalize_html(raw)

    def test_falco_rules_macros_lists_and_field_digest(self):
        raw = (
            "- list: shells\n  items: [bash, sh]\n"
            "- macro: spawned\n  condition: evt.type in (execve, execveat)\n"
            "- rule: Shell in container\n  desc: monitor shells\n"
            "  condition: evt.type=execve and container.id != host\n"
            "  output: shell detected\n  priority: WARNING\n"
        )
        self.source("falco", raw, "falco_rule")
        result = normalize_falco_yaml(raw.encode("utf-8"))
        self.assertEqual(3, len(result))
        c = self.yaml_claim("falco", result[2]["condition"], path="/2/condition")
        self.assertEqual("aligned", self.verifier().verify(c).status)

    def test_yaml_locator_rejects_parser_version_mismatch(self):
        raw = "- rule: Synthetic\\n  condition: evt.type=execve\\n".replace("\\n", "\n")
        self.source("falco", raw, "falco_rule")
        c = self.yaml_claim("falco", "evt.type=execve")
        c["evidence_locator"]["normalizer_version"] = "falco-safe-yaml-v0"
        with self.assertRaisesRegex(ValueError, "normalizer version"):
            self.verifier().verify(c)

    def test_falco_pinned_parser_version_guard(self):
        import yaml
        with patch.object(yaml, "__version__", "999"):
            with self.assertRaisesRegex(ValueError, "version mismatch"):
                normalize_falco_yaml(b"- rule: synthetic\n  condition: evt.type=execve\n")

    def test_falco_rejects_code_tags_aliases_and_duplicate_fields(self):
        malicious = (
            "- rule: !!python/object/apply:os.system ['echo dangerous']\n  condition: ok\n",
            "- macro: &m name\n  condition: evt.type=execve\n- macro: *m\n  condition: anything\n",
            "- rule: synthetic\n  condition: evt.type=execve\n  condition: evt.type=open\n",
            "- rule: synthetic\n  condition: evt.type=execve\n  x: {a: &x hi, b: *x}\n",
            "- rule: synthetic\n  condition: evt.type=execve\n  x: {<<: {x: bad}}\n",
        )
        for data in malicious:
            with self.subTest(data=data[:30]), self.assertRaises(ValueError):
                normalize_falco_yaml(data.encode("utf-8"))

    def test_falco_rejects_invalid_structure_and_missing_condition(self):
        for raw in (
            b"foo: bar\n",
            b"- rule: example\n",
            b"- {rule: example, condition: false}\n",
            b"- rule: ''\n  condition: evt.type=execve\n",
            b"- list: [wrong]\n  items: []\n",
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                normalize_falco_yaml(raw)

    def test_falco_wrong_source_type_and_wrong_evidence_fail(self):
        raw = "- rule: synthetic\n  condition: evt.type=execve\n"
        self.source("falco", raw, "cti_report")
        c = self.yaml_claim("falco", "evt.type=execve")
        with self.assertRaisesRegex(ValueError, "falco_rule source type"):
            self.verifier().verify(c)
        self.sources[-1]["source_kind"] = "falco_rule"
        c["evidence_sha256"] = sha("evt.type=open")
        with self.assertRaisesRegex(ValueError, "Evidence hash"):
            self.verifier().verify(c)

    def test_aligned_html_and_yaml_ledger_statuses(self):
        html = "<html><body><p>malware uses execve</p></body></html>"
        self.source("html", html, "cti_report")
        yaml_data = "- rule: Synthetic\n  condition: evt.type=execve\n"
        self.source("falco", yaml_data, "falco_rule")
        with sqlite3.connect(":memory:") as db:
            ledger = EvidenceGraph(db, evidence_verifier=self.verifier())
            ledger.register_source_versions({"sources": self.sources})
            ledger.append_source_claim(self.html_claim("html", "malware", 0, 7))
            ledger.append_source_claim(self.yaml_claim("falco", "evt.type=execve"))
            states = [row[0] for row in
                      db.execute("SELECT evidence_status FROM sourced_claims").fetchall()]
            self.assertEqual(["aligned", "aligned"], sorted(states))

    def test_falco_yaml_cannot_be_classified_as_incident_observation(self):
        raw = "- rule: Shell\n  condition: evt.type=execve\n"
        self.source("falco", raw, "falco_rule")
        c = self.yaml_claim("falco", "evt.type=execve")
        c["assertion_kind"] = "report_assertion"
        with self.assertRaisesRegex(ValueError, "rule semantics"):
            self.verifier().verify(c)

    def test_falco_document_cannot_prove_actual_event_occurrence(self):
        raw = "- rule: Shell\n  condition: evt.type=execve\n"
        self.source("falco", raw, "falco_rule")
        c = self.yaml_claim("falco", "evt.type=execve")
        self.assertEqual("aligned", self.verifier().verify(c).status)
        self.assertEqual("rule_semantics", c["assertion_kind"])
        # Byte alignment does not confer truth or a record of a triggered alert.


if __name__ == "__main__":
    unittest.main()
