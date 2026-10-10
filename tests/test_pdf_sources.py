"""Synthetic, offline PDF byte-to-page evidence provenance tests.

Every document is generated locally using pinned pypdf. No external PDFs,
OCR, network access, LLM extraction, or historical CTI source claims.
"""
from io import BytesIO
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from pypdf import PdfWriter
from pypdf.generic import DictionaryObject, NameObject, DecodedStreamObject

from src.threatragraph.pdf_sources import (
    PDF_NORMALIZER_VERSION, normalized_pdf_pages,
)
from src.threatragraph.evidence_alignment import EvidenceVerifier
from src.threatragraph.evidence_graph import EvidenceGraph
from scripts.project_case_graph import run


def sha(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def synthetic_pdf(pages, password=None):
    """Create a real PDF with plain, ASCII Helvetica text content streams."""
    writer = PdfWriter()
    for text in pages:
        page = writer.add_blank_page(width=612, height=792)
        if text is not None:
            font = DictionaryObject({
                NameObject("/Type"): NameObject("/Font"),
                NameObject("/Subtype"): NameObject("/Type1"),
                NameObject("/BaseFont"): NameObject("/Helvetica"),
            })
            font_ref = writer._add_object(font)
            page[NameObject("/Resources")] = DictionaryObject({
                NameObject("/Font"): DictionaryObject({NameObject("/F1"): font_ref})
            })
            stream = DecodedStreamObject()
            # Escaped PDF strings; these tests deliberately use ASCII text.
            escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            stream.set_data(
                ("BT /F1 12 Tf 72 700 Td (" + escaped + ") Tj ET").encode("ascii")
            )
            page[NameObject("/Contents")] = writer._add_object(stream)
    if password:
        writer.encrypt(password)
    out = BytesIO()
    writer.write(out)
    return out.getvalue()


class PDFSourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.sources = []

    def tearDown(self):
        self.tmp.cleanup()

    def archive(self, source_version, raw, source_kind="cti_report"):
        digest = sha(raw)
        folder = self.root / digest[:2]
        folder.mkdir(parents=True, exist_ok=True)
        (folder / digest).write_bytes(raw)
        record = {
            "source_id": "src:" + source_version,
            "source_version_id": source_version,
            "source_kind": source_kind,
            "status": "approved",
            "sha256": digest,
            "available_at": "2024-01-01T00:00:00Z",
            "date_confidence": "verified",
            "date_evidence": "Synthetic unit-test fixture only",
        }
        self.sources.append(record)
        return record

    def verifier(self):
        return EvidenceVerifier({"sources": self.sources}, self.root)

    def claim(self, version, page, text, start=0, end=None):
        if end is None:
            end = start + len(text)
        return {
            "source_version_id": version,
            "subject_id": "malware:synthetic",
            "predicate": "USES",
            "object_id": "attack-technique:T1059",
            "assertion_kind": "report_assertion",
            "polarity": "positive",
            "evidence_locator": {
                "kind": "pdf_page_span",
                "normalizer_version": PDF_NORMALIZER_VERSION,
                "page_number": page,
                "segment_id": (
                    "page:" + version + ":" + PDF_NORMALIZER_VERSION + ":" + str(page)
                ),
                "start": start, "end": end,
            },
            "evidence_sha256": sha(text),
            "extractor_version": "fixture/pdf-v1",
        }

    def test_actual_two_page_text_extraction(self):
        raw = synthetic_pdf(["Malware uses execve", "Falco rule describes exec"])
        self.assertEqual(("Malware uses execve", "Falco rule describes exec"),
                         normalized_pdf_pages(raw))

    def test_second_page_claim_only_matches_second_page(self):
        raw = synthetic_pdf(["Page one entirely different", "Malware uses execve"])
        self.archive("pdf-a", raw)
        claim = self.claim("pdf-a", 2, "Malware uses execve")
        self.assertEqual("aligned", self.verifier().verify(claim).status)
        claim["evidence_locator"]["page_number"] = 1
        claim["evidence_locator"]["segment_id"] = (
            "page:pdf-a:" + PDF_NORMALIZER_VERSION + ":1"
        )
        with self.assertRaisesRegex(ValueError, "Evidence hash"):
            self.verifier().verify(claim)

    def test_page_number_one_based_and_bounded(self):
        raw = synthetic_pdf(["Malware uses execve"])
        self.archive("pdf-a", raw)
        for page in (0, -1, True, 2, "1"):
            c = self.claim("pdf-a", page, "Malware uses execve")
            with self.subTest(page=page), self.assertRaises(ValueError):
                self.verifier().verify(c)

    def test_invalid_page_segment_or_parser_version_is_rejected(self):
        raw = synthetic_pdf(["Malware uses execve"])
        self.archive("pdf-a", raw)
        claim = self.claim("pdf-a", 1, "Malware uses execve")
        claim["evidence_locator"]["segment_id"] = "page:pdf-b:" + PDF_NORMALIZER_VERSION + ":1"
        with self.assertRaisesRegex(ValueError, "segment ID"):
            self.verifier().verify(claim)
        claim = self.claim("pdf-a", 1, "Malware uses execve")
        claim["evidence_locator"]["normalizer_version"] = "pdf-text-v0"
        with self.assertRaisesRegex(ValueError, "normalizer"):
            self.verifier().verify(claim)

    def test_forged_digest_and_off_end_offsets_are_rejected(self):
        raw = synthetic_pdf(["Malware uses execve"])
        self.archive("pdf-a", raw)
        claim = self.claim("pdf-a", 1, "Invented text")
        with self.assertRaisesRegex(ValueError, "Evidence hash"):
            self.verifier().verify(claim)
        claim = self.claim("pdf-a", 1, "Malware uses execve")
        claim["evidence_locator"]["end"] = 10000
        with self.assertRaisesRegex(ValueError, "out of page bounds"):
            self.verifier().verify(claim)

    def test_blank_page_requires_ocr_or_other_evidence(self):
        raw = synthetic_pdf([None, "Page two textual"])
        self.archive("pdf-a", raw)
        claim = self.claim("pdf-a", 1, "whatever")
        with self.assertRaisesRegex(ValueError, "no extractable text"):
            self.verifier().verify(claim)
        self.assertEqual("aligned",
                         self.verifier().verify(self.claim("pdf-a", 2, "Page two textual")).status)

    def test_all_blank_pdf_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "no extractable text"):
            normalized_pdf_pages(synthetic_pdf([None, None]))

    def test_encrypted_pdf_requires_manual_handling(self):
        raw = synthetic_pdf(["A test"], password="example")
        with self.assertRaisesRegex(ValueError, "Encrypted"):
            normalized_pdf_pages(raw)

    def test_broken_or_oversized_pdf_rejected(self):
        for raw in (b"%PDF-1.7\nbroken archive", b"arbitrary not pdf",
                    b"%PDF-" + b"a" * (8 * 1024 * 1024 + 1)):
            with self.subTest(len=len(raw)), self.assertRaises(ValueError):
                normalized_pdf_pages(raw)

    def test_pdf_parser_version_is_pinned(self):
        import pypdf
        raw = synthetic_pdf(["Some text"])
        with patch.object(pypdf, "__version__", "0.0.0"):
            with self.assertRaisesRegex(ValueError, "parser-version mismatch"):
                normalized_pdf_pages(raw)

    def test_wrong_source_kind_and_assertion_kind_refused(self):
        raw = synthetic_pdf(["Malware uses execve"])
        self.archive("pdf-a", raw, source_kind="falco_rule")
        with self.assertRaisesRegex(ValueError, "not permitted"):
            self.verifier().verify(self.claim("pdf-a", 1, "Malware uses execve"))
        self.sources[-1]["source_kind"] = "cti_report"
        c = self.claim("pdf-a", 1, "Malware uses execve")
        c["assertion_kind"] = "rule_semantics"
        with self.assertRaisesRegex(ValueError, "report assertion"):
            self.verifier().verify(c)

    def test_archive_tampering_is_detected(self):
        rec = self.archive("pdf-a", synthetic_pdf(["original"]))
        file = self.root / rec["sha256"][:2] / rec["sha256"]
        file.write_bytes(synthetic_pdf(["changed"]))
        with self.assertRaisesRegex(ValueError, "differs from approved"):
            self.verifier().verify(self.claim("pdf-a", 1, "original"))

    def test_pdf_claim_in_ledger_has_aligned_status(self):
        self.archive("pdf-a", synthetic_pdf(["Malware uses execve"]))
        with sqlite3.connect(":memory:") as conn:
            ledger = EvidenceGraph(conn, evidence_verifier=self.verifier())
            ledger.register_source_versions({"sources": self.sources})
            ledger.append_source_claim(self.claim("pdf-a", 1, "Malware uses execve"))
            self.assertEqual("aligned", conn.execute(
                "SELECT evidence_status FROM sourced_claims"
            ).fetchone()[0])

    def test_pdf_page_citation_in_historical_b0_g1_cli(self):
        """The actual CLI must verify a PDF claim and exclude later sources."""
        early_bytes = synthetic_pdf(["Sparse initial report", "Malware uses execve"])
        self.archive("early-pdf", early_bytes)
        self.archive("background", b"background malware uses execve")
        self.archive("heldout", b"later reference is never exposed")
        for record in self.sources:
            record.update({
                "title": "Synthetic " + record["source_version_id"],
                "publisher": "Fixture only",
                "url": "https://example.org/" + record["source_version_id"],
                "published_at": record["available_at"],
                "independence_group": "group:" + record["source_version_id"],
                "redistribution": "restricted",
                "selection_rationale": "Unit fixture, not real CTI",
            })
        for record in self.sources:
            if record["source_version_id"] == "heldout":
                record["published_at"] = "2024-02-01T00:00:00Z"
                record["available_at"] = "2024-02-01T00:00:00Z"
            elif record["source_version_id"] == "background":
                record["published_at"] = "2023-12-01T00:00:00Z"
                record["available_at"] = "2023-12-01T00:00:00Z"
        sources = {
            "schema_version": "1.0", "dataset_id": "fixture", "dataset_version": "v1",
            "sources": self.sources,
        }
        cases = {
            "schema_version": "1.0", "dataset_id": "fixture", "dataset_version": "v1",
            "cases": [{
                "case_id": "case-fixture",
                "target_entity_id": "malware:synthetic",
                "selection_rationale": "Synthetic end-to-end PDF provenance",
                "cutoff_at": "2024-01-15T00:00:00Z",
                "early_source_version_ids": ["early-pdf"],
                "background_source_version_ids": ["background"],
                "later_reference_source_version_ids": ["heldout"],
            }],
        }
        first = self.claim("early-pdf", 2, "Malware uses execve")
        second = {
            "source_version_id": "background", "subject_id": "malware:history",
            "predicate": "USES", "object_id": "attack-technique:T1059",
            "assertion_kind": "report_assertion", "polarity": "positive",
            "evidence_locator": {
                "kind": "text_span", "segment_id": "seg:background",
                "start": 0, "end": 10,
            },
            "evidence_sha256": sha("background"),
            "extractor_version": "synthetic/1",
        }
        claims = self.root / "claims.jsonl"
        claims.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n")
        output = run(sources, cases, "case-fixture", claims, self.root,
                     development=True)
        self.assertEqual(1, len(output["B0"]["edges"]))
        self.assertEqual(2, len(output["G1"]["edges"]))
        self.assertEqual("aligned", output["B0"]["edges"][0]["evidence_status"])
        self.assertEqual("pdf_page_span",
                         output["B0"]["edges"][0]["evidence_locator"]["kind"])
        self.assertNotIn("heldout", json.dumps(output))

    def test_pdf_whitespace_normalization_is_documented(self):
        raw = synthetic_pdf(["Malware  uses   execve"])
        self.assertEqual(("Malware uses execve",), normalized_pdf_pages(raw))


if __name__ == "__main__":
    unittest.main()
