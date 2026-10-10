"""Deterministic, page-scoped text extraction from *archived* PDF source bytes.

This is source-byte-linked text extraction, not OCR, text rendering, visual
coordinate proof, publication dating, or semantic assertion validation.
No embedded PDF content is executed or fetched. Extraction is fail-closed
for encrypted/corrupted documents and citations to nonextractable pages.

Pinning pypdf includes the 6.20.0 work-per-stream security improvements.
Run untrusted real-world PDFs with process-level resource limits/sandboxing
as an additional defense: a Python library cannot guarantee resource safety.
"""
from __future__ import annotations

from io import BytesIO

PDF_NORMALIZER_VERSION = "pdf-text-v1-pypdf-6.20.0"
MAX_PDF_BYTES = 8 * 1024 * 1024
MAX_PAGES = 40
MAX_PAGE_TEXT_BYTES = 128 * 1024
MAX_TOTAL_TEXT_BYTES = 2 * 1024 * 1024


def normalized_pdf_pages(raw: bytes) -> tuple[str, ...]:
    """Return page-ordered, whitespace-collapsed Unicode text.

    Empty pages are represented by empty strings so page numbers remain
    stable; no claim may cite an empty page. Text-only extraction may miss
    figures and cannot support claims requiring nontextual figure evidence.
    """
    if not isinstance(raw, bytes) or not raw.startswith(b"%PDF-"):
        raise ValueError("Evidence source is not an original PDF archive")
    if len(raw) > MAX_PDF_BYTES:
        raise ValueError("PDF input exceeds byte limit")
    try:
        import pypdf
        from pypdf import PdfReader
    except ImportError as exc:
        raise ValueError("pypdf==6.20.0 is required for PDF verification") from exc
    if getattr(pypdf, "__version__", None) != "6.20.0":
        raise ValueError("PDF normalizer parser-version mismatch; require pypdf==6.20.0")

    try:
        reader = PdfReader(BytesIO(raw), strict=True)
        if reader.is_encrypted:
            raise ValueError("Encrypted PDF cannot supply verified evidence")
        pages = reader.pages
        count = len(pages)
        if count < 1 or count > MAX_PAGES:
            raise ValueError("PDF has unsupported page count")

        result: list[str] = []
        total = 0
        for page in pages:
            extracted = page.extract_text(extraction_mode="plain")
            if not isinstance(extracted, str):
                raise ValueError("PDF page text extraction returned no text")
            # Stable character offsets refer to this normalized page text,
            # not to PDF compressed streams or visual bounding boxes.
            text = " ".join(extracted.split())
            n = len(text.encode("utf-8"))
            if n > MAX_PAGE_TEXT_BYTES:
                raise ValueError("PDF page extracted text exceeds byte limit")
            total += n
            if total > MAX_TOTAL_TEXT_BYTES:
                raise ValueError("PDF document extracted text exceeds byte limit")
            result.append(text)
        if not any(result):
            raise ValueError("PDF has no extractable text; OCR unsupported")
        return tuple(result)
    except ValueError:
        raise
    except Exception as exc:
        # Avoid reporting untrusted PDF metadata/text in exception messages.
        raise ValueError("PDF parsing or text extraction failed") from exc


def pdf_page_evidence(raw: bytes, source_version_id: str,
                      locator: dict) -> bytes:
    """Select a bounded 1-based page and source-version-bound Unicode span."""
    if locator.get("normalizer_version") != PDF_NORMALIZER_VERSION:
        raise ValueError("PDF normalizer version mismatch")
    page_number = locator.get("page_number")
    if type(page_number) is not int or page_number < 1:
        raise ValueError("PDF page number must be a positive integer")
    expected = f"page:{source_version_id}:{PDF_NORMALIZER_VERSION}:{page_number}"
    if locator.get("segment_id") != expected:
        raise ValueError("PDF page segment ID does not match source and version")
    pages = normalized_pdf_pages(raw)
    if page_number > len(pages):
        raise ValueError("PDF page number outside archived document")
    text = pages[page_number - 1]
    if not text:
        raise ValueError("PDF page has no extractable text; OCR unsupported")
    start, end = locator["start"], locator["end"]
    if start < 0 or end > len(text) or end <= start:
        raise ValueError("PDF text span out of page bounds")
    cited = text[start:end]
    if not cited.strip():
        raise ValueError("PDF evidence span must not be blank")
    return cited.encode("utf-8")
