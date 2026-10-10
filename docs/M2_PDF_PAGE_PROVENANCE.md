# M2 — PDF Page Text Evidence Provenance

**Status:** Implemented with generated, synthetic PDFs and CI; **no real CTI PDFs or historical case sources approved**.

**Tracking:** [Issue #15](https://github.com/FardinSamin/ThreatRAGraph/issues/15). **Related:** [M2 evidence alignment](M2_EVIDENCE_ALIGNMENT.md), [M2 normalization](M2_HTML_FALCO_NORMALIZATION.md), [M2 graph](M2_EVIDENCE_GRAPH.md).

## Why this component exists

PDF-based threat intelligence documents are common, but copying a quote and a page number into a JSON record does not prove the quote actually came from that PDF. This change extracts **per-page text** directly from the **archived, SHA-256-approved PDF source version** every time an evidence claim is checked. It then recomputes the SHA-256 of the exact page substring and compares it with the claimed evidence hash.

A valid citation is evidence of a matching extracted text fragment; **it is not evidence that the statement is true, that the graph edge is semantically justified, or that the PDF was publicly available at the historical cutoff**.

## Parser and normalization protocol

**Normalizer version:** `pdf-text-v1-pypdf-6.20.0`. **Package:** `pypdf==6.20.0`, pinned in [requirements-normalization.txt](../requirements-normalization.txt). This version was released October 9, 2026 and contains a limit on PDF stream decoding work; it does not remove the need for OS/process-level resource controls when untrusted files are processed.

- Input **must** be the exact original PDF bytes with `%PDF-` header in the M1 content-addressed archive.
- Source-version SHA-256 is recomputed from the original bytes and must match the approved source manifest.
- `PdfReader(..., strict=True)` must successfully parse the file. Encrypted, structurally invalid, very large, or unsupported-page-count PDFs fail closed.
- Page text is extracted in pypdf **plain** extraction mode. For each page, all Unicode whitespace runs are collapsed to a single ASCII space with `" ".join(extracted.split())`. This is a deterministic, versioned **normalization policy**, not original layout preservation.
- The returned text remains ordered by page, with a separate normalized string for each **one-based page number**. Empty text pages stay empty in the page list, and attempts to cite them are rejected.
- The system does not perform OCR, render images, execute JavaScript, access the internet, fetch external resources or trust an externally supplied normalized text file.

### Current safety limits

| Limit | Value |
|---|---:|
| Archived input PDF | 8 MiB |
| PDF pages | 40 |
| Extracted page text | 128 KiB |
| Extracted total text | 2 MiB |
| Claimed excerpt | Existing global evidence limit of 128 KiB |

These are application-level limits. They **do not guarantee** protection from every crafted/hostile compressed stream, parser bug, or memory exhaustion; process isolation/resource limits are required before accepting arbitrary PDF uploads into a production system.

## Exact evidence locator

A `pdf_page_span` locator identifies a **particular PDF page in a particular approved source version**, pinned to the exact parser/normalizer version:

~~~json
{
  "kind": "pdf_page_span",
  "normalizer_version": "pdf-text-v1-pypdf-6.20.0",
  "page_number": 2,
  "segment_id": "page:SOURCE_VERSION_ID:pdf-text-v1-pypdf-6.20.0:2",
  "start": 0,
  "end": 12
}
~~~

- `page_number` is **1-based** and must exist.
- `start` and `end` are **0-based Unicode code-point positions** within the normalized text of **that page only**, with exclusive end.
- `segment_id` must exactly match the source version ID, parser version and page number. It cannot be reused across different PDFs or pages.
- `evidence_sha256` on the claim must match the **UTF-8 bytes of the selected normalized substring**.
- The associated approved `source_kind` must be a CTI report, CVE advisory, Kubernetes document, or approved other source; a Falco YAML rule cannot be presented as a PDF incident report. PDF citations require `assertion_kind=report_assertion`.

A forged page number, wrong digest, wrong source version, unsupported parser version or out-of-range/empty offset is rejected **before SQLite inserts the claim**. The graph projection only accepts such aligned evidence after the M1 source-archive audit and M3 historical early/background source allowlist checks.

## Reproducible synthetic tests

The tests generate real multi-page text PDFs locally using pinned pypdf; they do not upload confidential research PDFs.

~~~powershell
python -m pip install -r requirements-normalization.txt
python -m unittest discover -s tests -v
~~~

Tests cover correct page number/text attribution, Unicode span boundaries in the general verifier, mismatched parser/source IDs, modified source bytes, malicious citation hashes, unsupported source types, invalid PDF headers/structure, encrypted PDFs, image-only/blank pages, file-size limits, and SQLite aligned status. The CLI's source-allowlist rules are inherited unchanged from M3.

## What remains

- OCR for scanned reports; graphics/figures, tables with ambiguous extraction order, and page-layout coordinate mapping are **not supported**. A page with no selectable text must not silently produce a claim.
- pypdf does not prove how the page looks to a human; **visual review remains necessary** for ambiguous tables, overprinted text, redactions or badly embedded fonts.
- Independently verifying exact public availability, source rights, published revisions and subsequent extracted relationship semantics is mandatory before real research evaluation.
- True case counts and approved corpus versions, original local prototype integration, model contamination studies and GraphRAG scoring remain pending under [#1](https://github.com/FardinSamin/ThreatRAGraph/issues/1), [#3](https://github.com/FardinSamin/ThreatRAGraph/issues/3) and [#11](https://github.com/FardinSamin/ThreatRAGraph/issues/11).

**This feature is page-scoped citation integrity infrastructure, not an OCR service, PDF attack detector, complete CTI extraction pipeline, or empirical GraphRAG result.**
