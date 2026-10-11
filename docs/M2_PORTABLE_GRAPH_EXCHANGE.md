# M2.8 — Versioned portable graph exchange (offline candidate-only)

**Status:** Draft FR-18 partial implementation; 21 authored synthetic and
adversarial tests, not executed/CI-validated. Based directly on stable
main, independent of unfinished PR #51, #52 and #53. No approved historical
source versions, label sets or real B0/G1 study results were created.

## Goal and safety boundary

Transfer exact, provenance-attributed **source-view and graph metadata**
between research workspaces without committing publisher article bodies,
reference/ground-truth labels, future evidence, provisional G1 hypotheses,
tokens or credentials. The supplied inputs must already satisfy the strict
source-view and graph contracts in src/threatragraph/contracts.py.

This work does NOT create a writable SQLite ingest path, does not verify
original bytes, source redistribution rights, real publication timestamps,
semantic truth, reviewer identities or researcher study approval.

## Exchange formats

The Python module src/threatragraph/portable_exchange.py provides:

- create_bundle(view, graph, reviewed=bool): validate the existing view and
  attributed graph contract, then produce a canonical, content-addressed
  portable_sourced_graph_bundle envelope.
- bundle_json() and parse_bundle_json(): stable UTF-8 JSON serialization,
  duplicate-key refusal, exact schema enforcement, and SHA-256 fingerprint
  checks. Embedded source views, graph claims, and evidence locators remain
  unaltered; no text-body bytes are included.
- export_claims_csv(): deterministic, explicitly ordered column representation
  of the graph's sourced claims, with canonical evidence_locator_json and
  review status where present.
- verify_claims_csv(csv, bundle): read imported CSV and refuse any changed
  field, missing/duplicate/extra claim, reordered/malformed header, wrong
  evidence locator, unsupported review status or differing source identity.
  The matching validated JSON bundle is mandatory. After field-level parity,
  imported CSV bytes must match the canonical v1 export exactly: appended
  blank rows and alternative quoting or line endings are refused. No
  untrusted CSV is ever allowed to insert a claim into SQLite automatically.

A successful receipt has research_ready=false and original_source_bytes_verified
and reviewer_identities_verified both false. A self-hash detects inadvertent
changes; it is **not a publisher signature or independent proof of approval**.

CSV formula-like fields (=, +, -, @) are rejected, including when preceded
by invisible Unicode formatting characters (such as BOM and zero-width
spaces). Embedded control characters and line breaks in exported fields
are refused instead of being silently rewritten into unsafe spreadsheet
formulas.
Import/export operate on bounded local data: 8 MiB maximum per interchange
file, at most 10,000 graph claims.

## CLI

For an existing bounded, already-cited B0 or G1 graph projection:

    python -m scripts.exchange_graph_bundle \
      --mode export --view artifacts/snapshots/b0-view.json \
      --graph artifacts/graphs/b0.json --reviewed

By default, this is a read-only preview. To write both canonical JSON and CSV
artifacts using exclusive creation and content-addressed filenames:

    python -m scripts.exchange_graph_bundle \
      --mode export --view artifacts/snapshots/b0-view.json \
      --graph artifacts/graphs/b0.json --reviewed \
      --write --output-dir artifacts/portable_exchange

Verification never needs source article bodies or SQLite writes:

    python -m scripts.exchange_graph_bundle \
      --mode verify --bundle artifacts/portable_exchange/BUNDLE.json \
      --csv artifacts/portable_exchange/CLAIMS.csv

The actual output filenames are canonical byte SHA-256 hashes with .json and
.csv extensions. Duplicate JSON fields, symlinks, invalid metadata, future
sources, unsupported ontology triples, malformed review states, changed claim
IDs and mismatched input digests are refused.

Writes are immutable **per artifact**, not an atomic multi-file transaction:
a failure after writing JSON may leave an intact content-addressed JSON
artifact; a retry reuses identical bytes or refuses conflicting content.

## Next tasks

- Run the dedicated local test module and complete full cross-platform CI
  after runner billing/minute restriction is resolved, without paying.
- Security review CSV formula handling, JSON duplicate/null/nonfinite values,
  malformed CSV, large input limits, and stale source/case identities.
- Integrate actual preapproved source ingestion separately after original-byte
  replay, date/right-of-use review, and independently checked semantic reviews.
- Optional STIX export requires truly conformant STIX 2.x objects and their
  own schema validators. This deliberately does not invent STIX mappings.
- Build FR-13 date-valid aliases with explicit identity/collision policy; never
  silently retroactively enrich frozen B0/G1 profiles.

The status ledger must describe FR-18 as **partial/draft/unverified** until
the code has been executed and independently inspected.
