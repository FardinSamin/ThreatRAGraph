# Independent sidecar integration — draft candidate

**Status:** New integration draft based on PR #59. No execution of the
new tests, original source lookups, authenticated review or historical
study scoring. This is not a merge to main or independent empirical result.

## Included independently, without promoting provenance

- PR #51: direct Common Crawl CDXJ original-source **discovery tool**,
  synthetic tests, and investigation report. The mandatory known-original
  Cado positive control is not independently confirmed in this integration.
  No new CrowdStrike/Sysdig primary article is approved.
- PR #54: versioned JSON/CSV attributed-graph evidence exchange. It
  serializes metadata only and **does not insert into SQLite** or verify
  original article byte rights or reviewer identities.
- PR #55: read-only, historically dated typed-alias *candidates*. Alias
  mapping into B0/G1 remains expressly prohibited, even when a candidate
  is structurally supported.
- New sidecar reconciliation module: compares the exact saved B0/G1
  source views and reviewed graph objects with their separately prepared
  portable bundles, checks B0/G1 early-source parity, supported and byte-aligned reviewed
  source claims, independent historical background publisher groups, and
  excludes background target-specific claims. It optionally checks
  a candidate alias history tied exactly to the B0 view. Results contain
  only digests, candidate counts and explicit caveats, never raw articles.

## Workflow conflict deliberately avoided

PR #51 modifies `.github/workflows/quality.yml` to perform extra
original-source verification. PR #60 proposes a separate budget-aware
workflow that skips costly historical witnesses by default. Importing
both incompatible changes into this integration candidate would silently
risk duplicate Actions runs, so this branch copies ONLY the archive
discovery source, tests and research document — **not PR #51's workflow
or older README/build-plan/status edits**. It keeps the parent PR #59
workflow unchanged. The workflow proposals remain separately reviewable
and unmerged; a future human must decide which verification jobs to
run during the funded/available validation phase.

## Command

Prepare exact previously frozen early B0 and G1 view/graph JSON artifacts,
plus two portable bundles created separately by the portable exchange
tool. Optionally, provide their exact canonical CSV exports **as a pair**.
Then from the repository root:

    python -m scripts.audit_independent_sidecars --b0-view PATH --b0-graph PATH --g1-view PATH --g1-graph PATH --b0-bundle PATH --g1-bundle PATH --b0-csv B0.csv --g1-csv G1.csv --alias-history OPTIONAL_PATH

The final `--alias-history` may be omitted; when supplied it must match
the B0 source view and chronology exactly. Both `--b0-csv` and `--g1-csv`
may be omitted for a JSON-only reconciliation, but specifying either one
requires the other. Each witness is checked against its own sealed bundle,
including identical rows and **exact canonical CSV bytes**. The receipt then
contains `csv_witnesses_verified=true` and both CSV SHA-256 hashes.
Without CSV files, it explicitly states `csv_witnesses_verified=false`
and null CSV hashes; a JSON-only check is not a CSV verification. The command is read-only and
fails closed on changed evidence, unexpected review modes, wrong-case alias
records, mismatched early G1 sources or unsafe input JSON.

This is a **structural compatibility receipt** only. The exchange bundle
does not revalidate original source timestamps or bytes, and the alias
candidate index does not independently prove names represent the same
entity. Neither becomes a pipeline input or feature enrichment.

## Validation gates

- 19 synthetic original-CDXJ tests, 24 exchange tests, 15 shared
  local-file tests, 16 atomic-output tests, 21 alias tests, and 25 sidecar integration tests are **authored but not executed** in
  this branch. Those counts are inventories, not pass rates.
- `python -m scripts.preflight_validation_plan --scope all` is a
  static check only; do not claim passing tests. Real unit/CLI tests,
  lint/security scans and full Linux/Windows CI remain deferred.
- Independently inspect the original Cado positive control, source
  rights, archival chronology, reviewer identity, historical alias
  provenance, and any independently attested freeze before results.
- Resolve README/build-plan amendments and PR #51/PR #60 workflow
  choices in a **separate reviewed change**. Avoid unexpected paid
  GitHub Actions usage; this draft does not authorize paid overages.

All outputs and the status ledger remain candidate-only and
`research_ready=false`. Parent branches #51/#54/#55 are not rewritten
or force-pushed.

## Static integration-review hardening

This integration draft also incorporates narrowly scoped upstream fixes:
PR #54 now rejects invisible Unicode spreadsheet-formula prefixes and
embedded control characters in exported CSV fields, and verifies canonical
CSV bytes in addition to parsed claim rows (24 authored, unexecuted tests).
PR #55 now reports contradictory supported/rejected identity evidence as
**conflicting_evidence_requires_adjudication**, not a single uncontested
candidate (21 authored, unexecuted tests). The sidecar reconciler refuses
unaligned, unsupported or background-contaminated source evidence and counts
competing/rebutted alias mappings without converting them into features.
Its 25 authored synthetic tests are unexecuted.

No historical source rights, dates, semantic truth or reviewer identities
were independently authenticated by these contract fixes.

## Paired CSV witness refinement (unexecuted)

The reconciler can now verify both canonical B0 and G1 CSV witnesses
against their corresponding exact source-view/graph JSON bundles in the same
read-only invocation. The two CSVs are optional as a **pair**, not
independently; missing partners, altered claims, and equivalent but
noncanonical CSV are refused. Eight additional authored tests exercise the
paired library and CLI contracts. This is not proof of source copyright,
publisher chronology, human semantic review, or research readiness.

## Bounded local input-reader consolidation (unexecuted)

The exchange, alias and combined sidecar CLIs now use one bounded helper
`src/threatragraph/local_file_inputs.py` with strict UTF-8 decoding,
refusal of nested duplicate/nonfinite JSON, binary read-size bounds,
file-change checks, regular-file checks, no-follow directory traversal on
POSIX, and Windows symlink/junction component checks (with documented
race limitations). Distinct input arguments must not reference the same
inode, even through hardlinks. The new shared helper has 15 authored tests.
The exchange suite has 24 tests; alias has 21; integrated sidecar has 25.

These local filesystem protections do **not** authenticate original
publisher evidence, prove reviewer independence, replace sandboxing, or
establish that the historical case is research-ready. CI and local tests
remain deferred; no passing outcome is implied by authored test counts.

## Atomic per-file publication (new draft storage hardening)

The bundle JSON, CSV exports, single-case artifacts, multi-case artifacts
and immutable research views now route through a shared SHA-addressed byte
publisher in `src/threatragraph/immutable_artifacts.py`. It stages and
fsyncs complete bytes under a private name, then creates each final digest
filename with a no-replace hardlink. The stage is removed on normal errors.
An abrupt kill can leave private incomplete stage files, but cannot publish
an incomplete digest-named destination through this writer.

This does **not** make a multi-artifact batch transaction atomic or prove
that a source was historical or independently reviewed. The last-written
batch receipt marks the logical completion of per-case file publication;
a filesystem failure may still leave reusable individual digest files.
Cross-platform filesystem semantics, concurrent write behavior and crash
recovery require executed validation. **16 writer failure-injection tests
were authored but not run**. See `docs/IMMUTABLE_ARTIFACT_OUTPUT_POLICY.md`.
