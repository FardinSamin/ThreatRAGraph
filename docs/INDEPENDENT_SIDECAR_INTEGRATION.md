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
tool. Then from the repository root:

    python -m scripts.audit_independent_sidecars --b0-view PATH --b0-graph PATH --g1-view PATH --g1-graph PATH --b0-bundle PATH --g1-bundle PATH --alias-history OPTIONAL_PATH

The final `--alias-history` may be omitted; when supplied it must match
the B0 source view and chronology exactly. The command is read-only and
fails closed on changed evidence, unexpected review modes, wrong-case alias
records, mismatched early G1 sources or unsafe input JSON.

This is a **structural compatibility receipt** only. The exchange bundle
does not revalidate original source timestamps or bytes, and the alias
candidate index does not independently prove names represent the same
entity. Neither becomes a pipeline input or feature enrichment.

## Validation gates

- 19 synthetic original-CDXJ tests, 21 exchange tests, 18 alias tests,
  and 14 sidecar integration tests are **authored but not executed** in
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
CSV bytes in addition to parsed claim rows (21 authored, unexecuted tests).
PR #55 now reports contradictory supported/rejected identity evidence as
**conflicting_evidence_requires_adjudication**, not a single uncontested
candidate (18 authored, unexecuted tests). The sidecar reconciler refuses
unaligned, unsupported or background-contaminated source evidence and counts
competing/rebutted alias mappings without converting them into features.
Its 14 authored synthetic tests are unexecuted.

No historical source rights, dates, semantic truth or reviewer identities
were independently authenticated by these contract fixes.
