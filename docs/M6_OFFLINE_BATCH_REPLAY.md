# M6.5 — Offline integrity replay of frozen unscored multi-case batches

**Status:** Engineering-only draft. Nineteen synthetic/adversarial unit tests
authored, not yet executed. Depends on unmerged PR #57 (and #56/#53/#52).
No actual historical case has been evaluated and research_ready remains false.

## Goal

The batch runner from PR #57 can write ten individual hash-addressed
JSON artifacts for each case plus one batch receipt. This verifier RELOADS
those files and independently checks structural consistency. It DOES NOT
re-execute extractors, authenticate original publisher bytes or date evidence,
or score B0/G1 against held-out outcomes. The term "replay" here means
persistence/integrity replay, not independent source acquisition/recomputation.

## Command

From the repo root:

    python -m scripts.verify_offline_batch_replay --artifact-root artifacts/offline_case_batches --batch-receipt-sha256 YOUR_64_CHARACTER_BATCH_RECEIPT_DIGEST

Use the batch_receipt.sha256 returned by the --write mode of
scripts/run_offline_case_batch.py, not the symbolic batch_id prefixed
with batch:. A successful result is a descriptive structural-integrity
receipt, not a scientific evaluation. This command is read-only and never
opens raw reports, source archives or future reference labels.

## Exact checks

- Refuse symlinked artifact roots and path components, missing/empty/oversize
  JSON files, noncanonical JSON bytes, duplicate object fields, NaN/Inf,
  modified SHA-256 content, and unknown receipt/lock keys.
- Load each required artifact ONLY from its 64-character SHA-256 filename
  beneath the specified artifact root; never interpolate case names or
  user-supplied absolute paths into read locations.
- Require 1–100 sorted unique cases, exact ten-artifact inventories,
  canonical batch and pipeline IDs, unique run IDs, honest status flags
  and consistent source dataset/version and case/cutoff IDs.
- Recheck both source-view/graph contracts and aligned claim status;
  identical early B0 and G1 source metadata/claims; no target-specific
  background evidence; no common early/background independence group.
- Regenerate the B0/G1 paired-output audit and verify both profiles match
  their frozen source-view SHA-256 digests and the source-bound run lock.
- Verify run-lock schema, declared provenance syntax, exact five input
  hashes, stored G1 exact-only feature-lineage object and digest/flags, B0/G1 profile
  hashes, algorithm settings, observed/predicted counts and no-label flags.
- Deterministically regenerate the saved B0 baseline directly from the
  stored early view/graph and exact development flag; refuse inconsistent
  observed facts even when every digest and run ID has been recomputed.
- Bind G1 proposed-relation and matching-feature source paths to *exact*
  eligible, supported, positive, byte-aligned claims in the persisted early
  and background graphs. Reject forged witnesses and unsupported publisher
  groups. The now-persisted canonical feature lineage is reloaded and
  checked against the run lock; the deterministic G1 builder is rerun
  against frozen source views, early/background evidence graphs, the exact
  lineage artifact, and the stored configuration. Full G1 predictions,
  rankings, abstentions and diagnostics must agree byte-for-byte at the
  canonical object level with the stored profile.
- Verify the pipeline receipt's source/case/review/dependency declared hashes,
  graph SHA-256, run/audit/profile IDs, raw claim/review counts and research
  limitations; bind every result back to the per-case batch record.

## Important scientific limitations

B0 and G1 are now both deterministically recomputed from stored views,
graphs, the exact persisted as-of lineage and run configuration. The output
exposes separate true flags for G1 recomputation and the reloaded lineage
artifact; it explicitly reports that the original researcher-supplied input
path and original publisher archives are not reread. This adds stronger
within-artifact consistency checks but remains neither source authentication
nor an independent new extraction run. Adversarial replay tests are authored
but remain unexecuted.

The original researcher-supplied feature-lineage INPUT FILE (distinct from the canonical lineage artifact), source manifests, archival source bodies,
reviews, dependency bytes and batch-plan file are NOT reread by this
verifier. It tests only that existing metadata declarations and saved
artifacts agree with each other. It does not independently prove that those
declarations were truthful. A malicious actor who replaces a COMPLETE
untrusted collection and recomputes every self-hash cannot be detected
without an independently trusted published digest/signature.

A legitimate, successful structural audit does NOT validate source dates,
publication rights, the factual support for a relation, historical alias
knowledge, researcher identity, original source integrity, a third-party
pre-gold freeze or predictive usefulness. The receipt explicitly states
these unresolved conditions and never claims research approval.

All source rights, reviewer independence, full source/feature provenance,
actual historical case acceptance, and future label isolation require
separate independent review before legitimate empirical evaluation.

## Test and integration gates

- Author-only test coverage: 19 methods, including two real synthetic paired
  profiler outputs, byte-stable readback, tampered canonical/sha hashes,
  missing files, symlinks, label smuggling, cross-case substitution and
  malformed JSON. **Tests have not been executed.**
- Run locally when the deferred validation phase begins, including the parent
  M6 unit suites and integration tests. Run full cross-platform CI once
  GitHub Actions minutes/runners return, without enabling paid overages.
- Optional future work: external signed content-commitment ledger and
  independent complete-source re-execution for strong reproducibility.
- The existing batch writer is exclusive-create PER FILE, not a transactional
  all-or-nothing directory snapshot. Replay refuses incomplete output sets.

FR-29 reproducibility remains **partial/draft**; this module adds structural
persistence checks, not independent reproducibility certification.

## Later integration hardening on dependent PR #62

The dependent publication/recovery branch replaces separate artifact
`is_symlink()/stat()/read_bytes()` checks with a bounded, regular-file,
no-follow descriptor reader. All source artifact ancestors and the leaf
are opened without following symlinks on POSIX; Windows junction checks
are best effort and require actual platform tests. The verifier still
checks exact declared SHA-256 and canonical JSON bytes. Six new tests in
PR #62 extend the 19-test replay suite to **25 authored but unexecuted**
methods, including a simulated path replacement at the moment of open.
PR #58 itself remains unchanged until explicitly integrated. Neither
version is scientific or historical-source authentication.

### Legacy Windows filesystem verification (dependent draft PR #62)

The dependent integration branch also rejects Windows reparse metadata
without depending on the newer `Path.is_junction` method. The replay
suite on that branch has **26 authored, unexecuted** tests (the parent PR
#58 remains at 19), including a synthetic missing-junction-method case.
This is best-effort local filesystem hygiene, not an OS-wide sandbox.

## Dependent PR #62: preserve lexical root after no-follow checks

The integration branch now intentionally returns the checked lexical
absolute path from `_root_directory` instead of resolving it a second
time. A new test refuses a late `Path.resolve` call. Each opened artifact
continues to be checked with no-follow descriptor traversal. The dependent
branch holds **27 authored replay tests, unexecuted**; original PR #58
remains unchanged. Windows concurrent replacement remains a manual gate.
