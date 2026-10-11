# M6.5 — Offline integrity replay of frozen unscored multi-case batches

**Status:** Engineering-only draft. Fifteen synthetic/adversarial unit tests
authored, not yet executed. Depends on unmerged PR #57 (and #56/#53/#52).
No actual historical case has been evaluated and research_ready remains false.

## Goal

The batch runner from PR #57 can write nine individual hash-addressed
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
- Require 1–100 sorted unique cases, exact nine-artifact inventories,
  canonical batch and pipeline IDs, unique run IDs, honest status flags
  and consistent source dataset/version and case/cutoff IDs.
- Recheck both source-view/graph contracts and aligned claim status;
  identical early B0 and G1 source metadata/claims; no target-specific
  background evidence; no common early/background independence group.
- Regenerate the B0/G1 paired-output audit and verify both profiles match
  their frozen source-view SHA-256 digests and the source-bound run lock.
- Verify run-lock schema, declared provenance syntax, exact five input
  hashes, G1 exact-only feature-lineage report digest/flags, B0/G1 profile
  hashes, algorithm settings, observed/predicted counts and no-label flags.
- Deterministically regenerate the saved B0 baseline directly from the
  stored early view/graph and exact development flag; refuse inconsistent
  observed facts even when every digest and run ID has been recomputed.
- Bind G1 proposed-relation and matching-feature source paths to *exact*
  eligible, supported, positive, byte-aligned claims in the persisted early
  and background graphs. Reject forged witnesses and unsupported publisher
  groups. G1 similarity ranking is NOT recomputed without original lineage.
- Verify the pipeline receipt's source/case/review/dependency declared hashes,
  graph SHA-256, run/audit/profile IDs, raw claim/review counts and research
  limitations; bind every result back to the per-case batch record.

## Important scientific limitations

B0 recomputation and G1 citation-to-graph checks add genuine structural
verification, but do **not** authenticate source truth or recompute the full
G1 similarity ranking. The output exposes separate flags for those checks.
Tests for rehashed fabricated B0 facts and false G1 support paths are authored
but remain unexecuted.

The original feature-lineage file, source manifests, archival source bodies,
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

- Author-only test coverage: 15 methods, including two real synthetic paired
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
