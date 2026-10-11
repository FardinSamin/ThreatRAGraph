# M6.4 — Offline multi-case batch coordinator

**Status:** Draft engineering build with 20 authored (not executed) synthetic
and adversarial tests. Depends on unfinished PR #56, #53 and #52. No real
source or historical case has been scientifically approved or scored.

## Purpose and isolation

The new scripts/run_offline_case_batch.py handles one to 100 independently
named cases using the existing archive-backed single-case coordinator. It
does not accept held-out source labels, inspect later reference partitions,
import the evaluator, tune G1 against outcomes, or claim empirical results.

A strict batch plan specifies the case ID, sourced claim JSONL, separate
review JSONL, independently supplied as-of feature-lineage JSON, metadata JSON
and G1 config JSON. All cases share the declared dataset version, source/case
manifests, archive root and pinned dependency-lock file.

The plan is exact-field, case IDs unique and sorted, and every case must
exist in the case manifest. Per-case claims, reviews, lineage and provenance
file paths must not be reused between cases. Files must be bounded relative
JSON/JSONL paths confined under --input-root with no symlink components.
All input files are preflighted BEFORE processing even the first case.

## Example plan

{
  "schema_version": "1.0",
  "artifact_kind": "unscored-multicase-batch-v1",
  "dataset_id": "synthetic",
  "dataset_version": "v1",
  "cases": [
    {
      "case_id": "case-a",
      "claims_jsonl": "case-a/claims.jsonl",
      "reviews_jsonl": "case-a/reviews.jsonl",
      "feature_lineage_json": "case-a/lineage.json",
      "metadata_json": "case-a/metadata.json",
      "g1_config_json": "common/config.json"
    }
  ]
}

Extra unknown keys, paths outside the input root, future/gold label fields,
duplicate cases and noncanonical ordering are refused.

## Running the command

From the repository root:

    python -m scripts.run_offline_case_batch --plan artifacts/private/batch-plan.json --sources datasets/manifests/pilot.json --cases datasets/cases/pilot.json --input-root artifacts/private --archive-root artifacts/source_versions/sha256 --dependency-lock artifacts/private/dependencies.lock --development-only

Default mode only previews immutable artifact SHA-256 digests, case IDs, and
the batch ID. The per-case receipt refuses feature-lineage digests that do not match the exact input stored in the run lock, so claims cannot be replayed with a different lineage file. --write persists ten individually content-addressed artifacts
per case, including an exact feature_lineage JSON record, plus one final batch receipt in artifacts/offline_case_batches.

Every case is computed completely in memory BEFORE any output write, so
failure of a later case cannot leave newly written outputs. On --write, the
updated publication gate first validates all in-memory content against the
sealed case inventory; then it writes or reuses ten immutable files per case.
It rereads and independently recomputes B0 and G1 from ALL stored leaves
before publishing the final batch receipt. It then rereads the published
receipt and repeats the full structural replay check before reporting success.
An I/O error can still leave complete reusable hash-addressed leaves because
the multi-file operation is not atomic; those leaves **cannot** imply a
committed batch without an exact persisted and verified final receipt.

Run this read-only completion probe with the exact digest returned by preview:

    python -m scripts.check_batch_completion --artifact-root artifacts/offline_case_batches --batch-receipt-sha256 YOUR_PREVIEW_RECEIPT_SHA256

The response is `uncommitted` (nonzero exit) if the final digest-named
receipt is absent. Corrupted receipts, missing leaves, tampered hashes and
profile mismatches are refused (nonzero exit). The only zero-exit state is
`sealed_unscored_batch_verified` with research_ready=false, and is **not**
an empirically completed experiment or approved historical case. A retry
reuses exact previously written leaves after confirming they match and
attempts the receipt gate again; it does not delete orphan stages or
partially written earlier batch outputs.

The canonical batch receipt contains no raw source or label text or private
paths, only case IDs, case/pipeline/run/profile/audit IDs, G1 novel prediction
and abstention counts, exact artifact hashes, plan hash and explicit
research_ready=false, empirical_evaluation=not_performed, and
later_reference_labels_accessed=false.

## What this does not establish

The source manifest, published-at times, reviewer IDs, research approval,
source rights, code provenance and source-independent study cutoff remain
claims requiring outside proof. A self-hash is not a third-party signature.
The separate evaluator in PR #53 may only be run AFTER the predictions have
been properly frozen and future-label access independently controlled.
This batch step does not compute metrics or certify a real study.

## Deferred validation

- Execute tests/test_offline_case_batch.py (20 authored tests) and the
  existing single-case, profiler and isolation suites locally.
- Extend real end-to-end integration fixtures to two different synthetic
  cases, test deterministic preview/write byte parity and disk failures.
- Verify Linux/Windows CI at the exact branch head when runners return,
  without authorizing paid GitHub Actions overages.
- Obtain independently approved 4–6 real cases, source rights, authenticity
  and reviewed held-out labels before any empirical result is reported.

FR-27, FR-28 and FR-29 remain PARTIAL, DRAFT and UNVERIFIED.

### Retrying a previously published receipt

When the expected digest-named batch receipt already exists, `--write`
first replays that receipt and its full artifact inventory. If valid, it
returns `existing_receipt_reused=true` without writing any new files.
If the receipt or one of its leaves has been damaged, it fails before
starting new writes; it never silently repairs an already published batch.
If the receipt is absent, an interrupted run may safely reuse exact orphaned
leaves and publish the receipt only after the full saved B0/G1 replay.
The preview always reports `existing_receipt_reused=false` and remains
read-only. This does not imply an authenticated external or pre-gold freeze.
