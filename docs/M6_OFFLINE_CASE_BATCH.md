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
failure of a later case cannot leave newly written outputs. Writes themselves
are exclusive-create but not an atomic group transaction; an I/O failure
partway through can leave earlier complete, reusable hash-addressed files.

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
