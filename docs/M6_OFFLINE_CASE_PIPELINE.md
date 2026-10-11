# M6.3 — Offline source-to-paired-profile case orchestration

**Status:** Engineering-only draft; 16 authored synthetic/adversarial tests NOT executed. Zero approved real cases or empirical results. Depends on draft PRs #52 and #53.

## Boundary

The command at scripts/run_offline_case_pipeline.py builds one *unscored*
case using existing source/case manifests, exact local archive bytes,
source-assertion JSONL, declared semantic reviews, separate as-of feature
lineage, and the established M3 graph/B0/G1 paired-run validators.

The coordinator does NOT import, read or accept held-out reference-label
files. It does NOT call the M6.2 scorer. Reference partitions must be opened
only in a later independent scoring process after predictor artifacts are
frozen and independently inspected.

The chain reuses source/case validation, archive-byte integrity, evidence-
locator alignment, semantic review/allowlist checks, exact B0/G1 early-input
parity, source-bound as-of feature lineage and the paired run lock. It does
not automatically manufacture trusted feature-lineage declarations from
already processed graph records.

## Additional input safety

The coordinator requires actual local SHA-256 parity with the metadata
declarations for the source manifest, case manifest, review JSONL and
dependency-lock file. It refuses duplicate claim/review JSON keys, fields
such as gold_labels or future_answer inserted into assertions, nonfinite
JSONL values, oversize/symlink input files and more review records than
source claims.

The metadata's source/case hashes follow the canonical JSON fingerprint
contract. Review and dependency hashes are computed from exact local file
bytes. Git commit, ontology/extractor/ruleset metadata still represent
caller declarations, not independent authentication. Matching local
archive bytes is not proof of original publisher authorship or public date.

## Usage

Run the following as one line from the local repository root:

    python -m scripts.run_offline_case_pipeline --sources datasets/manifests/pilot.json --cases datasets/cases/pilot.json --case-id REVIEWED-CASE-ID --claims artifacts/private/source-claims.jsonl --archive-root artifacts/source_versions/sha256 --reviews artifacts/private/semantic-reviews.jsonl --feature-lineage artifacts/private/reviewed-asof-lineage.json --metadata artifacts/private/pinned-run-metadata.json --g1-config artifacts/private/g1-config.json --dependency-lock artifacts/private/dependency-lock.txt

The default produces a nonwriting preview of canonical artifact hashes,
case ID and run ID. Add --write to persist nine individually content-
addressed, exclusive-create JSON files in artifacts/offline_case_pipeline:

- b0_view and g1_view
- b0_graph and g1_graph
- b0_profile and g1_profile
- paired_audit and run_lock
- pipeline_receipt

A write retry can reuse exact same-byte artifacts; a different existing
artifact is rejected. The output group is not atomic, so some complete
files can remain after a later write failure. No raw article bodies or
outcome labels are emitted in output artifacts.

The pipeline receipt explicitly declares heldout_labels_opened=false,
empirical_evaluation=not_performed, and research_ready=false.
Development mode (--development-only) relaxes pilot count thresholds for
synthetic cases only; it does not grant scientific approval.

Later candidate scoring must be invoked separately with the frozen output
paths using scripts/evaluate_frozen_paired_run.py. The read order and
self-hashes are not independently authenticated freeze timestamps.

## Deferred work

- Run this branch's 16 tests and the whole repository suite locally, then
  cross-OS CI after the GitHub Actions allowance becomes usable again.
- Independently approve publisher source dates and rights, typed identities,
  exact original citation semantics, reviewer authenticity and lineage.
- Authenticate a true pre-outcome freeze and gold isolation across processes.
- Only then run valid multi-case B0/G1 evaluations and report real results.

This is partial FR-28/29 engineering, not a finished scientific experiment.
