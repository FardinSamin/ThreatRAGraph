# M6.7 — Unscored batch publication and read-only recovery

**Status:** Draft, 17 new tests authored but NOT executed. Based on the
unmerged consolidated integration PR #61. No research case is approved, no
gold labels are used, and no tests or real experiments have been verified.

## Problem

The old batch runner wrote ten digest-named artifacts per case, then wrote
a digest-named batch receipt. Every individual file was content addressed,
but the runner did not reconstruct the SAVED B0/G1 outputs before making
the final receipt visible. If a later file write failed, leaves remained
and could be mistaken by a manual operator for a complete batch.

## New fail-closed publication gate

1. Compute all requested cases and their sealed receipt in memory, before
   writing any file. Compare each of the ten artifacts per case with its
   declared receipt digest; reject missing, extra, reordered or inconsistent
   inventories before making an output directory.
2. Write or reuse individually stage/fsync/no-replace immutable JSON files.
   A later failure can leave previously committed complete leaves, but NO
   NEW final receipt.
3. Reopen each stored leaf under its hash-only filename, validate its exact
   canonical SHA-256 and structural graph/source/lineage contracts, and
   deterministically reconstruct B0/G1 profiles using the frozen lineage.
   This reuses the existing no-gold structural replay verifier. A failure
   here is **not** allowed to publish the final receipt.
4. Only once all stored leaves pass, write the batch receipt as the final
   immutable JSON file. Reopen that exact digest-named receipt and perform
   the full structural replay again before reporting unscored success.
5. A byte-identical retry reuses existing leaves and any already valid
   receipt. Corrupt or missing leaves fail closed. No cleanup of unknown
   orphans, no mutation of existing digest files and no gold access.

## Completion probe

Use the exact 64-digit SHA-256 digest printed by the default batch PREVIEW,
not the shorter `batch:...` logical ID:

    python -m scripts.check_batch_completion --artifact-root artifacts/offline_case_batches --batch-receipt-sha256 ACTUAL_PREVIEW_DIGEST

The probe is READ ONLY and never guesses based on an output directory scan.

- `uncommitted`, exit 2: directory or exact final receipt is absent.
  Previously stored individual artifacts are NOT proof of completion.
- `unscored_batch_completion_refused`, exit 2: a receipt/file exists but
  cannot be safely verified, or its digest and saved artifacts disagree.
- `sealed_unscored_batch_verified`, exit 0: exact canonical receipt,
  ten per-case leaves, cross-case binding, B0/G1 reconstruction and
  stored run/profile/graph linkage pass the structural audit.

Even a successful probe **does not** mean `research_ready=true` or an
empirically complete experiment. It does NOT reread original publisher
archives, authenticate source rights or chronology, independently review
semantics, confirm prediction freeze timing, or open later gold labels.

## Important limitations

Multi-file publication is not atomic. An interrupted attempt may leave
complete individually hash-addressed artifacts or private stale
.stage-*.partial files. Their existence does not change probe status.
Do not delete artifacts automatically or infer success from file counts.
Hardlink/filesystem durability semantics require Linux and Windows tests,
and concurrent external filesystem replacement remains outside the
historical research threat model unless independently secured.

The final receipt is a SELF-hashed engineering object, not an external
signed commitment or third-party witnessed pre-label freeze. An adversary
who controls all stored data can still replace all self-hashes.

## Deferred gates

- Execute `python -m unittest discover -s tests -p 'test_batch_publication.py' -v`
  (17 synthetic/failure-injection tests authored, not run).
- Run original `test_batch_replay.py`, `test_offline_case_batch.py`,
  `test_immutable_artifacts.py` and two-case byte-backed synthetic
  integration tests on the exact branch head.
- Test failures before/after final receipt write, crash/retry, concurrent
  same-digest publication, signed external freeze, and cross-platform file
  durability as separate research/integration gates.
- Run the full repository/security CI when INCLUDED Actions allowance
  resumes. Do not enable paid billing overages or merge to main now.
