# M6.7 — Unscored batch publication and read-only recovery

**Status:** Draft, 32 recovery tests plus 27 replay tests authored on this integration branch; NOT executed. Based on the
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
5. A retry FIRST looks for the exact expected final receipt. If present, it
   replays the existing record and all leaves before making any writes.
   A corrupt receipt, broken source link or missing leaf blocks the retry
   without rewriting anything. If fully valid, the receipt is reused and
   no leaf write is attempted. Without a receipt, byte-identical orphaned
   leaves may be reused and only after the full saved-data audit is a new
   final receipt published. No cleanup of unknown orphans or gold access.

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
  (32 synthetic/failure-injection tests authored, not run).
- Run original `test_batch_replay.py`, `test_offline_case_batch.py`,
  `test_immutable_artifacts.py` and two-case byte-backed synthetic
  integration tests on the exact branch head.
- Test failures before/after final receipt write, crash/retry, concurrent
  same-digest publication, signed external freeze, and cross-platform file
  durability as separate research/integration gates.
- Run the full repository/security CI when INCLUDED Actions allowance
  resumes. Do not enable paid billing overages or merge to main now.

## Concurrency and retry regression additions (authored, unexecuted)

Eight additional tests cover strict early refusal of corrupt/dangling
preexisting receipts, no-write reuse of a fully verified existing receipt,
corrupted or missing leaves behind a previously published receipt, parallel
publication of the same batch (only one new final receipt), a read-only
probe during the prepublication replay barrier, recovery after a simulated
exception immediately after the final receipt was published, and
coexistence of two independently sealed batches in the same storage root.
The CLI reports `existing_receipt_reused` so an already-sealed retry does not
look like a new publication. This boolean is not a guarantee of external
freeze or source authenticity.

Parallel execution and filesystem races are **not yet tested**. In particular,
correctness must be confirmed on Linux, Windows and the actual destination
filesystem before treating the implementation as reliable. An existing
corrupt digest-named receipt is never automatically repaired, replaced or
deleted; it requires an explicit manual integrity investigation.

## Replay input hardening (integration follow-up)

The verifier no longer performs a separate path type/size check followed by
`Path.read_bytes()`. It now uses the existing bounded no-follow input
reader: on POSIX every parent and leaf is opened via no-follow descriptors,
with stable file metadata and an exact 8 MiB byte bound; the Windows path
checks junctions/symlinks but still needs cross-platform race testing.
Canonical JSON, exact declared SHA-256, duplicate-key and nonfinite checks
remain in force. A preflight gate also refuses any in-memory leaf or receipt
that exceeds the REPLAY size limit before any batch writes, even though the
lower-level immutable writer can support larger unrelated artifacts.

Six additional replay tests cover leaf and parent symlinks, named pipes,
replacing a file at descriptor open, and use of the descriptor reader instead
of a racy pathname read. Two additional batch publication tests cover
oversized in-memory leaves/receipts. **32 publication tests and 27 replay
tests exist on this PR tip; all are authored and unexecuted.** The separate
parent PR #58 retains its original 19 replay tests.

### Legacy-Windows reparse roots (follow-up)

The batch replay root check now delegates to the same shared reparse-point
classifier as the input reader and atomic writer, including Windows file
attributes when the Python interpreter lacks `Path.is_junction`. An exact
batch's existing output root is refused before publishing new artifacts if
those attributes indicate a junction or other reparse point. One new replay
test and one new publication test simulate the legacy interpreter path;
**both are authored, not executed**, making 26 and 28 methods respectively.
Windows concurrent path replacement still requires live platform validation.

## Receipt preflight and replay-root race review

The replay root validator now keeps the checked **lexical absolute path**;
it does not call `Path.resolve()` after detecting symlink/reparse components.
Resolving after checking could follow a newly swapped symlink and silently
move subsequent evidence reads outside the original root. Exact leaf reads
continue to walk the checked lexical path with the bounded no-follow reader.
This does not make cross-platform filesystem replacement atomic.

The batch publisher now validates the final in-memory receipt's **exact
field schema**, its self-sealed batch ID, declared dataset identity, plan
SHA-256, unscored/independent-approval flags, and each case record's exact
field schema BEFORE writing any per-case files. An oversized receipt is also
rejected at the preflight boundary. This prevents malformed or self-resealed
premature-approval metadata from leaving new orphan leaf files before replay.

Five additional synthetic tests are authored: a no-resolve replay-root
regression and four malformed/forged-receipt preflight refusals. The exact
head therefore has 32 batch-publication tests and 27 replay tests,
**59 authored but NOT EXECUTED**. Previously recorded research gates remain
open. No gold access, original publisher authentication or trusted external
freeze is claimed by these integrity checks.
