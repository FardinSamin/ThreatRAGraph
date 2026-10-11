# Safe content-addressed output files (engineering draft)

**Status:** Draft implementation; 16 authored, unexecuted unit/fault-injection
tests. No CI runner has completed this branch's tests. Applies to canonical
JSON snapshots (including M6 case/batch artifacts) and portable CSV exports.

## Publishing contract

1. Encode the exact intended bytes and calculate SHA-256.
2. Reject unknown extensions and unbounded output bytes.
3. Create/traverse the output directory without following symlinks
   (POSIX: descriptor-relative directories; Windows: best-effort symlink
   and junction checks with a remaining directory-replacement race).
4. Reuse an existing digest-named file only if it is a standalone regular
   file with exact expected length and bytes. Refuse symlinked, directory,
   persistently hardlinked and byte-inconsistent destinations.
5. For new outputs, create a randomized same-directory
   .stage-*.partial file with exclusive creation and restrictive mode.
6. Write the complete data, flush and fsync it. Then atomically publish
   the final digest filename through a hard link that refuses replacement.
7. Remove the private stage name and fsync the directory where supported.
   If another writer already committed identical content, reuse that file
   after byte verification. Reject any conflicting file.
8. On normal exceptions, clean up temporary stage names. A power failure
   or abrupt process termination can leave orphaned .stage-*.partial files;
   they are never recognized as content-addressed artifacts and this
   module intentionally does not delete unknown old stages.

## Remaining limitations

This change does NOT make JSON+CSV or 10-per-case batch sets atomic.
If a process stops after committing some valid artifact files, they remain
present. A new batch receipt is emitted only after all cases' individual
file writes succeed. Retry is idempotent for complete identical files,
but a caller must never infer a complete batch merely from some filenames.

A hardlink-based no-replace publish requires a filesystem with hardlink
support. A filesystem that cannot support the required primitive is
rejected, not silently downgraded to unsafe direct final-file writes.
Cross-volume remote/network filesystems are not independently certified.
Directory fsync and host filesystem durability are not a universal
power-loss guarantee. Content hashing is not third-party provenance or
a trusted timestamp.

This change was authored via GitHub but has not been tested. Deferred tests:
test_immutable_artifacts.py (16 methods), test_freeze_case_snapshots.py,
test_portable_exchange.py, test_offline_case_pipeline.py,
test_offline_case_batch.py, test_batch_replay.py, full security checks,
and Windows/Linux filesystem-specific CI when allowed. No paid overages,
external historical source fetch or gold-label access was authorized.
