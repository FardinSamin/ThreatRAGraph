# Isolated storage-component validation — 2026-10-11

**Scope:** Linux 6.18.44 x86_64, Python 3.13.5, local temporary filesystem.
This is focused *executed* validation, not a full repository checkout,
native Windows run, historical-source audit, or GitHub Actions result.

The container could not resolve github.com. Exact UTF-8 source and test
content was obtained through the authorized GitHub repository connection,
then locally reconstructed. Both tested source modules and both test files
were verified against their exact Git blob SHA-1 identifiers:

| File | Blob hash |
|---|---|
| `src/threatragraph/local_file_inputs.py` | `8765968040c293092321f2d158bff8b3e0cb917e` |
| `tests/test_local_file_inputs.py` | `8a7d8e80a7a073b6261ab1c62acfc01acf605d94` |
| `src/threatragraph/immutable_artifacts.py` (after repair) | `41f4df7e3136df406e195b29f67fdd726b3f6704` |
| `tests/test_immutable_artifacts.py` | `79b8f76acb12917b9fa8d22566ba756d7e2f38a2` |

The storage tests require two thin wrappers imported from scripts.
The isolated environment reproduced the actual implementation bodies of
`canonical_bytes`, `snapshot_sha256`, `write_immutable_view` and
`_write_csv`, but it did NOT import the full scripts with the full project
dependency graph. The storage modules themselves and their entire authored
test files were byte-identical to the noted Git revisions.

## Execution and identified defect

- Initially: 18/18 local input-reader tests passed; 17/18 immutable-writer
  tests passed and one errored.
- **Observed failure:** `test_rejects_nonregular_digest_directory` got
  `IsADirectoryError` while `os.fdopen(fd, "rb")` attempted to wrap an
  O_RDONLY directory fd. The test and contract expect fail-closed
  `ValueError("Destination is not an exact standalone artifact")`.
- **Repair:** immediately after opening the destination, inspect
  `os.fstat(fd).st_mode`, close the fd and raise the expected `ValueError`
  for a nonregular object, before `os.fdopen`.
- **After repair:** 36 tests passed, 0 failed, 0 errors, 0 skipped,
  using `python -m unittest discover` over the two exact test files in
  the isolated Python test tree.
- Additional local Linux stress: 40 rounds of 4 concurrent writers,
  fresh directory per round, **40/40 rounds succeeded** with exactly one
  newly created digest-named artifact and matching final contents.

## Limitations and remaining gates

The results validate two components on **one Linux runtime** and a
local test filesystem only. They do NOT validate the actual batch pipeline,
G1 recomputation, dependency locking, archived source provenance, network
filesystems, crash/power-loss durability, Windows junction races, the
full import tree or end-to-end CLI behavior. No held-out labels were
accessed, no real case was approved, and `research_ready` remains false.

No paid Actions minutes were used; the existing GitHub workflow failures
still show jobs without assigned runners or executed steps. Keep all PRs
draft until full suites and research gates are independently verified.
