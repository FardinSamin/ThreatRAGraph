# P0.3 — Versioned artifact contracts and SQLite compatibility

**State:** Synthetic-tested v1 source-view/graph validation and **fail-closed** persisted SQLite schema inspection. This is a bounded hardening milestone, not a production-grade schema registry or completed data migration suite.

**Tracking:** [P0 Issue #23](https://github.com/FardinSamin/ThreatRAGraph/issues/23). SRS FR-11–17, FR-19, FR-21, DR-07, DR-09–11 and [build gates](BUILD_PLAN.md).

## Why

Earlier graph code could reopen a SQLite file and issue `CREATE TABLE IF NOT EXISTS sourced_claims` even if a legacy table **lacked the new `evidence_status` column**. This creates a confusing failure later when data is written and must never be treated as evidence that older unverified citations are now verified.

Our source view and graph outputs were versioned, but the contracts were not consistently validated across graph projection, the reviewed-graph runner and the standalone B0 consumer. Unsupported metadata or future labels should fail at the interface boundary.

## Implemented contracts

`src/threatragraph/contracts.py` validates **v1**:
- `historical_source_input`: exactly the documented common source-view keys, allowed B0/G1 method, 1–2 early source versions, permitted roles, no future `available_at`, full SHA-256 strings, unique source version IDs, bounded and typed metadata. No later-reference fields may be smuggled into the view.
- `historical_sourced_graph`: version, case, method, cutoff and source-view SHA-256 fingerprint match the original view. It rejects extra fields such as outcome labels, non-eligible source claims, malformed source assertion types, invalid locators/evidence digests, duplicate claim IDs, unexpected review status and graph nodes absent from the attributed edges.
- **Reviewed edge mode** explicitly distinguishes a graph projection from the post-review projection that contains `semantic_review_status`. A raw graph carrying untrusted reviewer annotations is not silently accepted in core graph mode.

The existing M1 manifest, M2 claim and reviewer, and M4 B0 validators still enforce their own fields. This new shared contract is invoked at `EvidenceGraph.project()`, `scripts.project_case_graph.run()` and `baseline_b0.build_b0_profile()`; it **does not replace archive-byte checks, source-publication evidence or semantic adjudication**.

## SQLite compatibility and migration policy

`src/threatragraph/sqlite_schema.py` checks pre-existing `source_versions` and `sourced_claims` against v1 column names, order, declared SQLite types and primary-key/nullability metadata **before** running `CREATE TABLE IF NOT EXISTS`. Semantic-review storage receives the equivalent inspection before first use.

- A newly created ledger is stamped `PRAGMA user_version = 1`.
- An existing **valid legacy unversioned** ledger with the same v1 columns may be opened and stamped after successful inspection.
- An older ledger **missing `evidence_status`**, future `user_version`, missing core table, changed review schema or other incompatible structure is **rejected**, not silently rebuilt or rewritten.
- The optional `semantic_reviews` table may be initialized on first use in an otherwise complete v1 ledger.
- Existing claim evidence hashes and statuses are **never upgraded** from `unverified` to `aligned` by schema checks.

**Migration safety:** There is intentionally **no automatic migration for incompatible persisted ledgers**. Keep a protected backup of any old file; re-ingest original approved source versions, archived bytes, immutable claims and reviewer decisions through the current audited pipeline into a **new file**, or design a separately reviewed and tested explicit migration. Do not add missing columns and default them to `aligned`. The SQLite schema check is structural; it does **not** independently verify every index, trigger, foreign-key enforcement setting or all SQL constraints. Hardening those is still pending.

## Reproducing checks

~~~powershell
python -m pip install --no-deps -r requirements-normalization.txt
python -m unittest discover -s tests -v
python -m scripts.project_case_graph --help
python -m scripts.profile_b0 --help
~~~

The synthetic tests verify valid B0/G1 v1 shapes, unknown future fields, held-out source injection, graph/view hash drift, unsupported schema versions, invalid evidence/review states, ordinary reopen/idempotence of a persisted SQLite file, refusal of **missing evidence_status** and incompatible review structures, and rejection without destructive mutation.

## Deliberate remaining P0/P1–P5 limits

- The present contract parser is hand-coded and covers only the **implemented B0/G1 source-view and attributed graph interfaces**, not all original M1 registry forms, future G1 predictions, frozen run/label manifests or export versions.
- SQLite checks validate column metadata but not every index/constraint/trigger definition, so hostile database files require stronger inspection and isolated processing.
- Hashes in an input view do **not** independently verify the original source bytes, publisher chronology or case rights. That obligation remains with source-archive integrity and **human** research approval.
- The B0 test fixture can use **synthetic** claim IDs; this contract checks ID *syntax and uniqueness*, not whether an arbitrary external JSON edge was authentically produced by a ledger. A real production run must bind data to the verified claim ledger and a frozen artifact signature or trusted file provenance.
- G1 inference, frozen future-label evaluator, alias/taxonomy-as-of reconstruction, branch protections and full dependency hashes remain outside this PR.
- All components still disclose `research_ready=false`; no empirical claims are generated by these schema checks.

**Next:** Continue P0 [Issue #23](https://github.com/FardinSamin/ThreatRAGraph/issues/23) with independent contract signatures/fingerprints for exported artifacts, SQLite index/constraint verification, explicit upgrade policy, and repository branch protections as authorized. In parallel, begin [P1a one authentic case](https://github.com/FardinSamin/ThreatRAGraph/issues/24); don't prolong synthetic-only engineering.
