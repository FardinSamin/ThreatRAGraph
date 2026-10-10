# M3 Foundation — Historical Source Snapshot Contracts

**Status:** Deterministic source-level preview and snapshot writer implemented. **No real historical cases or scientific snapshots generated yet.**  
**Tracking:** [Issue #7](https://github.com/FardinSamin/ThreatRAGraph/issues/7)  
**Research basis:** [SRS](SRS.md) RC-05–06, FR-19–21, EV-08 and [SDD](SDD.md) ``7–9.

## 1. Why separate historical snapshots matter

The primary comparison is:

- **B0 (cold start):** Only the first one or two permitted early reports about the target.
- **G1 (graph-assisted):** The **same early sources as B0** plus pre-cutoff public historical background source versions.

The reference material published **after** the cutoff must not be loaded, listed or otherwise provided to either profiler. The evaluation runner may access it later, once predictions are frozen, but it belongs to a separate trust boundary.

The initial M1 validator checks declared chronological partition metadata. The M3 foundation packages the permitted versions into **deterministic, content-addressed source-level input views** to minimize accidental reference leakage in subsequent extraction/graph work.

## 2. Run a safe, no-write preview

From the repository root:

~~~powershell
python -m scripts.freeze_case_snapshots datasets/manifests/pilot.json datasets/cases/pilot.json
~~~

The current **17-candidate, zero-approved, zero-case** registries will yield **no_cases_yet**, not an experimental result. The command reports preview counts and future snapshot content digests for valid synthetic or later approved cases; it does not write source data, use cloud services, download reports or require API keys.

## 3. Research-ready artifact generation

Only after the research corpus genuinely contains **25–40 approved immutable source versions**, **4–6 documented historical cases**, and locally available archives matching their recorded SHA-256:

~~~powershell
python -m scripts.freeze_case_snapshots datasets/manifests/pilot.json datasets/cases/pilot.json --write
~~~

The `--write` mode gates on:
1. The existing strict metadata validator (including case chronology, partition disjointness and exact-content mirror checks);
2. The existing offline audit of **all approved archived source bytes** (`--require-all` behavior);
3. A nonempty valid case registry.

If any check fails, **no profiler-facing snapshot files are written**. Output is under ignored `artifacts/snapshots/` by default. Each JSON artifact filename is the SHA-256 of its canonical, sorted-key, UTF-8 JSON bytes (with a final newline), so rerunning the same inputs is idempotent. Existing differently populated files under the same content address are rejected rather than overwritten.

The creation of files still **does not prove that publication-date evidence is genuine or that the full research is ready**. Researchers must independently inspect reported date evidence and archive provenance.

## 4. Artifact schema

Each B0/G1 view contains:

| Field | Meaning |
|---|---|
| schema_version | Source-view contract version |
| artifact_kind | `historical_source_input` |
| dataset_id, dataset_version | Versioned corpus |
| case_id | Stable case identifier |
| target_entity_id | Target chosen under research protocol |
| cutoff_at | Documented historical UTC cutoff |
| method | `B0_sparse_report_only` or `G1_early_plus_historical_background` |
| sources[] | Permitted version IDs, sha256, `available_at`, independence group and role |
| scope_warning | Explicit boundary/limitations of metadata-level gating |

The B0 `sources[]` array contains **only** early versions. G1 starts with the **same** early versions, then adds background versions ordered deterministically by ID. A held-out later source must never appear even by ID inside the profiler-facing artifact. It contains no reference labels and no outcome metrics.

The snapshot hash protects against accidental changes and gives repeatable identity. It does **not** cryptographically prove earlier publication time.

## 5. Boundaries that still require implementation and audit

This is **source-level** time gating. Before claiming a valid early-threat graph experiment, we must ALSO:
- reconstruct extracted claims, graph edges, aliases and merge decisions **as of the cutoff** rather than reuse a modern built graph;
- use historically available ATT&CK/STIX, Falco rules and other taxonomies or disclose controlled constant ontology;
- ensure any semantic search index or embeddings do not contain or indirectly depend on later case documents;
- isolate outcome/reference labels and later reports in the evaluation process;
- address pretrained language-model contamination: old prompts are **not** proof the model never learned later information;
- document report copying/syndication beyond exact byte-identical mirrored files;
- review historical date source evidence manually and record which source versions were actually available before the cutoff.

Do **not** call these snapshot manifests a live GraphRAG inference engine, full historical graph or proven research result.

## 6. Testing and reproducibility

The standard-library tests cover B0 and G1 source separation, omission of later reference IDs, source chronology rejection, stable digests despite registry ordering, file tampering, symlinked output roots, idempotence, and the write-readiness gate.

~~~powershell
python -m unittest discover -s tests -v
~~~

The GitHub Actions workflow exercises a **no-write preview** against the current draft registry. A valid empty candidate registry is expected and must not be mistaken for a completed experiment.
