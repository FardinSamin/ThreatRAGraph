# ThreatRAGraph

**ThreatRAGraph** is a GraphRAG-based cyber threat intelligence research project investigating whether graph-structural similarity to historically documented threats can improve provisional profiles for newly emerging threats when only one or two early public reports exist.

## Status

**Architecture approved for planning; implementation unverified.** The investigator's URFS proposal describes an existing local Python extraction and graph-building prototype, but that original code has **not been imported or audited here**. At present, this repository contains architecture documents and preparation tools, not a demonstrated end-to-end research system.

## Documents

- [SRS](docs/SRS.md) — software requirements, research hypotheses, functional and nonfunctional criteria, acceptance gates.
- [SDD](docs/SDD.md) — proposed architecture, claim/evidence graph schema, time-safe snapshots, similarity engine, baseline, evaluation, deployment options.
- [M0 prototype intake](docs/M0_PROTOTYPE_INTAKE.md) — safe procedure for bringing the existing prototype into the repository and auditing it.
- [M1 corpus protocol](docs/M1_CORPUS_PROTOCOL.md) — source-version metadata, historical case partitions and cutoff validation.
- [M1 source byte-integrity audit](docs/M1_SOURCE_INTEGRITY.md) — locally verify SHA-256 of frozen CTI source versions while keeping archives out of Git.
- [M3 historical snapshot contract](docs/M3_HISTORICAL_SNAPSHOTS.md) — deterministic B0/G1 source inputs that exclude held-out later references.
- [M2 sourced evidence graph](docs/M2_EVIDENCE_GRAPH.md) — reference SQLite claim ledger, typed provenance edges and snapshot-scoped B0/G1 graph queries.
- [M2 evidence alignment](docs/M2_EVIDENCE_ALIGNMENT.md) — source-byte-backed text and JSON citation validation before graph insertion.
- [M1 preliminary case shortlist](docs/research/M1_CASE_CANDIDATES.md) — five researched container vulnerability case possibilities, not yet approved.
- [M0 tracking issue](https://github.com/FardinSamin/ThreatRAGraph/issues/1).

## Research plan

The pilot targets approximately **25–40 permitted public CTI, Kubernetes, CVE, ATT&CK and Falco sources** and **4–6 historical cases**. The central paired experiment compares (B0) a sparse-report-only baseline with (G1) similarity-based graph bootstrapping. The graph must only use historically eligible evidence at each case's cutoff. Source-backed observations and provisional inferred relationships must remain distinct.

Milestones: **M0** import/audit → **M1** source corpus → **M2** extraction/graph → **M3** historical snapshots → **M4** baseline → **M5** similarity inference → **M6** evaluation → **M7** research report/presentation.

## Getting ready for M0

The local prototype must be reviewed before any source code import. The read-only intake preflight can inspect a folder for suspicious filenames, selected secret patterns, symlinks and scan limitations without uploading file contents:

~~~powershell
python scripts/preflight_import.py "C:\full\path\to\your\existing\ThreatRAGraph"
~~~

The script prints finding **categories and relative paths**, not token values. A clean result does **not** certify the source or Git history as safe. Read the [complete intake procedure](docs/M0_PROTOTYPE_INTAKE.md) before pushing.

Validate the preflight itself using the built-in test suite:

~~~powershell
python -m unittest discover -s tests -v
~~~

No application dependencies, API tokens, AWS account or paid cloud services are needed for this preparatory script.

## Research manifests (draft only)

The M1 **source registry now contains 14 preliminary public URL candidates**, but **zero approved/frozen source versions and zero selected evaluation cases**. These links require historical version, timestamp, rights and hash review before scientific use. The offline validator checks identities, immutable source metadata, independently verified availability dates, and leakage-safe case partitions:

~~~powershell
python scripts/validate_research_manifests.py datasets/manifests/pilot.json datasets/cases/pilot.json
python scripts/validate_research_manifests.py datasets/manifests/pilot.json datasets/cases/pilot.json --strict
~~~

The additional offline byte-audit checks a local content-addressed archive against approved hashes, without downloading or printing report content:

~~~powershell
python scripts/audit_source_artifacts.py datasets/manifests/pilot.json --require-all
~~~

With **zero approved sources**, a no-error audit is not proof of a valid research corpus. The first manifest command validates candidate metadata but must not be interpreted as approval. The strict readiness check is **expected to fail** until 25–40 verified source versions and 4–6 cases are populated and reviewed. This is an intentional quality gate, not a completed research dataset.

## Historical input snapshots (source-level foundation)

A no-write preview for deterministic cold-start (B0) versus graph-assisted (G1) **source lists** is available:

~~~powershell
python -m scripts.freeze_case_snapshots datasets/manifests/pilot.json datasets/cases/pilot.json
~~~

Current result is **no_cases_yet**, not a genuine research experiment. The strict `--write` mode requires a complete approved 25–40-source corpus, 4–6 historical cases, and byte-verified local archives before persisting content-addressed snapshots. This does **not** yet time-filter extracted graph claims, aliases, semantic embeddings or model pretraining.

## Provenance graph reference component

The repository now includes a **standalone, testable sourced-claim graph** in `src/threatragraph/evidence_graph.py` and a guarded offline CLI:

~~~powershell
python -m scripts.project_case_graph --help
~~~

For a real case, it will require approved, historically verified source versions, matching archived bytes and reviewed claim JSONL. It builds B0 (early only) and G1 (the same early source claims plus eligible background) **without loading held-out reference claims into either projection**. The reference ledger stores assertions, **not predictions**, and the CLI now verifies source citation spans against archived UTF-8 text/JSON bytes. It does **not** yet extract CTI text or predict novel behavior; Falco YAML and PDF normalization remain pending. Real corpus, cases, and original local prototype integration are still pending.

## Cloud services and licensing

The SDD proposes a **local-first** baseline. Neptune, Bedrock and S3 are optional and should not be activated until justified, budgeted and approved. No repository license has yet been selected; review source ownership and public-report redistribution terms before publication.

**Primary research source:** *URFS_Proposal_Fardin_Samin.pdf* supplied to the project investigator (not committed here). Requirements/design do not constitute evaluated research findings.
