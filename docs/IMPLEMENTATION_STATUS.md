# ThreatRAGraph — Implementation Coverage Ledger

**Ledger ID:** TRG-STATUS-001 | **Version:** 0.2.0 | **Review date:** 2026-10-10  
**Authority:** [SRS v0.2](SRS.md), [SDD v0.2](SDD.md), [build and acceptance gates](BUILD_PLAN.md)  
**Scope:** Greenfield **GitHub** codebase only. No pre-existing Python prototype exists, and no real approved CTI source corpus/case study has been evaluated.

This is a **code-and-test audit**, not a certification. Status labels:
- **Present/tested synthetic:** A bounded behavior is implemented and covered by current synthetic fixtures.
- **Partial:** Only part of the requirement is implemented; do not report the overall SRS requirement as fulfilled.
- **Missing:** No demonstrated repository implementation.
- **Optional/deferred:** Outside core critical path until justified, but must be implemented if claimed/released.
- **Not empirically verified:** No authentic historical input/independent evaluation demonstrates expected real-world behavior.

**Current reference:** the existing code through M4 and prior 149-test synthetic suite. Re-run tests on the current commit to establish an up-to-date count; test count alone cannot prove corpus validity or research effectiveness.

## Functional requirements FR-01–FR-36

| SRS ID | Implementation status | Current concrete implementation/test evidence | Missing gate / next step |
|---|---|---|---|
| FR-01 | Partial | `datasets/manifests/pilot.json`, `scripts/validate_research_manifests.py`, `tests/test_research_manifests.py` | Real collection/acquisition and complete source metadata |
| FR-02 | Partial | `src/threatragraph/normalized_sources.py`, `pdf_sources.py`, associated tests | Complete STIX/OTX/CVE adapters and source-to-typed-claim conversion |
| FR-03 | Partial | `scripts/audit_source_artifacts.py`, `tests/test_source_artifacts.py` | Approved real archive capture and rights evidence |
| FR-04 | Partial | `evidence_alignment.py`, `normalized_sources.py`, `pdf_sources.py` | Unified segments, versioned canonical IDs, all historical timestamps |
| FR-05 | Partial | Manifest validator duplicate digest/independence checks | Near-copy/syndication detection and publisher lineage |
| FR-06 | Partial | Source manifest versions, SHA-256 audit, `freeze_case_snapshots.py` | Immutable real corpus approval and complete preprocessing config |
| FR-07 | Partial | Candidate shortlist and rationale fields; draft registries | Human inclusion/exclusion approval workflow |
| FR-08 | Partial | Size/format/hash validation and refusal tests | Robust per-item quarantine and continue-on-error batch ingest |
| FR-09 | **Missing** | Parsing/validation exists, **not a complete CTI candidate extractor** | Structured STIX and rule-based text typed candidate extraction + gold quality |
| FR-10 | Partial | `normalized_sources.py`, `test_normalized_sources.py` | Actual Falco rule entity/field extraction and relationship mapping |
| FR-11 | Present/tested synthetic (subset) | `evidence_graph.py` + `evidence_alignment.py`, `test_evidence_alignment.py` | Audited extraction origin across complete real pipeline |
| FR-12 | Present/tested synthetic (limited ontology) | `evidence_graph.py`, `test_evidence_graph.py` | Full type coverage, schema evolution/migrations |
| FR-13 | **Missing** | Typed IDs enforced, but no time-aware alias resolution engine | Historized canonicalization and collision decisions |
| FR-14 | Partial | SQLite sourced claim tables and graph JSON projection | Full logical entity/evidence storage and export round-trip |
| FR-15 | Partial | `assertion_kind` + polarity + review ledger; predicted claims prohibited | Separate prediction plane and state transition contract |
| FR-16 | Partial | Source-allowlisted graph projection and neighborhood helper | General lineage/time/case query interface and access isolation |
| FR-17 | Partial | `semantic_reviews.py` decisions, adverse tests | Review queue, independent adjudication and conflict resolution protocol |
| FR-18 | **Missing** | JSON outputs exist | Versioned interoperable JSON/CSV export-import (STIX only valid types) |
| FR-19 | Present/tested synthetic (only) | `freeze_case_snapshots.py` + `baseline_b0.py` | Real historical case and extract/review parity |
| FR-20 | **Missing** | [M5 Issue #21](https://github.com/FardinSamin/ThreatRAGraph/issues/21) | G1 typed structural similarity and feature contributions |
| FR-21 | Partial | M1/M3 source-level cutoffs and provenance exclusions | Historized alias/taxonomy/feature/index exclusion + future controls |
| FR-22 | **Missing** | G1 prediction target schema designed in SDD | G1 provisional, attributable, scored, abstaining predictions |
| FR-23 | Partial | B0 abstention `baseline_b0.py`; synthetic tests | G1 score/support/uncertainty abstention |
| FR-24 | Present/tested synthetic (only) | `scripts/profile_b0.py`, `tests/test_b0_baseline.py` | Real paired-run common extraction/output comparison |
| FR-25 | Partial | `EvidenceGraph.neighborhood` and source-attributed edges | Historical evidence-chain explanations for G1 |
| FR-26 | Optional/deferred | Architecture only | Opt-in, budget-gated, citation-validated synthesis with contamination disclosure |
| FR-27 | Partial | Draft source/case registries and validators | 4–6 frozen real historical cases and independent label partitions |
| FR-28 | **Missing** | B0/G1 source view scaffold exists | Machine-verified paired early-input equivalence and runner |
| FR-29 | Partial | Snapshot/source SHA-256 IDs and profiles | Immutable full experiment run/lock/model/config/annotation registry |
| FR-30 | **Missing** | Evaluation design only | Held-out later label store and independent scorer |
| FR-31 | **Missing** | No empirical run reports | Casewise and aggregate denominator-bearing metrics exports |
| FR-32 | Partial | Source, archive, snapshot, graph and B0 CLIs | End-to-end ingest/extract/build/profile/evaluate/export orchestrator |
| FR-33 | Optional/deferred | No authenticated read API | Add only if required by researcher workflow |
| FR-34 | Optional/deferred | No dashboard | Defer to verified study, or implement minimal audit browser |
| FR-35 | Partial/deferred | Default local/no AWS, no cloud operations | Explicit budget/dry-run/timeouts/teardown when cloud adapters are proposed |
| FR-36 | Partial | Parsing as text + size caps and YAML safe loader tests | Full ingestion/LLM connector threat-model and isolation tests |

## SRS research, data, acceptance and nonfunctional coverage

| Cluster | Current assessment | Gate |
|---|---|---|
| RC-01/02 | 14 **candidate URLs**; **0 approved** real versions and **0 selected** cases | P1 complete exact archived sources and independent case chronology |
| RC-03/04 | Kubernetes/container/Falco types and source-vs-rule distinction in bounded graph | P2 real extraction, review, source lineage |
| RC-05/06 | Source-level cutoff + held-out exclusion synthetic tests | P3 full alias/taxonomy/feature/index/label isolation |
| DR-01/02 | Limited typed ontology, not full vocab | Ontology/version and compatibility tests |
| DR-03/05/07/08 | Claim evidence, source hashes, date checks, polarity and review contracts | Actual source time proof, immutable end-to-end run and correcting review lineage |
| DR-06 | No canonical full STIX/ATT&CK/CVE/Falco revision registry | Source-version and alias adapters |
| DR-09 | **No G1 Prediction store** | P4 candidate schema and separate hypotheses |
| DR-10 | **No independent evaluator outcome plane implemented** | P3/P5 process isolation and frozen labels |
| DR-11 | Some versioned JSON records; no complete migration suite | P0 schema validation and backward compatibility |
| EV-01–10 | Scoring/evidence policy designed; no independent real evaluation | P2 extraction labels and P5 paired evaluator |
| NFR-01/04 | Synthetic hashes and local integrity code | Clean-room real-corpus reproducibility |
| NFR-02/03 | Synthetic attribution and source-level cutoff protections | P3 full derived-leak audit, scored 100% provenance |
| NFR-05/06 | `.gitignore`, heuristic preflight, bounded parsers | Real secret/dependency scan and full untrusted-input sandbox |
| NFR-07/08/09 | Offline reference components; cloud off | Complete offline workflow, retries/quarantine and cloud opt-in budget guards if enabled |
| NFR-10/11/12 | Some exact parser versions, no full lock/benchmark | P0 locked reproducible environment and measured latency |
| NFR-13/14/15 | Explicit no-calibration/no-offensive defaults; JSON artifacts | G1 outputs and reporter UX |
| NFR-16 | `.github/workflows/quality.yml` Python tests | P0 lint/type/security and Windows verification |
| NFR-17/18/19/20 | Private/local by default and plan docs; no production deployment | Permissions, rights/retention and immutable run provenance |
| AC-01–09 | **None can currently be declared satisfied for the real pilot** | [P1b–P6 acceptance evidence](BUILD_PLAN.md), even if some synthetic subchecks pass |

## Known critical misinterpretations to prevent

1. **A local archive hash is not a publication timestamp.** Real source/date evidence is still missing.
2. **A matching quotation is not a correct CTI triple.** Semantic review is self-declared and synthetic-tested, not independent scientific validation.
3. **An extractor interface in the SDD is not an implemented extractor.** `pdf_sources.py`, `normalized_sources.py` and `evidence_alignment.py` mostly parse and verify, not classify all malware relations.
4. **Source allowlisting is not full historical reconstruction.** Future aliases, ATT&CK/Falco revisions and prior computed graph features are unsolved.
5. **P0.1 fix: structural validation now emits `research_ready=false`, even for strict synthetic fixtures.** Its explicit `readiness` disclosure does not authenticate original publication chronology, independent reviewers, or real case approval. A future separate empirical run acceptance protocol is still required.
6. **B0's `predictions=[]` is intentional.** No new inference is implemented; G1 is outstanding.
7. **149 synthetic tests do not imply 149 historical research successes.** There are currently zero real case comparisons.

**How to maintain:** When a PR changes any row, link the exact new module and test(s), change the status conservatively and update [BUILD_PLAN](BUILD_PLAN.md) and the affected SRS/SDD sections. Never close full FR/EV/AC items solely from documentation or fixture tests.
