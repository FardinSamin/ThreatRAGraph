# ThreatRAGraph

**ThreatRAGraph** is a GraphRAG-based cyber threat intelligence research project investigating whether graph-structural similarity to historically documented threats can improve provisional profiles for newly emerging threats when only one or two early public reports exist.

## Status

**Research infrastructure under development, not yet empirically evaluated.** This repository now contains testable, offline source-integrity, evidence-alignment, semantic-review, historical graph, and B0 baseline reference components. **This project is being developed from scratch in this repository; there is no pre-existing local Python prototype to import.** No approved real CTI source versions, historical cases or B0/G1 study outcomes exist yet. SRS/SDD are draft research designs, not proof of final faculty approval.

## Documents

- [SRS](docs/SRS.md) — software requirements, research hypotheses, functional and nonfunctional criteria, acceptance gates.
- [SDD](docs/SDD.md) — proposed architecture, claim/evidence graph schema, time-safe snapshots, similarity engine, baseline, evaluation, deployment options.
- [**Controlled build plan**](docs/BUILD_PLAN.md) — execution order, exact dependencies, per-stage acceptance, adversarial tests, stop/go rules and first three PRs.
- [**Implementation coverage ledger**](docs/IMPLEMENTATION_STATUS.md) — FR-01–36 and research gate statuses backed by actual code/test paths, with missing and partial work disclosed.
- [P0 research-readiness contract](docs/P0_READINESS_CONTRACT.md) — strict structural checks never automatically certify real-world research approval.
- [P0 security and dependency gates](docs/P0_SECURITY_GATES.md) — new Python lint, tracked-content secret detection, public runtime advisory auditing and exact parser pin checks.
- [P0 artifact and SQLite v1 contracts](docs/P0_SCHEMA_CONTRACTS.md) — validate exact historical source/graph boundaries and reject incompatible legacy SQLite ledgers without silent migration.
- [M0 historical intake note](docs/M0_PROTOTYPE_INTAKE.md) — superseded planning document; there is no pre-existing prototype to import. The preflight script remains optional for any future external contributions.
- [M1 corpus protocol](docs/M1_CORPUS_PROTOCOL.md) — source-version metadata, historical case partitions and cutoff validation.
- [M1 source byte-integrity audit](docs/M1_SOURCE_INTEGRITY.md) — locally verify SHA-256 of frozen CTI source versions while keeping archives out of Git.
- [M3 historical snapshot contract](docs/M3_HISTORICAL_SNAPSHOTS.md) — deterministic B0/G1 source inputs that exclude held-out later references.
- [M2 sourced evidence graph](docs/M2_EVIDENCE_GRAPH.md) — reference SQLite claim ledger, typed provenance edges and snapshot-scoped B0/G1 graph queries.
- [M2 evidence alignment](docs/M2_EVIDENCE_ALIGNMENT.md) — source-byte-backed text and JSON citation validation before graph insertion.
- [M2 GHSA structured candidate extraction](docs/M2_GHSA_CANDIDATES.md) — offline byte-pinned, human-review-only CVE-to-Go-package candidates, not approved source claims or G1 predictions.
- [M2 GHSA compound review packets](docs/M2_GHSA_COMPOUND_REVIEW.md) — verifies both structured supporting fields and records append-only self-declared reviews in an isolated candidate-only store, never as approved sourced claims.
- [M2 approved-source compound claim extension](docs/M2_COMPOUND_SOURCED_CLAIMS.md) — opt-in v1-compatible SQLite side tables for verified dual-field claims, explicit semantic reviews and cutoff-filtered separate projections; not G1 inference.
- [M2 HTML/Falco normalization](docs/M2_HTML_FALCO_NORMALIZATION.md) — deterministic source-linked HTML visible text and safe pinned Falco YAML citation parsing.
- [M2 PDF page evidence](docs/M2_PDF_PAGE_PROVENANCE.md) — pinned page-by-page PDF text extraction from approved archived bytes with verifiable page/offset citations.
- [M2 semantic claim review](docs/M2_SEMANTIC_REVIEW.md) — explicit reviewer attestations bound to exact claim IDs, archive evidence, and strict graph readiness gates.
- [M4 B0 cold-start baseline](docs/M4_B0_BASELINE.md) — deterministic target facts from early reviewed source assertions only, no background retrieval, prediction or invented confidence.
- [P1a first real-source screening](docs/research/P1A_LEAKY_VESSELS_CASE.md) — real dated Leaky Vessels source chronology and explicit remaining archive/review blockers; **not an approved case**.
- [P1a signed upstream release provenance](docs/research/P1A_RUNC_RELEASE_WITNESS.md) — replayable offline audit of runc GitHub release, annotated tag, reported PGP signature and hard historical-approval boundaries.
- [P1a actual pinned upstream tag acquisition](docs/research/P1A_PINNED_TAG_ACQUISITION.md) — GitHub CI fetches the original signed Git object and measures byte-level SHA-256; **candidate-only, no case/source approval**.
- [P1a release-era GnuPG signer verification](docs/research/P1A_RUNC_SIGNER_VERIFICATION.md) — authentic PGP signature verified with a historically pinned runc keyring in isolated CI; exact first-public date and reviewer approval still pending.
- [P1a original advisory public-event witness](docs/research/P1A_ORIGINAL_ADVISORY_WITNESS.md) — original advisory bytes tied to an independently retained pre-cutoff public commit, with repeatable offline verification and pending investigator approval.
- [P1a real original GHSA extraction replay](docs/research/P1A_GHSA_LIVE_REPLAY.md) — CI retrieves exact hash-pinned original advisory bytes, checks CVE/package fields and emits a hash-only candidate receipt; no study approval.
- [P1a case–method eligibility gate](docs/research/P1A_CASE_METHOD_ELIGIBILITY.md) — explains why CVE/vulnerability targets cannot be evaluated by G1 v2 and requires a reviewed case-unit decision before results.
- [Private candidate byte capture](docs/research/P1A_LEAKY_VESSELS_CASE.md#safe-manual-source-byte-preservation-private-not-approval) — bounded offline original-byte archiving and unapproved receipts; not proof of historical content or rights.
- [M1 preliminary case shortlist](docs/research/M1_CASE_CANDIDATES.md) — five container vulnerability prospects plus a new G1-v2-compatible **campaign** method screen; no approved cases.
- [P1b SCARLETEEL campaign screen](docs/research/P1B_SCARLETEEL_CAMPAIGN_SCREEN.md) — source-grounded, candidate-only Kubernetes/AWS campaign with tentative `USES` feature; explicitly refuses same-type peer/G1 eligibility without real evidence.
- [P1b historical campaign peer follow-up](docs/research/P1B_SCARLETEEL_CAMPAIGN_PEERS.md) — separately names the Chimaera and Kiss-a-dog campaigns as exact XMRig-feature *unverified* peers, clarifying why G1 still requires two independent groups **within each candidate peer’s evidence path**.
- [P1b original Chimaera URL in 2021/2022 pinned bibliographies](docs/research/P1B_CHIMAERA_HISTORICAL_BIBLIOGRAPHY.md) — real SHA-bound third-party Git reference bytes replayed in CI; the original AT&T 2021 article remains **unfrozen and unapproved**.
- [P1b original 2022 MITRE ATT&CK TeamTNT STIX bytes](docs/research/P1B_MITRE_ORIGINAL_TEAMTNT_2022.md) — live CI replays a publisher-owned historical **intrusion-set** record and traces the September 2020/2021 Chimaera citation discrepancy, without retyping TeamTNT as a campaign or approving any real sources.
- [P1c genuine same-peer Cado/CrowdStrike Kiss-a-dog prospect](docs/research/P1C_KISSADOG_SAME_PEER_CHAIN.md) — separately observed Redis/Docker XMRig and prospective XHide path by two original research lines, with a live 2022 derivative Git pointer replay and no claim of original Cado article-byte approval or G1 readiness.
- [P1d independently observed 2022 Cado report pointer public Git push](docs/research/P1D_KISSADOG_PUBLIC_PUSH_WITNESS.md) — authentic GH Archive public PushEvent **2022-12-23T11:42:28Z** joined to original Git commit/tree/two file blobs; this **timestamps the public derivative reference, not Cado's original report HTML**.
- [P1b original-report Common Crawl WARC intake](docs/research/P1B_COMMONCRAWL_PRIMARY_WARC_INTAKE.md) — strict offline CDX/WARC HTTP-200 original-HTML byte-range verifier for the SCARLETEEL/Chimaera/Kiss-a-dog leads. No matching genuine primary archive capture has been recovered or approved yet.
- [M5.2 exact-only as-of feature lineage](docs/M5_ASOF_FEATURE_LINEAGE.md) — mandatory per-claim graph/date and no-alias/no-external-taxonomy contract; **not independent evidence approval**.
- [**M5 G1 explainable similarity v2**](docs/M5_G1_SIMILARITY.md) — synthetic-tested paired early-source parity, typed graph neighbors, independent provenance paths and provisional hypotheses; **no real empirical claim**. [Remaining M5 work](https://github.com/FardinSamin/ThreatRAGraph/issues/21).

## Current engineering priorities

**Current research priority:** [P1a real historical case — Issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24), with [case–method compatibility reviewed first](docs/research/P1A_CASE_METHOD_ELIGIBILITY.md). In parallel, finish [P0 CI/contract hardening — #23](https://github.com/FardinSamin/ThreatRAGraph/issues/23) and [M5 G1 v2 — #21](https://github.com/FardinSamin/ThreatRAGraph/issues/21), without claiming empirical effectiveness. [Details and exit gates](docs/BUILD_PLAN.md).

No completed real-data GraphRAG comparison exists yet. The 30 source entries remain *unapproved candidates* and the case manifest remains empty. Strict structural checks now **always return `research_ready: false`** until a separately reviewed empirical approval protocol exists; even a passing synthetic test is not historical or scientific evidence.

## Research plan

The pilot targets approximately **25–40 permitted public CTI, Kubernetes, CVE, ATT&CK and Falco sources** and **4–6 historical cases**. The central paired experiment compares (B0) a sparse-report-only baseline with (G1) similarity-based graph bootstrapping. The graph must only use historically eligible evidence at each case's cutoff. Source-backed observations and provisional inferred relationships must remain distinct.

Milestones: **M0** greenfield repository setup (initial setup complete; legacy import inapplicable) → **M1** verified source corpus → **M2** extraction/graph foundation → **M3** historical snapshots → **M4** B0 baseline → **M5** G1 similarity inference → **M6** evaluation → **M7** research report/presentation. **M1 remains unfinished, and the real end-to-end CTI extraction/case evaluation have not been demonstrated.**

## Local setup and tests

This is a **greenfield project**. Clone the existing GitHub repository to work on the implementation already committed here. There is no prior local Python prototype to import.

~~~powershell
git clone https://github.com/FardinSamin/ThreatRAGraph.git
cd ThreatRAGraph
python -m pip install -r requirements-normalization.txt
python -m unittest discover -s tests -v
~~~

The historical `scripts/preflight_import.py` utility is optional for future external code imports; it is **not** a project blocker or required setup step. The full test suite uses pinned normalization dependencies; no AWS account or paid cloud service is required.

## Research manifests (draft only)

The M1 **source registry now contains 30 preliminary source candidate entries**, but **zero approved/frozen source versions and zero selected evaluation cases**. These links require historical version, timestamp, rights and hash review before scientific use. The offline validator checks identities, immutable source metadata, independently verified availability dates, and leakage-safe case partitions:

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

For a real case, it will require approved, historically verified source versions, matching archived bytes and reviewed claim JSONL. It builds B0 (early only) and G1 (the same early source claims plus eligible background) **without loading held-out reference claims into either projection**. The reference ledger stores assertions, **not predictions**. The CLI verifies archived source citations (UTF-8 text, JSON, HTML, Falco YAML, and extractable PDF text) and now requires **claim-bound human semantic reviews** for strict research runs. It does **not** yet predict novel behavior or implement a full extraction pipeline. A bounded GHSA 1.4.0 Go package candidate adapter is now available, but is strictly review-only and cannot directly insert compound-field evidence into the existing one-locator ledger. HTML visible-text, pinned Falco YAML, and **extractable PDF page-text citation verification** are now supported; OCR, PDF visual layout interpretation, independent reviewer authentication, and real semantic review annotations remain pending. Real corpus curation, end-to-end extraction validation and real-case experiments are still pending.

## M4 cold-start B0 baseline

The new **B0-only** CLI consumes a pair of isolated M3 source-view/M2 sourced-graph JSON inputs for a case. It refuses G1/background/later-source inputs, requires aligned citations and semantic review in strict mode, directly reports supported *early source assertions* about the target with source/claim/evidence provenance, and abstains on insufficient or contradictory evidence.

~~~powershell
python -m scripts.profile_b0 --help
python -m scripts.profile_b0 --b0-view "C:\research\b0-view.json" --b0-graph "C:\research\b0-graph.json"
~~~

The baseline itself requires only Python's standard library; preparing trusted source/evidence artifacts uses the broader pinned toolchain and historical validation pipeline. B0 deliberately emits **no inferred predictions** or statistical confidence. See [the full B0 contract](docs/M4_B0_BASELINE.md). A real baseline evaluation cannot proceed until the historical corpus, actual extractor behavior and independent case-review protocol are validated.

## Cloud services and licensing

The SDD proposes a **local-first** baseline. Neptune, Bedrock and S3 are optional and should not be activated until justified, budgeted and approved. No repository license has yet been selected; review source ownership and public-report redistribution terms before publication.

**Primary research source:** *URFS_Proposal_Fardin_Samin.pdf* supplied to the project investigator (not committed here). Requirements/design do not constitute evaluated research findings.
