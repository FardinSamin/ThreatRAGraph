# ThreatRAGraph — Software Requirements Specification (SRS)

**Document ID:** TRG-SRS-001  
**Version:** 0.2.0 (greenfield requirements + implementation-audit gates)  
**Date:** 2026-10-10  
**Status:** Controlled draft for investigator/faculty review; implementation coverage is evidenced by GitHub code/CI, not by this requirements document alone  
**Owner:** Primary student investigator, ThreatRAGraph  
**Companions:** docs/SDD.md (design and as-built gap map); docs/BUILD_PLAN.md (sequencing, dependencies and stop/go gates)

> **Greenfield source-of-truth correction (2026-10-10):** There has **never been a separate local Python prototype to import**. This GitHub repository is the project codebase. The initial SRS/SDD were created before the source/evidence/graph/historical/B0 reference components; those components now exist and have synthetic CI tests, but **0 real source versions and 0 historical cases have been approved and no B0/G1 empirical comparison has been performed**. Design descriptions and green synthetic CI must never be confused with real-world functionality, historical provenance, faculty approval or research results. See [BUILD_PLAN](BUILD_PLAN.md) for required exit gates.

## 1. Purpose and research foundation

### 1.1 Research problem

Cyber threat intelligence (CTI) arrives through unstructured reports, advisories, security documentation, indicators, and structured feeds. Newly emerging threats may initially be represented by only one or two public sources. **ThreatRAGraph** tests whether a knowledge graph constructed from *historically available* evidence can generate a more useful **provisional** profile of a sparse threat than a baseline using only those early reports.

**Primary question (RQ-01):** When a new threat is sparsely documented, can structural similarity in a CTI knowledge graph produce an earlier and more useful provisional profile than a cold-start method restricted to the first one or two public reports?

**Hypothesis (H1):** Similarity-based graph bootstrapping improves the completeness of early threat profiles relative to the cold-start baseline, while retaining sufficiently high correctness, attributable evidence, and clearly disclosed uncertainty.

**Null hypothesis (H0):** Graph bootstrapping does not improve quality over the sparse-report baseline under a time-valid evaluation.

This is a falsifiable research system, **not** a live operational threat-detection or autonomous response platform.

### 1.2 Authority and source hierarchy

1. **Research authority:** The provided six-page *URFS Proposal — ThreatRAGraph: A GraphRAG-Based Cyber Threat Intelligence Knowledge Graph System* (sections 1–10, especially 1–2, 5–7). Its intended pilot contains approximately **25–40 sources**, **4–6 sparse-threat evaluation cases**, Python-based ingestion/extraction/graph-building, a Kubernetes/container/Falco focus, and an evaluation against later evidence.
2. **Standards authority:** OASIS STIX 2.1, published MITRE ATT&CK STIX releases, published Falco rule syntax/fields, and upstream vendor documentation. External formats must be versioned and not silently assumed stable.
3. **Engineering proposals:** Requirements identified as **[DESIGN]** or **[TARGET]** are recommendations made here to operationalize the proposal, not commitments explicitly made by the URFS.
4. **Implementation evidence:** Code actually committed in this greenfield repository, synthetic and real-data tests, CI, case/source approval records and frozen experiment artifacts. An existing Python module does **not** imply the associated research requirement is fully met.

### 1.3 Goals and non-goals

**In scope**
- A curated, reproducible public CTI/container-security research corpus.
- Document collection, normalization, entity/relation extraction, schema validation, deduplication, human review and provenance.
- Knowledge graph with typed entities and evidence-backed assertions including time and source.
- Explicit historical snapshots for leakage-free cold-start experiments.
- Structural/similarity retrieval and provisional hypothesis generation, with abstention.
- Reproducible baseline vs. graph-assisted evaluation, measurement, analysis and export.
- A small, local-first researcher interface/API where useful; cloud services only if justified.

**Out of scope for the URFS pilot**
- Continuous worldwide CTI coverage; SOC production SLAs; real-time intrusion detection.
- Deploying exploit code, interacting with victim systems, offensive scanning, or automatic blocking.
- Treating similarity-inferred links as known facts, generating definitive threat attributions.
- Training a foundation model, massive labeled datasets, or deploying a large multi-tenant platform.
- Mandatory Amazon Neptune/Bedrock adoption regardless of cost; proposal costs are **budget estimates**, not deployment decisions.
- Demonstrating successful predictive results before experiments are run.

### 1.4 Actors and boundaries

| Actor | Needs | Privileges |
|---|---|---|
| Student investigator | Curate corpus, run experiments, inspect sources, publish reproducible results | Research administrator |
| Faculty mentor / reviewer | Review methodology, inspect metrics, trace evidence and versions | Read-only by default |
| Analyst / future researcher | Query entities, explore evidence/provisional profiles | Read-only |
| Automated collector | Collect authorized public data, record metadata | Ingestion-only |
| Extraction worker | Create candidate graph assertions, not adjudicated truth | Scoped write |
| Evaluation worker | Read frozen snapshots, create immutable run results | Scoped research write |
| External publishers / APIs | Data providers, not trusted executors | No system access |

## 2. Research and data constraints

**RC-01 — Corpus:** Curate approximately 25–40 public/non-classified sources spanning selected reports, AlienVault OTX pulses, MITRE ATT&CK/STIX, Falco rule docs, Kubernetes documentation and container-related CVEs. The exact balance and licensing are pending curation.

**RC-02 — Cases:** Select 4–6 candidate historical cases with verifiable publication chronology, one or two *initial* sources, and later independent documentation containing evaluable additional facts. Reject cases lacking a defensible historical cutoff.

**RC-03 — Focus:** Prioritize container/Kubernetes components, runtime behavior and system calls while retaining core malware, actor, vulnerability, tool, technique and indicator concepts.

**RC-04 — Evidentiary discipline:** Every extracted fact must be grounded in explicit input text/structured source. Graph extrapolations are hypotheses and must be stored and displayed distinctly.

**RC-05 — Temporal validity:** Only data that was publicly available **on or before** the evaluated cutoff may influence that early snapshot. A later-downloaded current ATT&CK collection is **not** automatically historical evidence.

**RC-06 — Evaluation independence:** Later reports may be used as held-out outcome/ground-truth material only, never as input, prompt context, precomputed graph features, aliases or similarity exemplars for the corresponding cutoff.

**RC-07 — Scope of research claims:** A positive result on 4–6 case studies is exploratory; report uncertainty, per-case behavior and limitations rather than generalize to all emerging threats.

## 3. Requirement notation

- **FR-nn:** testable functional requirement.
- **DR-nn:** data / ontology requirement.
- **NFR-nn:** nonfunctional constraint or proposed acceptance target.
- **EV-nn:** research-evaluation safeguard / outcome requirement.
- **AC-nn:** release acceptance criterion.
- Priority **M** = pilot must-have, **S** = should-have, **L** = later.
- Requirements are **normative targets**. A matching file or synthetic unit test is not necessarily end-to-end completion; assign each requirement an implementation evidence/status in the build-plan matrix. A future source/version/label leak is a release blocker.

## 4. Functional requirements

### 4.1 Collection, corpus and normalization

| ID | Pri. | Requirement | Verification |
|---|---|---|---|
| FR-01 | M | Register each authorized source with a stable source ID, publisher, URL or accession, title, content type, publication time, acquisition time, version and usage/license notes. | Inspect source manifest/schema tests |
| FR-02 | M | Import allowed report text, structured STIX JSON, OTX data, CVE/advisory metadata, Falco YAML rules and curated Kubernetes docs; unsupported types must fail explicitly. | Fixtures per supported format |
| FR-03 | M | Store original bytes/content checksum separately from normalized text/records; avoid destructive overwrites. | Round-trip/hash test |
| FR-04 | M | Normalize encodings, timestamps to UTC, canonical identifiers and document segmentation, preserving offsets or evidence locations. | Golden-record normalization tests |
| FR-05 | M | Deduplicate canonical source versions and near-identical republications; retain publisher/version relationships. | Duplicate and mirror fixture |
| FR-06 | M | Maintain immutable corpus manifests with source hashes, rights/status, import parameters and dataset version. | Rebuild reproducibility test |
| FR-07 | S | Provide a manual inclusion/exclusion workflow with reviewer rationale for pilot cases and documents. | Curator acceptance test |
| FR-08 | M | Quarantine malformed, oversized, suspicious, inaccessible or unauthorized content without breaking the remaining batch. | Failure-injection test |

### 4.2 CTI extraction, graph and quality

| ID | Pri. | Requirement | Verification |
|---|---|---|---|
| FR-09 | M | Generate typed candidate entities/relationships from normalized source content, with transparent deterministic extraction first and model assistance only when separately enabled. Parsers that *only verify citations* do not satisfy this requirement. | Manually labeled documents + a real source-to-claim test |
| FR-10 | M | Extract Falco rule names, descriptions, conditions, referenced fields, recognizable syscall/event types and container predicates; distinguish static rule patterns from observed incidents. | Falco YAML fixtures |
| FR-11 | M | Preserve evidence spans/field paths, document ID and extraction/model version for every candidate assertion. | Traceability assertions |
| FR-12 | M | Validate types, relation domain/range, identifiers and temporal fields; reject or quarantine incompatible objects. | Schema-negative tests |
| FR-13 | M | Canonicalize/deduplicate entities while preserving aliases and uncertainty; prevent automatic actor/tool/malware conflation. | Alias collision tests |
| FR-14 | M | Persist typed nodes and directed edges with separate, uniquely identifiable supporting claim/evidence records. | Graph round-trip tests |
| FR-15 | M | Encode assertion state as asserted/confirmed by source, disputed, or predicted; never promote a prediction to a sourced observation implicitly. | State-transition tests |
| FR-16 | M | Support source-to-claim, claim-to-entity, entity-neighbor, time-bounded and case-specific graph queries. | Query contract tests |
| FR-17 | S | Generate a structured extraction quality queue for uncertain/conflicting candidates and record manual adjudication. | Review workflow test |
| FR-18 | S | Export versioned entities, relationships, claims and corpus metadata as interoperable JSON/CSV; STIX export only where semantically valid. | Export-import test |

### 4.3 Retrieval, GraphRAG and provisional profiling

| ID | Pri. | Requirement | Verification |
|---|---|---|---|
| FR-19 | M | Construct a sparse input profile solely from each case's permitted first one or two reports. | Cutoff fixture |
| FR-20 | M | Retrieve eligible historical neighbors using typed graph features (e.g., techniques, components, behaviors, syscall/rule predicates); log feature contributions. | Deterministic top-k test |
| FR-21 | M | Exclude the target's later evidence, aliases learned later, later taxonomy/rule revisions, duplicated/syndicated target reports, full-corpus precomputed features, outcome labels and outcome-informed adjudications from retrieval and profile input. Rebuild or independently verify **every derived layer as of cutoff**. | Source-, claim-, alias-, taxonomy-, feature- and label-level adversarial leakage tests |
| FR-22 | M | Produce a provisional profile of candidate types/relations with evidence paths, similarity rationale, confidence/score and prediction status. | Output schema test |
| FR-23 | M | Support abstention when evidence is insufficient, ambiguous, contradictory or below a preregistered threshold; output must say why. | Negative-control cases |
| FR-24 | M | Produce a report-only cold-start profile using the same extraction/normalization and a comparable output schema, without access to the graph similarity result. | Baseline isolation test |
| FR-25 | S | Provide graph neighborhood and evidence-chain explanations, without exposing unsupported model prose as source truth. | Expert review of examples |
| FR-26 | S | Allow an LLM-assisted synthesis mode with strict citation/evidence constraints; no LLM requirement for the core similarity computation. | Prompt-injection/citation tests |

### 4.4 Experiment, interface, operations

| ID | Pri. | Requirement | Verification |
|---|---|---|---|
| FR-27 | M | Define case cutoff, source allowlist, forbidden future sources, reference facts and annotation rules before experiments. | Case manifest validation |
| FR-28 | M | Execute baseline and graph-assisted methods on the **same** selected case set, exact early source versions and extracted/reviewed initial claims, ontology and normalization; only eligible historical background structure differs. | Machine-checked early-input hash parity + paired-run audit |
| FR-29 | M | Persist immutable experiment configuration, code revision, dependency lock, source/data and graph snapshot hashes, ontology/extractor/ruleset and optional model/prompt versions, random seed if relevant, reviewer/annotation set and results. Freeze predictions **before** held-out labels are opened. | Clean-room reproduction, run manifest validation and gold-access boundary test |
| FR-30 | M | Score frozen profile facts against separately reviewed later references, recording supported, contradicted, not-assessable and duplicate/out-of-scope decisions. Do **not** count unmentioned predictions automatically as false. | Blinded/reference-separated gold-label fixtures and denominator tests |
| FR-31 | M | Produce per-case and aggregate results with claim-level traceability and failure/abstention analysis. | Metrics snapshot test |
| FR-32 | M | Expose a CLI to ingest, validate, build, snapshot, profile, evaluate and export without requiring a dashboard. | CLI smoke scenario |
| FR-33 | S | Expose authenticated local/research-only read APIs for sources, graphs, evidence, profiles and run artifacts. | API contract test |
| FR-34 | S | Present a lightweight researcher dashboard for inspection, not as a dependency of valid evaluation. | User acceptance check |
| FR-35 | M | Apply cost limits, dry-run capability, fail-fast missing-credential checks, timeouts, retries and structured logs to optional cloud operations. | Simulated quota/timeout tests |
| FR-36 | M | Keep data collection and analytical inference isolated from host/container execution; never execute embedded text or commands from CTI reports. | Adversarial fixture tests |

## 5. Logical data requirements / ontology

### 5.1 Required entity vocabulary (DR-01)

- **ThreatActor, Malware, Campaign, Tool, Vulnerability** (CVE as a possible external identifier), **AttackTechnique** (ATT&CK ID where available), **Indicator** (typed and normalized), **SoftwareProduct**, **ContainerComponent**, **KubernetesResource**, **AttackBehavior**, **SystemCall**, **FalcoRule**, **SourceDocument**, **ReportSection**, **Claim**, **EvidenceSpan**, **ExperimentCase**, **Snapshot**, **Profile**, **Prediction**, **EvaluationRun**.
- **[DESIGN]** An **Artifact/Observable** distinction avoids assuming every IP/hash is a confirmed malicious indicator.
- STIX types map where meaning matches; project-specific Kubernetes/Falco types may remain extension types rather than invalid STIX objects.

### 5.2 Relationship vocabulary (DR-02)

Representative controlled types: **USES**, **TARGETS**, **AFFECTS**, **EXPLOITS**, **IMPLEMENTS_TECHNIQUE**, **INDICATES**, **DETECTED_BY**, **HAS_BEHAVIOR**, **INVOLVES_SYSCALL**, **APPLIES_TO_COMPONENT**, **MENTIONS**, **SUPPORTS**, **CONTRADICTS**, **DERIVED_FROM**, **SIMILAR_TO**.

- Domain/range constraints, inverse conventions and meaning are defined and versioned in the SDD/schema.
- **SIMILAR_TO** is a computed analytical relation, not a sourced historical fact.
- **DETECTED_BY** in rule documentation means *potential detection logic*, not proof that a real threat was detected.
- A reported technique cannot be inferred as executed solely because a rule mentions the same syscall.

### 5.3 Evidence, uncertainty, dates (DR-03 to DR-10)

| ID | Requirement |
|---|---|
| DR-03 | Every sourced relationship has at least one claim with source ID, version/hash, evidence locator, extraction origin and recorded time. |
| DR-04 | Each source has separate **published_at**, **observed/modified_at when known**, **ingested_at**, and confidence/quality of publication dating; unknown is not equivalent to early. |
| DR-05 | Store earliest defensible **available_at** time for time-gated use. An unverifiable historical timestamp makes the source ineligible for cutoff-sensitive evaluation unless independently evidenced. |
| DR-06 | Preserve STIX object IDs, ATT&CK external IDs, CVE identifiers, Falco rule IDs/names, source revisions and canonicalization lineage. |
| DR-07 | Evidence records are immutable; corrections create superseding records or revisions, not silent replacement. |
| DR-08 | Represent contradiction, negation and uncertainty as claim properties; absence of reporting is **not** evidence of absence. |
| DR-09 | Predictions store target snapshot, candidate relation, method, **uncalibrated rank score (not a probability)**, calibration status, eligible source paths, feature contributions, abstention and run ID, separately from observed/sourced claims. |
| DR-10 | Link case ground-truth labels only to held-out outcome partitions; never merge them into early-retrieval graph views. |

### 5.4 Contracts (DR-11) **[DESIGN]**

Each important persisted record shall carry **schema_version**, stable **id**, creation time, source/run linkage, and a serializable representation. Version-breaking changes require a migration and backward-compatibility test. Source files must never be trusted as authoritative executable configuration.

## 6. Nonfunctional requirements and provisional targets

*These are proposed engineering thresholds for the pilot, not previously measured results or funding-program mandates. Calibrate targets after profiling the newly implemented, repository-based pipeline with real data.*

| ID | Pri. | Constraint or target | Acceptance method |
|---|---|---|---|
| NFR-01 | M | Reproducible experiments: same frozen inputs/config and deterministic stages yield byte-stable normalized/graph outputs; nondeterministic model steps record all parameters and residual variance. | CI hash comparison + repeated run audit |
| NFR-02 | M | Provenance coverage: **100% of scored claims** must have valid source evidence or explicit prediction status with supporting paths. | Automated invariant |
| NFR-03 | M | Temporal leakage: **zero known forbidden future sources, aliases, ontology/rule revisions, features, cached embeddings, reviewers' later decisions or held-out labels** in profile/rank/explanation paths. | Adversarial time-travel and process-isolation tests |
| NFR-04 | M | Data integrity: original source hash never changes in place; checksums validated when reused. | Artifact integrity test |
| NFR-05 | M | Data security: no credentials in repo, logs, prompts or exports; scoped secrets through environment/secret store. | Secret scan and code review |
| NFR-06 | M | Safe processing: raw inputs treated as untrusted text/JSON/YAML, with size limits and safe parsers; no evaluation of source-supplied code. | Malicious fixture tests |
| NFR-07 | M | Local-first: all core graph/evaluation stages runnable without chargeable AWS services when using configured local/mock extractors. | Offline integration smoke test |
| NFR-08 | M | Costs visible before execution: estimate expected requests, tokens and cloud resources; enforce per-run soft/hard budget guards. | Dry-run/budget test |
| NFR-09 | M | Resumable batches: failed item logged and quarantined; rerun is idempotent by content hash + pipeline version. | Retry fault injection |
| NFR-10 | S | **[TARGET]** On 25–40 pilot documents, routine local ingest/build/evaluate jobs finish within a documented practical research session; record actual wall clock per stage rather than promise a hard latency prematurely. | Benchmark report |
| NFR-11 | S | **[TARGET]** CLI/API query feedback for typical pilot graph neighborhood queries within 3 seconds on reference developer hardware; hardware documented. | Load test |
| NFR-12 | M | Every referenced external format/model/library is pinned to version or immutable artifact. | Manifest review |
| NFR-13 | M | Outputs include caveat: provisional scores are not calibrated probabilities until validated. | Profile schema/UI review |
| NFR-14 | M | No automated offensive action, exploit execution, scanning or cloud infrastructure modification as part of analysis. | Dependency and security review |
| NFR-15 | S | Accessible researcher output: machine-readable files + navigable provenance, plain-language interpretation, legible figures. | Researcher review |
| NFR-16 | M | Unit, integration, adversarial, schema and evaluation tests are automated with status visible in CI. | CI run |
| NFR-17 | M | Permissions: write/admin operations restricted; evaluator can read frozen snapshots but not mutate them. | Role access test |
| NFR-18 | M | Legal/ethical sourcing: respect API limits, terms, publication rights and attribution; document redistribution restrictions. | Dataset review |
| NFR-19 | S | Retention and deletion policy for source caches, logs and cloud copies documented before cloud deployment. | Policy inspection |
| NFR-20 | M | Every result carries dataset/snapshot ID, source inclusion manifest, code commit and extraction/model version. | Run artifact validator |

## 7. Research evaluation requirements

### 7.1 Study protocol

1. Preselect 4–6 historical threat/vulnerability cases independently of the experimental outcome.
2. For each case, determine first and second public report timestamps, an **early cutoff**, independent later evidence and permitted background graph. Document source chronology and any uncertainty.
3. Construct **B (baseline)** from only first one/two reports using identical extraction schema.
4. Construct **G (graph-assisted)** using the same B input **plus** historical background graph available by cutoff; disallow target-specific future evidence.
5. Freeze prompting, extraction configuration, threshold, top-k and relation vocabulary before comparison; tune on development cases only or flag exploratory tuning.
6. Obtain manually reviewed held-out reference claims from later sources, with adjudication and **not-assessable** labels.
7. Evaluate both systems at equal permitted fact types and evidence rules, including unsupported predictions, calibration and abstention. Report every case, negative result and failure.

### 7.2 Required evaluation criteria

| ID | Requirement |
|---|---|
| EV-01 | **Extraction quality:** entity precision/recall/F1 and relation precision/recall/F1 against a manually annotated held-out subset; include denominators and annotation definitions. |
| EV-02 | **Profile completeness:** recall of later-supported reference relations/facts (and count of newly recovered facts) for B and G, per case. |
| EV-03 | **Correctness:** precision of assessable predicted relations and false-positive count, never report recall without precision. |
| EV-04 | **Uncertainty:** abstention rate, coverage, score distribution and optionally Brier/calibration metrics only if probabilities are actually calibrated. |
| EV-05 | **Paired comparison:** case-level deltas G minus B; mean/median and descriptive dispersion; small sample disclaimers and bootstrap sensitivity only where meaningful. |
| EV-06 | **Ablation [DESIGN]:** test no-graph, graph without syscall/Falco features, and/or feature-weight variants if sufficient time/data; avoid unsupported causal claims. |
| EV-07 | **Evidence quality:** percentage of predictions with auditable source path; manual review of semantic relevance and contradiction. |
| EV-08 | **Leakage audit:** time-gate proof, exclusion manifest and tests for future aliases, newer ATT&CK versions, mirrored reports and reference-label contamination. |
| EV-09 | **Repeatability:** store immutable report of evaluated cases, source hashes, cutoff dates, outputs, annotations and metric scripts. |
| EV-10 | **Interpretation:** document alternative explanations, case-selection bias, sparse reference coverage, error bars and known limitations. |

**Scoring policy [DESIGN]:** Only facts labeled independently **supported** or **contradicted** by held-out evidence count toward assessable precision. **Not assessable** is reported separately, not automatically considered false. Existing explicitly observed facts and *newly proposed predictions* must be scored in separate breakdowns. Do not treat prediction count or profile length alone as success.

### 7.3 Cold-start fairness requirements

- Baseline and graph system receive identical early-case input documents, extraction prompts/models, taxonomy and postprocessing where feasible.
- The graph method receives only additional **permitted historical background knowledge**, which is the treatment being tested.
- Rule language and CVE descriptions that were revised after cutoff must be pinned to authentic earlier versions; otherwise exclude from time-gated graph.
- Record dependence among reports (syndicated/copied text); repeated stories do not count as independent corroboration.
- If model pretraining may already encode future events, label LLM-based retrospective experiments as contaminated-risk and prefer controlled deterministic candidates/ablations. Do **not** claim complete historical blindness of a pretrained LLM.

## 8. Interfaces and deliverables

**Primary CLI [DESIGN]:** Commands equivalent to corpus import, validate, extract, build-graph, freeze-snapshot, create-case, profile-baseline, profile-graph, evaluate and export. Exact command names are selected in SDD and tested.

**Optional read API [DESIGN]:** versioned endpoints for health, sources, entities, neighborhoods, cases, profiles, runs and metrics. Writes require authentication and validation.

**Research deliverables (from proposal):**
1. Curated documented pilot dataset and manifests.
2. Working research prototype with graph + extraction.
3. Paired baseline vs graph-assisted evaluation, including extraction quality.
4. Final written report and PURC Symposium presentation.
5. Optional poster/manuscript extension only if warranted by results.

## 9. Acceptance criteria and milestones

| ID | Exit criterion | Evidence required |
|---|---|---|
| AC-01 | Research protocol signed off, 4–6 valid cases and 25–40-source pilot **independently dated, rights-reviewed and byte verified**, or explicit reviewed deviation. | Frozen corpus/case manifests, archived-hash audit, date and license evidence, approval record |
| AC-02 | Reproducible **actual source-to-extracted-candidate-to-reviewed-claim-to-graph** pipeline for the pilot; no untraceable scored assertions. | Real source ingest replay + schema, evidence, review and graph tests |
| AC-03 | Valid extraction metrics on independent manually annotated documents. | Labels, scorer and summary |
| AC-04 | As-of source/claim/alias/ATT&CK/Falco/feature snapshots and adversarial time-leakage regressions pass; evaluator gold store cannot influence either profiler. | Source and feature-level cutoff tests, rejection logs, label-read isolation test |
| AC-05 | Frozen B0 and G1 runs consume **identical early input bytes/claims** and produce versioned observed and provisional outputs; predictions are not mixed into sourced claims. | Early-input hash equality, separate predictions, run artifacts frozen before scoring |
| AC-06 | Held-out scoring includes completeness **and** correctness, with casewise evidence and limitations. | Evaluation report + exports |
| AC-07 | Reproduction instructions work from versioned repository checkout using no-cost local fixtures; Windows and CI/Linux environments and full dependency versions documented. | Clean-environment offline smoke + dependency manifest and output hash verification |
| AC-08 | Secrets scan, dependency review, resource budgets and publication-rights checks completed. | Release checklist |
| AC-09 | Faculty review and symposium-ready methods/results communicated without overstating evidence. | Review notes and presentation |

**Controlled delivery sequence:** repository hardening/readiness truthfulness (P0) → independently dated/rights-reviewed one-real-case development slice, then full corpus (P1) → real extraction + review (P2) → complete temporal reconstruction (P3) → paired B0/G1 (P4; synthetic G1 engine can be developed in parallel) → independent evaluation (P5) → faculty/reproduction/reporting (P6). **See [BUILD_PLAN](BUILD_PLAN.md) for measurable gates.** The proposal's Phase I/II/III windows (mid-May to early August) are planned historical windows; do not invent a schedule or assume funding authorization.

## 10. Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Temporal / pretrained-model leakage | Invalid apparent improvement | Snapshot gating, historical versions, adversarial checks, deterministic core and model-risk disclosure |
| Ambiguous entity linking or relation semantics | False inferred links | Typed ontology, evidence first, manual review, alias collision tests |
| Small/correlated case set | Weak generalizability | Per-case results, independence review, transparent exploratory framing |
| Publication-date uncertainty | Invalid cutoff | Explicit provenance of timestamps; exclude or sensitivity-test uncertain sources |
| Vendor/API/schema drift | Irreproducible ingest | Pin versions, archive allowed raw copies/hashes, compatibility fixtures |
| Unsupported LLM claims/prompt injection | Hallucinated or unsafe output | Constrained JSON, evidence validation, abstention, never execute source text |
| Neptune/Bedrock billing | Unplanned financial cost | Local-first mocks, explicit enablement, spending guardrails, shutdown checklist |
| Disclosure/license risk | Unpublishable corpus | Usage-rights manifest and links/hashes when redistribution disallowed |
| Reference implementation–design mismatch | Rework | Audit this repository's implemented modules/tests against the SRS and SDD; integrate missing components incrementally |

## 11. Traceability baseline

| Research obligation | Requirements | Proposed validation |
|---|---|---|
| Public CTI/Kubernetes/Falco/CVE collection | RC-01, FR-01–08, DR-04–06 | Manifest tests, format fixtures |
| Extraction accuracy | FR-09–18, DR-01–03, EV-01 | Manual annotation + held-out metrics |
| Knowledge graph and evidence | FR-14–16, DR-01–11, NFR-02 | Graph and provenance integration |
| Sparse-profile baseline | FR-19, FR-24, EV-02–05 | Frozen paired cases |
| Similarity bootstrap | FR-20–23, EV-02–08 | Explainable predictions + ablations |
| No future evidence | RC-05–06, FR-21, EV-08, NFR-03 | Time-travel adversarial tests |
| Usable research output | FR-27–34, EV-09–10, AC-01–09 | Reproduction, final paper/poster |
| Bounded cloud spending | FR-35, NFR-07–09 | Dry-run, mocks, billing guard tests |

## 12. Open decisions / TBD register

| ID | Decision pending | Default until decided |
|---|---|---|
| TBD-01 | **Resolved:** Greenfield repository; no prior local prototype exists | Audit existing repository modules and their tests as the sole implementation of record |
| TBD-02 | Exact 25–40 documents and allowed redistribution? | Curate per-source manifest; do not copy restricted full texts into public releases |
| TBD-03 | Selection, dates and independent later reference facts for 4–6 cases? | No experimental claim until documented |
| TBD-04 | Exact source of OTX access and API quota? | Optional adapter; no credentials committed |
| TBD-05 | Extractor/model and whether use AWS Bedrock Claude? | Pluggable local/mock default; assess costs and leakage |
| TBD-06 | Graph backing store (local graph vs Neptune)? | Local adapter as reference, Neptune optional |
| TBD-07 | Embedding/RAG strategy, similarity weights, k and thresholds? | Baseline interpretable graph features; preregister experimental choices |
| TBD-08 | Manual annotation protocol / mentor reviewer availability? | Written rubric, adjudication log and held-out validation |
| TBD-09 | Compute environment, authentication needs, hosting model? | Greenfield single-user/offline-first Python repository; cloud and hosted API deferred |
| TBD-10 | Reconciled schedule/year and funding authorization? | No presumption that proposal spending or summer timeline is approved |
| TBD-11 | Public release policy / exact repository license? | Private until credentials, rights and code ownership reviewed |
| TBD-12 | Reference model for "ground truth" when reports disagree? | Label supported, contradicted, or not assessable with source evidence |

## 13. Budget boundaries

The **proposal**, not this document, requests **$2,800 total:** $2,000 student stipend and $800 research expenses allocated as $350 Bedrock, $225 Neptune Serverless compute, $75 Neptune storage/I/O/backup, $25 S3 and $75 monitoring/API headroom. These are **proposal-era estimates** and do not constitute verified current AWS pricing or authorization to deploy. Require current pricing review, explicit permissions, free/local run path, budget alerts, teardown procedures and spend tracking before cloud use.

## 14. References and document control

**Primary:** *URFS_Proposal_Fardin_Samin.pdf*, 6 pages, supplied by the investigator (not yet stored in repository). Particularly sections 1–2 (question/hypothesis), 5–6 (method/evaluation), 7 (phases), 9 (budget).

**Standards and external primary references**
- OASIS STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- MITRE ATT&CK STIX 2.1 releases: https://github.com/mitre-attack/attack-stix-data
- Falco rules / condition structure: https://falco.org/docs/concepts/rules/basic-elements/
- Falco field definitions: https://falco.org/docs/rules/supported-fields/
- Kubernetes documentation: https://kubernetes.io/docs/
- NVD CVE API documentation: https://nvd.nist.gov/developers/vulnerabilities
- AWS Neptune documentation: https://docs.aws.amazon.com/neptune/
- AWS Bedrock documentation: https://docs.aws.amazon.com/bedrock/

**Change policy:** Update this SRS first when research scope, requirements or acceptance criteria change; update the SDD, [build plan](BUILD_PLAN.md), contracts and tests in the same PR. Never mark a requirement scientifically fulfilled merely because scaffolding exists or synthetic tests pass.


## 15. Implementation reality and independent readiness gates (v0.2.0)

The original proposal's **research scope and hypothesis are unchanged**. This section corrects the mistaken historical assertion about a separate prototype, identifies which existing repository components have synthetic coverage, and makes empirical gate conditions explicit. [BUILD_PLAN](BUILD_PLAN.md) defines how to execute them.

| Requirement cluster | Actual greenfield code path | Supported claim **today** | Missing / acceptance gate |
|---|---|---|---|
| FR-01,03,05–08 / DR-03–05 | `scripts/validate_research_manifests.py`, `audit_source_artifacts.py`; draft `datasets/manifests/pilot.json` | Source metadata and archived-hash **validation tools** present | No approved real source versions, date evidence or end-to-end collector/batch quarantine/rights audit; AC-01 incomplete |
| FR-02,04,10–12 | `src/threatragraph/normalized_sources.py`, `pdf_sources.py`, `evidence_alignment.py` | Synthetic-tested citation normalization/verification for a bounded set of formats | Complete adapters, arbitrary report entity/relation **extraction**, measurable extraction quality not present; AC-02/03 incomplete |
| FR-13–18 / DR-01,02,06–08 | `src/threatragraph/evidence_graph.py`, `semantic_reviews.py` | SQLite typed **sourced-claim** ledger, limited ontology, attributable edges and reviewer-status controls | Versioned alias resolution, reviewer independence, full ontology and export/replay; partial |
| FR-19,24 | `src/threatragraph/baseline_b0.py`, `scripts/profile_b0.py` | B0 deterministic reviewed **early assertions** and abstention on synthetic fixtures | No real-case run or paired empirical validation |
| FR-20,22,23,25 / DR-09 | [Issue #21](https://github.com/FardinSamin/ThreatRAGraph/issues/21) | Design/requirements only | G1 structural similarity, provisional predictions, evidence-path ranking and no-LLM hypothesis generation absent |
| FR-21,27–29 / DR-10 | `scripts/freeze_case_snapshots.py`, `project_case_graph.py` | **Source-level** historical B0/G1 allowlisting and claim-derived graph isolation in synthetic tests | Alias/taxonomy/feature as-of reconstruction, approved full case set, prediction-run and label-process isolation missing |
| FR-30,31 / EV-01–10 | SRS/SDD test design only | Evaluation policy exists as document | Separate held-out annotation, scoring CLI, statistical tables, negative-result audit and real measurements missing |
| FR-32–36 / NFR-05–09 | Research CLIs, `.github/workflows/quality.yml`, `.gitignore` | Partial offline CLI and CI; AWS off | Full workflow CLI, authenticated API if desired, budget guards for optional cloud, security scanner/branch protections and clean-room replication not demonstrated |

**Required distinction:** The P0.1 graph and B0 outputs now **always report `research_ready: false`**, with a separate `readiness` disclosure of successfully completed *structural* checks. This explicitly prevents synthetic or self-declared-review fixtures from being confused with **independently approved historical sources, licensing, human authenticity or empirical evaluation**. Only a separately developed, auditable approval protocol satisfying [P1b–P5 signoffs](BUILD_PLAN.md) could eventually authorize a scientifically ready study result. See [readiness contract](P0_READINESS_CONTRACT.md).

**Non-negotiable negative tests (link to RC-04–06, FR-11,15,19–24,27–30, DR-03,07–10, NFR-02–04):** fabricated citation, malicious input, unsupported or expired source revision, uncertain publication date, later target report, copied/syndicated evidence, post-cutoff ATT&CK/Falco revisions, later-learned aliases/entity merges, future graph feature/embedding index, contradiction, forged reviewer judgment and held-out reference-label access. No scored run proceeds if any input contains forbidden evidence or an unresolved eligibility failure.

**Experimental scope:** B0 may output **no inferred predictions** and legitimately abstain; it is the report-only reference. G1 must separate early observed assertions from *new provisional* ranker hypotheses and report uncalibrated similarity, provenance and abstentions. Evaluate both using the same case cutoffs, initial evidence, ontology and independently reviewed later labels. A positive result is **not required** for a valid research deliverable.

**Research governance:** Proposed 25–40 sources and 4–6 cases are maintained from the proposal; any change to these sample-size bounds, funding, hypothesis or study design needs an explicit investigator/faculty decision rather than automatic optimization for convenient results.
