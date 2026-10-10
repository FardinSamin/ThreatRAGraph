# ThreatRAGraph — Software Design Document (SDD)

**Document ID:** TRG-SDD-001  
**Version:** 0.2.0 (greenfield reference architecture + verified implementation delta)  
**Date:** 2026-10-10  
**Status:** Controlled architecture draft with an as-built mapping (`18); unimplemented flows remain explicit designs, not capabilities  
**Design authority:** docs/SRS.md, version 0.2.0; execution/exit gates: docs/BUILD_PLAN.md, version 0.2.0  
**Project:** ThreatRAGraph — A GraphRAG-Based Cyber Threat Intelligence Knowledge Graph System

> **Source of truth (2026-10-10):** ThreatRAGraph is **greenfield**. There is **no separate prior local prototype**; this GitHub repository is the implementation. The SRS/SDD design predates now-committed **synthetic-tested source validation, archive integrity, bounded normalization, SQLite sourced claims, manual-review contract, source-level historical views and B0 reference baseline**. Those modules are **not a completed data collector, free-text extractor, as-of entity resolver, G1 predictor or empirical research platform**. `18 maps actual code to remaining gaps; [BUILD_PLAN](BUILD_PLAN.md) defines measurable go/no-go conditions.

## 1. Design objectives and decisions

ThreatRAGraph is a **research platform first**, a prototype second. Its defining success criterion is a scientifically defensible comparison between a sparse-report-only baseline and a similarity-assisted graph method for container/Kubernetes CTI, **without future-information leakage**.

### 1.1 Design principles

1. **Evidence before inference.** Store sourced claims and predicted relationships in distinct stores/types and use distinct query modes. Do not label a graph suggestion as established intelligence.
2. **Temporal correctness is architectural.** All retrieval inputs are filtered by historical availability, data versions, case cutoff and target holdout partition, including cached embeddings and aliases.
3. **Local-first and AWS-optional.** Reference evaluation needs no paid infrastructure. AWS Bedrock, Neptune Serverless and S3 are interchangeable optional adapters, not prerequisites.
4. **Auditable experiments.** Every result identifies exact source set, snapshots, code version, model/prompt/configuration, feature scores, predicted facts and later reference labels.
5. **Separation of concerns.** Sources, normalized text, extracted claims, curated graph, similarity features, provisional profiles and evaluation ground truth are independent logical stages.
6. **Reproduce before optimizing.** For 25–40 pilot sources and 4–6 cases, transparent algorithms and deterministic defaults are preferable to premature distributed infrastructure.
7. **Least privilege, untrusted inputs.** Web reports/YAML/JSON can contain misleading instructions; parse as data only. No runtime execution or cloud changes are part of ingestion.
8. **Pluggability without excessive abstraction.** A small set of explicit protocols isolates source adapters, extraction engines, graph backends and synthesis methods.

### 1.2 Architecture decision record (initial)

| ADR | Choice | Rationale | State |
|---|---|---|---|
| ADR-001 | Python 3.12 reference runtime **[IMPLEMENTED IN CI]** | Current workflow explicitly selects Python 3.12; another platform requires separate smoke validation | Implemented reference / portability pending |
| ADR-002 | Batch/CLI-first, optional FastAPI read API | Standalone source validation, graph, snapshot and B0 scripts exist; full orchestrated ingest/evaluate CLI is pending | Partially implemented |
| ADR-003 | SQLite sourced-claim ledger + content-addressed local archives; FTS5/NetworkX only if shown necessary | SQLite claim/review tables and in-memory attributed graph JSON implemented; FTS5/NetworkX are **not** presently demonstrated dependencies | Partial; defer unused complexity |
| ADR-004 | Optional Amazon Neptune **property graph** backend using an adapter; openCypher/Gremlin compatibility reviewed before use | Proposal mentions Neptune; backend-independent evidence logic | Conditional |
| ADR-005 | Deterministic source parser first, then rules/STIX-native extraction; model assistance optional | Format parsing/citation verification implemented, but automatic typed candidate extraction remains pending | Partially implemented |
| ADR-006 | Typed source/evidence claim records with explicit date-time uncertainty | Limited typed ontology, source version, evidence and polarity ledger exists; fuller event-time/alias model missing | Partially implemented |
| ADR-007 | Interpretable weighted graph-feature ranking before embeddings or LLM synthesis | Falsifiable similarity treatment and meaningful ablations | Proposed |
| ADR-008 | Offline scoring pipeline and human-reviewed reference facts | Human **source-claim** review contract exists, but held-out gold labels and metric scorer are not implemented | Partially implemented |
| ADR-009 | Frozen manifests + content hashes + exact release revisions | Source-byte hashes and source-level input hashes implemented; historical taxonomy, aliases, real archives and freeze signoff missing | Partially implemented |
| ADR-010 | One-user local-first greenfield implementation; hosted dashboard deferred | Matches focused pilot size and scope | Proposed |

*An ADR documents a design choice; its state above distinguishes implemented code from targets. Revisit open decisions against the actual repository/test evidence and faculty methodological feedback. This SDD does not claim that a component exists merely because it appears in a Mermaid diagram.*

## 2. Context and high-level architecture

### 2.1 System context

~~~mermaid
flowchart LR
    PUB["Public CTI / OTX / CVE / K8s / Falco / ATT&CK sources"] --> COL["ThreatRAGraph collector"]
    RES["Student investigator"] --> CLI["Research CLI / optional UI"]
    MENT["Faculty mentor / reviewer"] --> READ["Read-only reports and evidence"]
    COL --> CORE["ThreatRAGraph local pipeline"]
    CLI --> CORE
    CORE --> READ
    CORE -. "explicitly enabled" .-> AWS["Optional S3 / Bedrock / Neptune"]
~~~

**Trust boundaries:** External content is untrusted. Local source artifacts are accepted only via validated ingestion. Optional cloud services are outside the default research runtime; credentials and data export require explicit configuration. The retrospective **outcome/reference partition** is physically or logically segregated from graph construction and inference.

### 2.2 Container/component view

~~~mermaid
flowchart TB
  subgraph DATA["Source and provenance plane"]
    AD["Adapters: reports / STIX / OTX / CVE / Falco / Kubernetes"]
    RAW["Immutable raw documents + manifest"]
    NOR["Normalizer + deduplication + temporal metadata"]
    AD --> RAW --> NOR
  end
  subgraph KNOW["Knowledge plane"]
    EXT["Parser + extractor"]
    REV["Schema validation / canonicalization / review"]
    CLM["Evidence-backed claims ledger"]
    PROJ["Typed graph projection"]
    NOR --> EXT --> REV --> CLM --> PROJ
  end
  subgraph RESEARCH["Research plane (historically isolated)"]
    CASE["Case definitions + cutoff policy"]
    SNAP["As-of snapshot builder"]
    BASE["Cold-start report-only baseline"]
    SIM["Graph similarity + candidate proposal"]
    GEN["Evidence-constrained profile renderer"]
    GOLD["Held-out later annotations"]
    EVAL["Paired scorer + ablation + reports"]
    CASE --> SNAP
    CLM --> SNAP
    SNAP --> BASE
    SNAP --> SIM
    PROJ -. "filtered projection only" .-> SIM
    BASE --> EVAL
    SIM --> GEN --> EVAL
    GOLD --> EVAL
  end
  subgraph OPS["Control and access"]
    CLI["CLI orchestration"]
    API["Optional read API / dashboard"]
    RUN["Run registry / budgets / logs"]
  end
  CLI --> AD
  CLI --> CASE
  API --> CLM
  API --> RUN
  CLI --> RUN
  EVAL --> RUN
~~~

**Mandatory invariant:** The diagram's graph projection fed to similarity is rebuilt **from the snapshot**, not a full contemporary graph with a WHERE clause applied only at the last query. No gold labels, future source text, later entity merges or model outputs trained on outcome labels can enter it.

### 2.3 Deployable units **[DESIGN]**

| Unit | Responsibility | Deployment |
|---|---|---|
| trg CLI | Imports, extracts, builds, snapshots, profiles, evaluates, exports | Developer/research machine |
| Source adapters | Fetch/download or read curated snapshots under explicit usage policy | Local scheduled/manual batch |
| Extractor worker | Deterministic parser and optional LLM HTTP adapter | Local process |
| Record store | Documents, versions, claims, evidence, cases, runs | Local SQLite + file store |
| Graph projection | In-memory typed multigraph built from allowed claim set | Local Python process |
| Scoring runner | Leakage audit + baseline/G comparisons + report generation | Local process/CI |
| Read API/UI | Optional browse graph and experiments | localhost by default |
| AWS adapters | Bedrock generation, Neptune property graph, S3 artifact sync | Opt-in, IAM-scoped only |

## 3. Suggested repository structure

**Illustrative target layout (not the as-built file tree).** Actual modules live at `src/threatragraph/`, `scripts/` and `tests/`; see `18 for the code inventory. Do not create a parallel project structure when extending existing modules.

~~~text
ThreatRAGraph/
  README.md
  pyproject.toml
  .gitignore
  .env.example
  docs/
    SRS.md
    SDD.md
    ADR/
    ontology.md
    experiment-protocol.md
    data-governance.md
  config/
    ontology_v1.yaml
    pipelines.yaml
    similarity_v1.yaml
  src/threatragraph/
    cli.py
    settings.py
    provenance/
      models.py
      repository.py
      temporal.py
    sources/
      base.py
      stix.py
      otx.py
      falco.py
      cve.py
      documents.py
      kubernetes.py
    normalization/
      text.py
      dedupe.py
      canonicalize.py
    extraction/
      rules.py
      llm_adapter.py
      validate.py
    graph/
      ontology.py
      projection.py
      storage.py
      neptune_adapter.py
    research/
      cases.py
      snapshots.py
      features.py
      similarity.py
      baseline.py
      profiles.py
      evaluate.py
      metrics.py
    api/
      app.py
      schemas.py
    ops/
      budget.py
      logging.py
      artifacts.py
  tests/
    unit/
    integration/
    temporal/
    adversarial/
    fixtures/
  datasets/
    manifests/                 # Metadata, licenses, hashes, not restricted report copies
    cases/                     # Historical case definitions
    annotations/               # Gold labels: segregated from inference
  reports/                     # Generated; avoid committing sensitive/raw content
  scripts/
~~~

**Artifact locations [DESIGN]:** Keep raw/normalized blobs in a project-local artifact directory ignored by Git by default, save manifests and small permissible fixtures in Git. Use run-local immutable paths such as **artifacts/runs/{run_id}/**; this notation is illustrative, not an active directory.

## 4. End-to-end data and control flows

### 4.1 Ingest and build graph — **target flow, not yet complete**

~~~mermaid
sequenceDiagram
  participant R as Researcher
  participant I as Ingestor
  participant N as Normalizer
  participant X as Extractor
  participant V as Validator/reviewer
  participant D as Claim ledger
  participant G as Graph projection
  R->>I: import(source manifest, policy)
  I->>I: fetch/check rights, content hash, metadata
  I->>N: immutable source version
  N->>N: parse, timezone, segments, deduplicate
  N->>X: normalized segments / STIX / YAML
  X->>V: candidate entities, typed claims, evidence locators
  V->>V: type checks, aliases, uncertainty, conflicts
  V->>D: append validated source claims + audit
  D->>G: build typed graph from accepted eligible claims
  G-->>R: snapshot ID, quality report, source/claim counts
~~~

**Failure semantics:** Each step records input hash, adapter version, output hash, status and error category. Invalid records are quarantined; valid batch items continue. Retry uses idempotency key **source_version_id + pipeline_config_hash + extractor_version**. The ledger never silently overwrites a previous claim.

### 4.2 Historical experiment — **planned full run; only source-level views and B0 currently implemented**

~~~mermaid
sequenceDiagram
  participant C as Case manifest
  participant S as Snapshot service
  participant B as Baseline profiler
  participant G as Graph-assisted profiler
  participant H as Held-out label store
  participant E as Evaluator
  C->>S: case ID + cutoff + allowed source IDs
  S->>S: check sources, temporal eligibility, forbidden aliases
  S-->>B: early report-only evidence
  S-->>G: same early evidence + eligible background graph
  B->>E: baseline observed profile
  G->>E: proposed relations + provenance paths/abstentions
  H->>E: later fact labels (evaluation only)
  E->>E: assess facts, precision, recall, coverage, caveats
  E-->>C: immutable paired-run report
~~~

**Target isolation, not yet a complete deployed guarantee:** the intended B0/G1 profiler processes must be unable to read gold-label files at all. The current repository has source-level B0/G1 graph views and a standalone B0 CLI but no finished G1 or gold-label evaluator process. Implement OS/filesystem/process separation and an adversarial read-access test before treating this boundary as verified.

## 5. Storage and identity design

### 5.1 Three distinct record planes

1. **Raw/source plane:** byte-for-byte captures when redistribution/retention rights permit, SHA-256, fetching and chronology metadata. URL alone is not sufficient for reproducibility.
2. **Claim/evidence plane:** normalized assertions from explicit text or structured fields, supporting evidence and editorial decisions; authoritative for *what a source said*, **not** unquestioned real-world truth.
3. **Analytical plane:** per-snapshot graph features, similarity candidates and predictions; can be regenerated from frozen source/claim inputs. Evaluation ground truth is a **fourth isolated outcome plane**.

A sourced edge cannot be directly overwritten by a predicted edge; edge labels and claim IDs remain separately queryable.

### 5.2 Target record contracts **[DESIGN illustrations; not executable schemas]**

SourceDocument:
~~~json
{
  "schema_version": "1.0",
  "source_id": "src:report:001",
  "version_id": "srcver:sha256:...",
  "publisher": "Example public publisher",
  "title": "Example incident analysis",
  "canonical_url": "https://example.org/report",
  "source_kind": "cti_report",
  "published_at": "2024-01-12T14:00:00Z",
  "available_at": "2024-01-12T14:00:00Z",
  "date_evidence": "publisher timestamp on archived version",
  "ingested_at": "2026-10-10T00:00:00Z",
  "sha256": "full SHA-256 digest",
  "rights": {"redistribution": "unknown", "attribution": "required"},
  "status": "eligible"
}
~~~

Claim:
~~~json
{
  "schema_version": "1.0",
  "claim_id": "claim:sha256:...",
  "subject_id": "malware:example_family",
  "predicate": "USES",
  "object_id": "attack-technique:T1059",
  "polarity": "positive",
  "status": "source_assertion",
  "source_version_id": "srcver:sha256:...",
  "evidence": [
    {
      "segment_id": "seg:001",
      "locator": {"start_char": 210, "end_char": 264},
      "exact_quote_sha256": "full SHA-256 digest"
    }
  ],
  "extractor": {"name": "deterministic-or-llm", "version": "pinned"},
  "review_state": "unreviewed",
  "valid_time": null,
  "available_at": "2024-01-12T14:00:00Z"
}
~~~

Prediction:
~~~json
{
  "schema_version": "1.0",
  "prediction_id": "pred:sha256:...",
  "case_id": "case:001",
  "snapshot_id": "snapshot:sha256:...",
  "subject_id": "threat:case_001",
  "predicate": "MAY_USE",
  "object_id": "attack-technique:T1059",
  "status": "predicted",
  "score": 0.67,
  "score_kind": "uncalibrated_similarity",
  "evidence_paths": [["claim:a", "entity:b", "claim:c"]],
  "method_version": "similarity_v1",
  "abstained": false,
  "run_id": "run:sha256:..."
}
~~~

**These JSON examples are future target shapes, not actual input schemas.** The current sourced-claim ID has the form `claim:<64-lowercase-hex>` (not `claim:sha256:...`); source manifests use `source_version_id`, `status=approved/candidate` and hash fields; M3 B0/G1 source views and M4 B0 profiles have their own versioned structures. Read the actual validators/fixtures before integrating. Prediction format above is **not implemented**. A sample score (0.67) is never a probability without calibration and is not a measured result.

### 5.3 Target SQLite record schema (**not all tables exist yet**)

| Logical table | Key / important fields | Indexes / constraints |
|---|---|---|
| sources | source_id, title, publisher, canonical_url, rights | unique source_id |
| source_versions | version_id, source_id, sha256, published_at, available_at, ingested_at, date_evidence | unique hash/version, index available_at |
| segments | segment_id, source_version_id, offset or JSON field path, content hash | unique version+location |
| entities | entity_id, type, display_name, normalized_key, ontology_version | unique entity_id; avoid name-only merges |
| aliases | alias_id, entity_id, value, first_evidenced_at, source claim | index alias and first_evidenced_at |
| claims | claim_id, subject, predicate, object, polarity, status, source version, available_at, extractor | constraints on types and status; temporal index |
| evidence | evidence_id, claim_id, segment_id, locators/field path, checksum | FK to claim/segment |
| reviews | review_id, claim_id, decision, rationale, reviewer, at | append-only audit |
| cases | case_id, target definition, cutoff, early versions, forbidden versions, reference set | manifest hash |
| snapshots | snapshot_id, case_id, cutoff, allowed source hashes, ontology/pipeline versions | immutable unique snapshot hash |
| predictions | prediction_id, snapshot_id, candidate triple, path, feature scores, score kind, run_id | unique scoped record |
| runs | run_id, git SHA, config hashes, seed, extraction/model identifiers, runtime and cost | immutable run metadata |
| outcome_labels | label_id, case_id, canonical fact, supported/contradicted/not-assessable, evidence | **separate authorization boundary** |
| eval_results | run_id, case_id, metric name, numerator/denominator, value, annotation set version | versioned append-only |

**SQLite concurrency:** Pilot batch pipeline uses a single writer with transactional append and WAL where suitable. Never rely solely on foreign keys without enabling their enforcement. Use migrations and exported backups. FTS5 may index *eligible normalized segments* for research search; it must be built per snapshot or strictly source-version filtered for historical retrieval.

### 5.4 Graph ontology and edge representation

Represent a **typed directed multigraph**: multiple reports can support the same triple without losing evidence. The graph projection may aggregate repeated claims into a logical relation but must retain IDs of all backing claims and individual source versions.

Core node classes:
- Security: ThreatActor, Malware, Campaign, Tool, Vulnerability, AttackTechnique, Indicator, Observable, SoftwareProduct.
- Container runtime: ContainerComponent, KubernetesResource, AttackBehavior, SystemCall, FalcoRule.
- Provenance/research: SourceDocument, SourceVersion, ReportSection, Claim, EvidenceSpan, Snapshot, ExperimentCase, Prediction (can remain in ledger tables rather than graph vertices).

**Canonicalization examples:** CVE-YYYY-NNNN remains a vulnerability ID; ATT&CK T-codes identify techniques; STIX UUIDs remain upstream IDs with version history; syscall canonical name and Falco field expressions remain distinct; an IP or file hash receives type/normalization and never implies maliciousness by existence alone.

Representative typed edges:

| Predicate | Example domain → range | Semantics / guards |
|---|---|---|
| USES | Malware/ThreatActor/Campaign → Tool/Malware/AttackTechnique | Requires affirmative sourced relationship |
| EXPLOITS | Malware/ThreatActor/Campaign → Vulnerability | Do not infer from coexistence in report |
| AFFECTS | Vulnerability → SoftwareProduct/ContainerComponent | Include affected version bounds when evidence available |
| TARGETS | ThreatActor/Campaign → SoftwareProduct/KubernetesResource | Source-supported target not assumption |
| HAS_BEHAVIOR | Malware/AttackTechnique → AttackBehavior | Behavior must be evidenced or explicitly hypothetical |
| INVOLVES_SYSCALL | AttackBehavior/FalcoRule → SystemCall | For Falco, expresses rule condition pattern |
| DETECTED_BY | AttackBehavior/AttackTechnique → FalcoRule | Potential coverage mapping, not real event/sighting |
| APPLIES_TO_COMPONENT | FalcoRule/Vulnerability → ContainerComponent | Explicit scope or documented condition |
| INDICATES | Indicator → Malware/Campaign | Source or independent validation required |
| SUPPORTS/CONTRADICTS | Claim/EvidenceSpan → Claim | Evidence lineage; not model confidence alone |
| SIMILAR_TO | Entity/Case → Entity/Case | **Computed, snapshot-scoped, analytical only** |

**Type-checking:** Every edge must satisfy an ontology domain/range table. Use strict predicate vocabulary; preserve unrecognized source semantics as non-promoted candidates. Later additions to ontology require schema migration and benchmark rerun.

### 5.5 Handling Falco and syscall semantics

A Falco rule is primarily **detection logic**, not an observed attack. Parse YAML safely into rule name, description, condition, priority, outputs, tags, lists/macros and applicable event source where present. Parse conditions into an AST or normalized predicate list where feasible; do not evaluate arbitrary rule expressions or execute tools from rule files.

- An expression with **evt.type** expresses a Falco event type; use **syscall.type** only when the upstream field actually identifies a syscall. Do not automatically equate all event types with syscalls.
- Preserve **container.id** and Kubernetes-related field filters as predicate constraints, not evidence of actual container compromise.
- Rule macros/lists require safe resolution under a pinned rule package version; unresolved symbols remain explicit.
- **rule_matches_behavior** means a researcher-supported semantic mapping; **rule_triggered_in_incident** requires real telemetry evidence, outside the pilot.
- Record rule repository commit/date/version; applying an up-to-date rule to a 2022 experiment requires proof the rule existed by the cutoff or must be excluded.

References: https://falco.org/docs/concepts/rules/basic-elements/ and https://falco.org/docs/rules/supported-fields/

## 6. Connector/extraction design

### 6.1 Source adapter protocol (**planned; parsing helpers alone are not adapters**)

**SourceAdapter** supports discover/list (optional), fetch, transform-to-source-version and validate. Adapters run independently and emit standardized metadata. Recommended:
- **MITRE ATT&CK STIX 2.1:** pin a specific release from https://github.com/mitre-attack/attack-stix-data, preserve STIX IDs, modified time, ATT&CK technique identifiers and relationship objects. Do not confuse the older MITRE/cti STIX 2.0 repository with this release source.
- **OTX pulses:** API retrieval with explicit token, rate limits, redistribution-rights notes and original update time; never imply all indicator associations are verified.
- **CVE and vendor advisories:** preserve advisory publication/update history, affected versions and uncertain disclosure timestamps. NVD recent JSON is not a substitute for an archived historical state.
- **Falco rules:** YAML rule/macro/list parser under a pinned repository revision; retain complex conditions as normalized syntax if full AST support unavailable.
- **Kubernetes docs:** curated page snapshots and stable URLs/revisions; distinguish security best-practice documents from incident observations.
- **CTI reports:** permitted HTML/PDF/text extraction, with headers, paragraph boundaries, text spans, publication provenance and content hashes.

### 6.2 Extractor contract (**planned; free-text candidate extraction missing**)

~~~text
extract(normalized_version, ontology_version, config) -> CandidateSet

CandidateSet:
  source_version_id
  entities[]:
    proposed_type, surface_text, canonical_id?, evidence_locators[], confidence?
  relationships[]:
    source_entity_ref, predicate, target_entity_ref,
    polarity, qualifiers, evidence_locators[], confidence?
  warnings[]
  model_or_ruleset_version
  prompt_hash_or_parser_version
~~~

**Pipeline stages:** parse -> normalize -> candidate extraction -> rule-based constraints -> evidence alignment -> type validation -> entity resolution -> quarantine/review -> append to ledger -> graph materialization.

**Deterministic first:** Parse STIX objects/relations and Falco YAML as structured data; use LLM or language NER for freeform prose when enabled. Compare extractor against manually reviewed held-out set; avoid allowing a language model to invent a missing source quotation.

**LLM controls [DESIGN]:** Strict JSON-schema outputs, maximal input size, redaction policy, no chain-of-thought retention, no code/tool authority, timeout/retry limits, declared model and generation parameters, token/cost logging. A rejected/missing citation becomes an invalid candidate. The model cannot adjudicate its own scored predictions.

### 6.3 Entity resolution rules (**planned; historized alias state missing**)

Order:
1. Exact high-confidence upstream identifiers (STIX, ATT&CK, CVE, documented rule ID).
2. Type-compatible normalized aliases **supported by pre-cutoff evidence**.
3. Candidate fuzzy matches flagged for reviewer, not silently merged.
4. Explicit negative matching constraints across incompatible entity types or different revisions.

Save merge decisions with reviewer/date/supporting sources; **snapshot as-of reconstruction must not inherit decisions or aliases justified only by future evidence**. Re-running earlier cases after a merge must filter or replay the earlier resolution state.

## 7. Time-valid snapshot builder: central research control

### 7.1 Inputs and outputs (**source-level subset implemented; derived as-of state pending**)

Input: **case manifest** containing target ID, research question, event context, **cutoff UTC**, allowed one/two early source-version IDs, forbidden later sources, independence grouping and reference-label set ID.

Output: content-addressed **snapshot manifest** listing allowed source versions, claim IDs, alias decisions, upstream vocabulary releases, optional embedding index/model cutoff constraints, graph checksum and exclusions with reasons.

### 7.2 Eligibility predicate

~~~text
eligible(record, cutoff):
  require known, defensible source_version.available_at <= cutoff
  require record.evidence derives from eligible source_version
  require model/ruleset/ATT&CK/Falco revision was available <= cutoff,
          OR isolate it as a time-agnostic parser with documented caveat
  reject outcome-partition provenance, target later reports, derivative mirrors
  reject claim/alias/relationship derived from post-cutoff adjudication
  reject unknown/ambiguous publication date unless independently verified
~~~

The cutoff uses **public availability**, not data ingestion date. Store publication date, access date, observed incident date and source-modification date separately. First-seen in an incident need not equal first-known-to-public.

### 7.3 Leakage defenses

1. **Graph rebuilding:** generate each case's feature graph from eligible claims rather than masking only retrieval results after features computed.
2. **Historical taxonomy:** pin ATT&CK/Falco versions, exclude later-introduced techniques/rules/aliases or document a controlled constant ontology used in both branches.
3. **Source versions:** avoid current CVE entries overwriting historical early descriptions; capture old releases/archives or exclude case.
4. **Text and embeddings:** full-corpus embedding index is **not** time-safe without source-level filtering *before* candidate retrieval and proof no future corpus influenced representation/index. Use per-snapshot index for pilot.
5. **Pretrained LLM caveat:** the model may have learned later facts during training. Even prompts containing only old text cannot certify historical ignorance. Prefer no-LLM graph baseline and deterministic ablation; document this threat.
6. **Target holdout:** exclude reference labels, exact target later variants and repeated copied stories; document acceptable pre-cutoff mentions rather than erasing legitimately known earlier evidence.
7. **Automated tests:** introduce forbidden future source, alias, changed CVE and identical copy fixture; fail snapshot assembly if any reach candidate graph or prediction explanation.

**Invariant:** Every retrieved feature must have at least one provenance path terminating in a source version permitted by this snapshot.

## 8. Baseline and graph-assisted inference

### 8.1 Common target profile

Both methods output **typed profile facts** with:
- subject, predicate, object, fact status (**observed** versus **predicted**), optional evidence and qualifiers;
- per-source evidence IDs and time-validity status;
- normalized canonical IDs and a canonical triple key;
- uncertainty/abstention where applicable.

The baseline retains source-asserted facts from early reports only. The graph method starts with the identical facts and proposes **additional** testable candidate relations. Score new proposed facts separately from copied observed facts.

### 8.2 Interpretable similarity engine version 1 **[NOT IMPLEMENTED — M5, Issue #21]**

A case is represented by feature sets extracted from the early profile:
- **techniques** (ATT&CK IDs) and tactic context;
- **container/Kubernetes components** and affected software;
- **behavioral predicates**;
- **Falco rule-condition features** (where genuine and time-valid);
- **syscall features** distinguishable from generic events;
- eligible **indicator types**, not excessively weighted raw indicators;
- graph neighborhood/relation-pattern motifs.

For candidate historical entity h and sparse target t, compute a **weighted, evidence-backed similarity**:

~~~text
feature_sim(f, t, h) = weighted_jaccard(F_f(t), F_f(h))
weighted_jaccard(A, B) =
    sum(weight(x) for x in intersection(A,B))
    / sum(weight(x) for x in union(A,B))

similarity(t, h) =
    sum(feature_family_weight[f] * feature_sim(f,t,h) for f in informative families)
    / sum(feature_family_weight[f] for f in informative families)

candidate_relation_score(t, r) =
    combine(similarity(t,h), supporting_neighbor_count, path_quality,
            corroboration_discount, contradictory_evidence_penalty)
~~~

**Important constraints:**
- Family weights, thresholds and top-k are chosen on development data or documented as exploratory, **never silently tuned on the four-to-six evaluation outcomes**.
- Use information weights like snapshot-local IDF only if derivation is documented and time-valid.
- Empty/unknown sets are not counted as negative evidence. A family with zero informative features is excluded from the denominator; if all are empty, abstain.
- Neighbor selection is type-compatible and excludes target synonyms/mirrored reports/known future reports.
- Limit candidate propagation to ontology-permitted relation templates with reproducible evidence paths.
- Do not propagate actor attribution, exploitation, vulnerability reachability or maliciousness solely because two candidates overlap on generic behaviors.
- Discount correlated reports; where several paths share a single source, do **not** count them as independent corroboration.
- Conflict handling can reduce score or cause abstention. Explanations name shared features and source paths, not rhetorical model justification.
- Scores are **ranking heuristics**, not calibrated likelihoods until empirically validated.

### 8.3 Candidate construction and abstention **[M5 DESIGN]**

~~~text
for case in frozen_cases:
  early = read_first_one_or_two_sources(case)
  graph = build_eligible_snapshot(case.cutoff)
  observed = extract_common_profile(early)
  neighbors = rank_type_compatible_neighbors(graph, observed, top_k)
  candidates = propagate_allowed_relation_templates(neighbors)
  for candidate in candidates:
      support = verify_all_evidence_paths_pre_cutoff(candidate, graph)
      score = weighted_score(candidate, support, config)
      if contradictory or not support or score < threshold:
          record_abstention(candidate, reason)
      else:
          emit_prediction(candidate, score, support, "uncalibrated_similarity")
  freeze_output_before_opening_reference_labels()
~~~

**Provisional output:** Could say "candidate technique supported by historical analog patterns" with supporting source paths. It must not say "the new threat definitely uses the technique" unless explicit early reports assert it.

### 8.4 GraphRAG synthesis **[OPTIONAL; NOT IMPLEMENTED]**

GraphRAG is **grounded retrieval + constrained text generation**, not the scientific treatment by definition. The primary testable treatment is graph **structural evidence**. Optional synthesizer:
1. Retrieve approved neighborhood/evidence paths and plain source snippets within snapshot.
2. Supply only allowed snippets and typed candidate results to text generator.
3. Ask for a structured profile/explanation, not unconstrained predictions.
4. Check every generated claim against candidate IDs and cited evidence; reject unsourced claims.
5. Store prompt template hash, model ID, token use, temperature, seed if honored, output JSON and validation report.
6. Evaluate deterministic no-LLM mode as an ablation where feasible.

This avoids falsely crediting the graph for information the LLM already memorized.

### 8.5 API of research profiler **[DESIGN]**

~~~text
profile(case_id, mode, config_version) -> ProfileArtifact

mode = baseline | graph_similarity | graph_similarity_llm
ProfileArtifact:
  profile_id, case_id, mode, snapshot_id
  observed_facts[], predicted_facts[], abstentions[]
  supporting_claim_ids[], feature_breakdown[], explanation_paths[]
  code_commit, dataset_manifest_hash, config_hash
  model_or_extractor_versions, warnings[]
~~~

## 9. Experiment and evaluation architecture

### 9.1 Case registry and annotation rules

Each of 4–6 cases includes:
- target (malware family/actor/vulnerability), documented discovery and relevant container context;
- first one/two early source versions, cutoff rationale;
- independent held-out later sources (not automatically all "truth");
- known uncertainty in timeline and independence/syndication;
- proposed later fact labels in ontology vocabulary.

**Annotation protocol [DESIGN]:** Define canonical fact units in advance; label **SUPPORTED**, **CONTRADICTED**, **NOT_ASSESSABLE** and **DUPLICATE/OUT_OF_SCOPE** with exact references. Where feasible, blind the adjudicator to treatment identity. Record disagreements and resolutions. Do not conflate a claim that was unreported later with a false claim.

### 9.2 Paired experiment matrix (**planned experimental methods, not run results**)

| Comparison | Early reports | Historical graph | LLM synthesis | Purpose |
|---|---|---|---|---|
| B0: sparse baseline | Yes | No | No by default | Reference cold-start |
| G1: structural graph | Same | Yes, as-of cutoff | No | Main hypothesis test |
| G2: graph minus syscall/Falco | Same | Yes, features ablated | No | Contribution of runtime features |
| G3: GraphRAG explanation | Same | Yes | Optional | Presentation/LLM-assisted sensitivity |

The primary scientific comparison is **G1 versus B0**, preserving all other extraction and scoring conditions. If B0 and G1 use different extractors/prompts, run a controlled variant to separate graph gains from model gains.

### 9.3 Metrics specification (**planned; no held-out scorer implemented yet**)

Define canonical evaluated facts rather than comparing free-text similarity.

~~~text
TP = distinct proposed facts supported by independent later evidence
FP = distinct proposed facts contradicted by independent later evidence
NA = predicted facts not assessable under reference evidence
FN = later reference facts in scope absent from system profile

assessable_precision = TP / (TP + FP)     # undefined if denominator = 0
reference_recall = TP / (TP + FN)          # requires complete reference labeling
f1 = 2 * precision * recall / (precision + recall) when defined
abstention_rate = abstained_candidate_facts / all_eligible_candidate_facts
net_new_supported = TP_graph_new - TP_baseline_new
paired_delta_recall = recall_G1 - recall_B0
~~~

**Scoring qualifications:**
- In this context some facts with no later mention should be **NA**, not FP, making assessable precision potentially optimistic. Report NA counts and sensitivity treating NA as wrong as a secondary bound where meaningful.
- Distinguish prediction correctness from observed-claim extraction quality. Do not inflate TP by including the facts already in the first two reports; report both full-profile and **newly inferred** breakdowns.
- A later evidence set is generally not a complete list of all true facts. Call the metric **reference recall**, not universal threat-profile recall.
- Extractions are evaluated separately with manually annotated entity and relation precision/recall/F1 and confusion analysis.
- With only 4–6 cases, report per-case paired values, descriptive mean/median, abstention and qualitative failures; do not infer population-level significance without design-appropriate support.

### 9.4 Evaluation outputs

- **case_manifest.json**: source inclusion/exclusion, cutoff, target aliases, revisions.
- **snapshot_manifest.json**: eligible graph, hashes, chosen ATT&CK/Falco revisions.
- **baseline_profile.json**, **graph_profile.json**, **prediction_paths.json**.
- **annotation_set.json** with later sources and manual decisions, restricted from the inference process.
- **metrics.json**: raw numerator/denominator, not just rounded values.
- **experiment_report.md**: per-case tables, examples, ablations, negative outcomes, leakage checks, total spend and threats to validity.
- **run_manifest.json**: Git SHA, environment lock, config SHA, model metadata, timestamps, warnings, case versions.

Exported figures/posters must be reproducible from this run folder.

## 10. Interfaces and UX

### 10.1 CLI surface **[DESIGN]**

~~~text
trg corpus import --manifest datasets/manifests/pilot.yaml --dry-run
trg corpus validate --manifest datasets/manifests/pilot.yaml
trg extract --manifest datasets/manifests/pilot.yaml --engine rules
trg graph build --dataset-version pilot-v1 --backend local
trg experiment snapshot --case case-001 --verify-temporal
trg experiment baseline --case case-001 --run-config config/baseline.yaml
trg experiment graph --case case-001 --run-config config/similarity_v1.yaml
trg experiment evaluate --case-set datasets/cases/pilot.yaml
trg experiment report --run-id <run-id>
trg ops estimate-cost --run-config config/similarity_v1.yaml
~~~

Commands are conceptual; use actual implemented CLI flags from the greenfield repository and update this design when they change. Prefer typed configuration validation, clear exit codes, --dry-run on imports and cloud operations, and output of artifact paths/hashes.

### 10.2 Optional REST read API **[DESIGN]**

Base prefix **/api/v1**, localhost by default. Avoid generic unauthenticated write operations.

| Method / path | Returns | Safeguard |
|---|---|---|
| GET /health | Service and dependency state | No secret details |
| GET /sources | Source metadata and filters | Hide restricted raw content |
| GET /sources/{source_id} | Version/rights/provenance | Safe read |
| GET /entities/{entity_id} | Node + attributable claims | Enforce time/snapshot scopes |
| GET /entities/{entity_id}/neighbors?snapshot_id=... | Typed graph neighborhood | Required snapshot for time-sensitive views |
| GET /cases | Approved case manifests | No gold labels in profiler role |
| GET /cases/{case_id}/profiles?run_id=... | B/G result and prediction caveats | Role separation |
| GET /runs/{run_id} | Frozen run config and integrity metadata | Read only |
| GET /runs/{run_id}/metrics | Scores, denominators, limitations | Evaluator/reviewer role |

OpenAPI/JSON schemas should mirror persisted data contracts. API endpoints must not silently construct full-current graph views for a historical case.

### 10.3 Dashboard **[OPTIONAL]**

If built, provide:
- corpus/source inventory with rights and timestamp confidence;
- case timeline and cutoff display;
- observed vs **provisional predicted** facts in visually distinct styles;
- graph neighbor explorer with evidence drill-down and excluded-future-source diagnostics;
- paired metrics, per-case gains/losses, abstention and leakage audit status;
- export of frozen results to JSON/CSV/PNG/Markdown.

Never show an uncalibrated similarity value as "67% probability". Do not present a hypothesis as an official attribution.

## 11. Security, safety and ethics

### 11.1 Threat model

| Threat | Defense |
|---|---|
| Malicious or prompt-injecting report text | Treat as data; strip/escape tool directives, output schema validation, no source text authority |
| YAML parser gadget or unsafe serialized input | Safe YAML/JSON parsers, disallow Python object tags/exec |
| Poisoned CTI or coordinated report mirroring | Publisher metadata, corroboration discount, source independence review |
| Secrets leaked to repo/model/logs | Local environment secret loading, key rotation, commit secret scan, structured log filtering |
| Leakage of future facts via aliases or cached embeddings | Snapshot rebuild, source/date checks, isolated gold store, temporal adversarial tests |
| URL fetch SSRF/local resource access | Optional collector allowlist, no localhost/private-network fetch, size/time limits, redirect checks |
| API misuse and altered runs | Default localhost, auth for non-local use, least privileges, immutable results |
| AWS unexpected charges | Explicit cloud enablement, IAM least privilege, spending hard caps, service teardown plan |
| Unlicensed publication of reports | Source rights registry; redistribute manifests and links/hashes if full text not licensed |
| Misleading security recommendation | Provisional caveats, human review, no production enforcement |

### 11.2 Secret/data practices

No AWS access keys, OTX API tokens, private source corpora, credentials or real secrets in Git. Support local env/secret-manager injection, .env.example with dummy values, read-only defaults, role separation, and secret scanning in CI. Encrypt cloud artifacts at rest/in transit, apply minimal retention and deletion after pilot, and log run metadata instead of full raw inputs by default.

This research uses public non-classified material. A corpus artifact being public does not automatically confer redistribution rights.

## 12. Runtime, deployment, budget and operations

### 12.1 Local reference deployment (required)

- Python virtual environment with locked dependency versions and explicit OS/Python compatibility.
- SQLite metadata/claim store, local content-addressed artifacts, NetworkX graph projection.
- Unit/integration/evaluation commands run without network in fixture mode; no cloud identity needed.
- Optional process-local API server is not required for batch experiments.
- Scripted start/validate/reproduce/clean commands and backup/checksum validation.

### 12.2 Optional AWS deployment (deferred pending authorization)

~~~mermaid
flowchart LR
  LOCAL["Local CLI/runner"] --> IAM["Scoped temporary AWS identity"]
  IAM --> BR["Bedrock model inference (optional)"]
  IAM --> NP["Neptune Serverless property graph (optional)"]
  IAM --> S3["S3 artifacts (optional)"]
  IAM --> LOG["CloudWatch/API monitoring (optional)"]
  LOCAL --> COST["Local budget policy + alerts"]
  COST -. "explicit approval only" .-> IAM
~~~

- **Bedrock:** opt-in extraction/synthesis only; chosen model and token prices verified before use. Log model version, token count, request failure and billed estimate. No guarantee of historical ignorance.
- **Neptune Serverless:** use an explicit property-graph adapter (openCypher or Gremlin); not RDF/SPARQL for this schema without an intentional migration. Neptune serverless scales compute with a minimum NCU and does **not** mean cost-free idle storage or always-zero running expense. Confirm currently supported engine/region, network/VPC access and IAM design. Use separate development resources and purge when complete.
- **S3:** object versioning/retention, encryption, narrow IAM, report rights; avoid uploading restricted raw reports or outcome labels unnecessarily.
- **CloudWatch/API Gateway/Lambda:** not required merely to produce research results. Add only when there is an accepted operational need.

The proposal's $800 research-expense budget ($350 Bedrock, $225 Neptune compute, $75 Neptune storage/I/O, $25 S3, $75 monitoring/API) is **an estimate**, not verified pricing or authorization. Require live cost calculation, threshold alerts, review of existing billed resources and explicit teardown plan before provisioning.

### 12.3 Observability and run registry

Log per stage: job/run ID, source/case/snapshot ID, durations, counts of accepted/rejected claims, model tokens, estimated service cost, retries, provenance failures, snapshot exclusions and leakage-test pass/fail. Sensitive input text and credentials are omitted from default logs.

Metrics: extraction precision/recall, provenance coverage, orphan claims, graph nodes/edges, distribution of feature families, number of abstentions, per-case scoring, drift in upstream schema and cloud spend.

### 12.4 Recovery and operational safety

- Idempotent artifact creation by hash and transactional ledger updates.
- Quarantined error records with rerun command; failed extractor must not partially publish a graph as validated.
- Local encrypted backup policy if necessary; checksum manifests support recovery.
- Per-run and per-project cost ceilings; terminate or refuse more calls before exceeding a configured hard limit based on estimates (acknowledge costs may settle later).
- Infrastructure is destroyed after experiments unless continued funding and ownership are explicitly agreed.

## 13. Verification plan

### 13.1 Test pyramid and fixtures

| Layer | Examples | Mapped requirements |
|---|---|---|
| Pure unit | Timestamp parsing, canonical ID, type constraints, condition AST, weighted similarity, abstention | FR-04, FR-10–13, FR-20–23 |
| Connector contract | STIX 2.1 fixture, Falco rules/macros, OTX mock, CVE archived metadata, malformed data | FR-01–08 |
| Persistence/integration | Hash roundtrip, append-only revisions, alias collision, graph query provenance | FR-11–18, DR-03–11 |
| Temporal adversarial | Future report, future alias, newer ATT&CK/Falco rule, mirror, embedding from later text | FR-21, EV-08, NFR-03 |
| Research correctness | B0/G1 same inputs, no gold access, same ontology, frozen run reproducibility | FR-19–31, EV-02–10 |
| Security | Parser exploit string, prompt injection, SSRF redirect, secret redaction, cloud spend guard | FR-08, FR-35–36, NFR-05–09 |
| API/UI | Read-only permissions, snapshot-scoped neighborhood, predicted-vs-observed display | FR-33–34, NFR-13, NFR-17 |
| End to end | Clean checkout, run fixture research case, export all manifests/reports offline | AC-01–09 |

**Pass gates:** zero known forbidden temporal edges, 100% provenance coverage among scored claims/predictions (through evidence paths), no actual credentials, all tests passing and reproducible run manifests. Precision/recall performance is measured, **not predetermined as successful**.

### 13.2 Required test fixture stories

1. Two independent early reports + later follow-up: future facts absent from B0 and G1 inputs.
2. Falco shell-in-container rule: syscall/event distinction, rule semantic mapping not actual detection event.
3. CVE edited years later: selected early version includes only originally available facts.
4. ATT&CK technique introduced after cutoff: not eligible historical feature.
5. Malware renamed after cutoff: later alias must not connect historical nodes prematurely.
6. Three syndicated versions of one story: support weight counts correlated evidence only once.
7. Malicious prompt in scraped CTI text: no commands/tools executed, extraction may quarantine.
8. Empty/noisy sparse report: graph abstains rather than fabricates high-confidence facts.
9. Contradicting advisories: both preserved with provenance and scored with uncertainty.
10. Manually adjudicated gold facts: scorer reads outcome partition only after predictions frozen.

### 13.3 CI pipeline — current coverage vs required hardening

**Current CI (`.github/workflows/quality.yml`):** Ubuntu, Python 3.12, pinned `PyYAML`/`pypdf` versions, Python `unittest`, a heuristic import-preflight scan, candidate-manifest validator, local source-artifact audit (zero approved versions), snapshot preview, compilation and CLI help checks. **P0.2 status:** CI now also enforces Ruff's basic error/import rules, detect-secrets tracked-content scanning, pip-audit runtime advisories, pinned parser version checks and cross-platform Ubuntu/Windows tests ([coverage and limitations](P0_SECURITY_GATES.md)). **Still required before formal readiness:** complete formatting/static-type/SBOM review, historical commit secret audit, GitHub required branch protections, OS-specific cryptographic dependency lock, real-source ingestion, derived time-leak adversarial tests and evaluator outcome isolation. Nothing invokes AWS in normal CI.

## 14. Requirement-to-design traceability

| SRS IDs | Primary design locations | Evidence expected |
|---|---|---|
| RC-01–04, FR-01–08 | §§4, 6, 11 | Source manifests + adapter contracts |
| FR-09–18, DR-01–11 | §§5–6 | Ontology, claim ledger, extraction schema |
| RC-05–06, FR-21, EV-08, NFR-03 | §7 | Snapshot builder + leakage regression |
| FR-19–26, EV-02–07 | §8 | Baseline/G1 algorithms + grounded artifacts |
| FR-27–31, EV-01–10 | §9 | Case registry, annotations, paired metrics |
| FR-32–34 | §10 | CLI/API/dashboard contracts |
| FR-35–36, NFR-05–09, 14, 17–19 | §§11–12 | Threat model + budget guards |
| NFR-01–04, 10–13, 16, 20 | §§5, 9, 12–13 | Reproducibility, provenance and CI |
| AC-01–09 | §§9, 13, 15 | Research readiness/release gates |

## 15. Greenfield implementation sequence and dependency-gated exit criteria

**Detailed authoritative execution checklist:** [BUILD_PLAN](BUILD_PLAN.md), `TRG-PLAN-001 v0.2.0`. Do **not** mistake architectural *design presence* for an accepted implementation, or a passing synthetic test for a genuine historically valid research result.

| Milestone | As-built state (2026-10-10) | Work and gate still required |
|---|---|---|
| **M0 — Greenfield repo baseline** | Initial repository, docs, Python components and CI are present. A separate local prototype **never existed**. | P0 CI/dependency hardening and an honest FR/DR/NFR code+test matrix; **no import task** |
| **M1 — Historical corpus** | 17 **unapproved** source URL candidates, empty case registry, source metadata/hash tools. | P1: independently verify rights, exact original bytes and historic availability; first one real development case, then 25–40 approved sources and 4–6 cases / reviewed deviation; AC-01 |
| **M2 — Extraction/evidence graph** | Synthetic-tested parsers, evidence alignment, SQLite sourced claim ledger and self-declared review gates. | P2: real source → typed candidate extractor/adapters, historized aliases, full coverage/independent annotations and precision/recall; AC-02/03 |
| **M3 — As-of safety** | Deterministic source-level snapshots, case role allowlist and digest-bound graph views. | P3: independent case cutoff validation; feature/alias/taxonomy/decision-level reconstruction, gold-store isolation, strict adversarial leakage tests; AC-04 |
| **M4 — B0 baseline** | Deterministic early-source report-assertion profile with abstention; synthetic tests. | P4: run from approved cases using same extracted/reviewed early inputs as G1; freeze output/run provenance |
| **M5 — G1 similarity** | **Not implemented**, [#21](https://github.com/FardinSamin/ThreatRAGraph/issues/21). | P4: historically eligible neighbor ranker, weighted feature provenance, independence/correlation discount, versioned provisional hypotheses, abstention; no LLM required |
| **M6 — Evaluator** | **Not implemented**. | P5: frozen paired B0/G1 outputs and independently adjudicated held-out facts, metrics incl. NA, extraction F1, per-case/ablation and leakage report; AC-05/06 |
| **M7 — Reporting/release** | Research outline/design only. | P6: clean-room offline reproducibility, mentor approval, rights/ethics, negative-result reporting and symposium outputs; AC-07–09 |

**Immediate build priority:** P0 hardening + P1a one-real-case evidence validation, while the independent M5 ranking algorithm is developed against synthetic fixtures. Do **not** delay all real source verification until after synthetic G1 is coded. It is appropriate to defer *empirical G1 claims*, not to defer the actual dataset indefinitely.

### Definition of Done / stop-the-line acceptance for each PR

1. Declare issue, requirement IDs, exact data/schema boundaries, expected behavior, non-goals and evidence of need.
2. Add positive, negative, corrupt, time-travel, provenance and deterministic tests appropriate to the component. No future/held-out feature or label may reach B0 or G1.
3. Verify source bytes, source version, date, permitted use and manual decisions using separate gates; claims and predictions must never share asserted-truth status.
4. Run CI on **final PR head**, including security/dependency scans when available; document unimplemented scans instead of pretending they passed.
5. For scientific output, require P1b/P2/P3 signoffs, frozen early inputs, isolated reference labels, denominator-bearing scoring and independently reviewable run hashes.
6. Update SRS/SDD/build plan/implementation matrix where relevant and leave one clearly scoped next action. No AWS resources or paid APIs without explicit budget authorization.

**Stop immediately on:** post-cutoff source/alias/taxonomy/embedding leakage, unknown chronology called verified, later labels exposed before prediction freeze, forged evidence promoted to fact, incompatible B0/G1 early inputs, unreviewed claims scored, secrets/raw restricted content in Git, or unauthorized cloud expense.

## 16. Open technical decisions / follow-up ADRs

| TBD (from SRS) | Resolution process / default |
|---|---|
| TBD-01 project origin (resolved) | Greenfield repository; audit only code actually committed here, not a nonexistent pre-existing prototype |
| TBD-02 corpus rights | Review source-by-source terms; avoid restricted raw payloads in Git |
| TBD-03 historical cases | Mentor-reviewed inclusion criteria and frozen cutoff/held-out manifests |
| TBD-04 OTX | API mock first; validate quotas and access permission |
| TBD-05 extractor | Benchmark rule-only and optional model modes; account for model leakage and prices |
| TBD-06 graph backend | Continue SQLite/source-linked graph JSON locally; FTS5/NetworkX/Neptune are optional until justified by tests |
| TBD-07 similarity | Freeze interpretable weighted-family baseline and development-only tuning |
| TBD-08 annotation | Written labeling rubric, source references and disagreement log |
| TBD-09 auth/hosting | Local-only initially; threat-model expansion before external exposure |
| TBD-10 scheduling | Confirm research calendar and funding prior to cloud commitment |
| TBD-11 publication | Choose license only after ownership/data-rights review |
| TBD-12 conflicting later evidence | Supported/contradicted/not-assessable with reference provenance; sensitivity analysis |

## 17. External references and document governance

**Research authority:** Investigator-supplied *URFS_Proposal_Fardin_Samin.pdf*, pp. 1–6 (not yet committed).

**Normative format and implementation references:**
- OASIS STIX 2.1: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- MITRE ATT&CK versioned STIX 2.1 releases: https://github.com/mitre-attack/attack-stix-data
- Falco rule definitions: https://falco.org/docs/concepts/rules/basic-elements/
- Falco event/syscall fields: https://falco.org/docs/rules/supported-fields/
- Kubernetes docs: https://kubernetes.io/docs/
- Neptune graph languages (Gremlin/openCypher for property graphs, SPARQL for RDF): https://docs.aws.amazon.com/neptune/latest/userguide/access-graph-queries.html
- Neptune Serverless scaling/capacity: https://docs.aws.amazon.com/neptune/latest/userguide/neptune-serverless-capacity-scaling.html
- STIX/Python optional library: https://stix2.readthedocs.io/

**Change control:** Any architecture change that affects a requirement should carry a change to docs/SRS.md, this document, related ADR (when material), appropriate schema examples and tests. Keep **proposal intent**, **chosen design**, and **verified implementation** clearly separated. Quantitative findings belong in immutable evaluation runs, not speculative README statements.

## Appendix A. Explicit SRS identifier coverage

The ranges in §14 are summarized below with every individual SRS identifier spelled out for searchable, machine-auditable traceability. A design location does **not** mean the corresponding requirement has been implemented or tested.

| SRS requirements (all IDs) | Design location |
|---|---|
| RC-01, RC-02, RC-03, RC-04 | §§4, 6 — corpus, sourcing, provenance |
| RC-05, RC-06 | §§7, 9 — time gating and outcome isolation |
| RC-07 | §9 — research-claim limitations |
| FR-01, FR-02, FR-03, FR-04, FR-05, FR-06, FR-07, FR-08 | §§4, 6 — collection and normalization |
| FR-09, FR-10, FR-11, FR-12, FR-13, FR-14, FR-15, FR-16, FR-17, FR-18 | §§5–6 — extraction and graph |
| FR-19, FR-20, FR-21, FR-22, FR-23, FR-24, FR-25, FR-26 | §§7–8 — profiles, similarity and GraphRAG |
| FR-27, FR-28, FR-29, FR-30, FR-31 | §9 — evaluation and reproducibility |
| FR-32, FR-33, FR-34 | §10 — CLI, API and optional dashboard |
| FR-35, FR-36 | §§11–12 — cloud limits and safe input |
| DR-01, DR-02, DR-03, DR-04, DR-05, DR-06, DR-07, DR-08, DR-09, DR-10, DR-11 | §5 — ontology and evidence records |
| NFR-01, NFR-02, NFR-03, NFR-04 | §§5, 7, 13 — reproducibility, provenance, temporal integrity |
| NFR-05, NFR-06, NFR-07, NFR-08, NFR-09 | §§11–13 — security, local execution and recovery |
| NFR-10, NFR-11, NFR-12, NFR-13 | §§8, 10, 12–13 — latency targets and uncertainty |
| NFR-14, NFR-15, NFR-16, NFR-17, NFR-18, NFR-19, NFR-20 | §§9, 11–13 — ethics, controls and measured output |
| EV-01, EV-02, EV-03, EV-04, EV-05, EV-06, EV-07, EV-08, EV-09, EV-10 | §9 — research scoring, validity and ablations |
| AC-01, AC-02, AC-03, AC-04, AC-05, AC-06, AC-07, AC-08, AC-09 | §§13, 15 — test and milestone exit gates |


## 18. As-built module inventory and architecture delta (2026-10-10)

This section makes **actual implementation** distinguishable from diagrams and example schemas. Paths have been inspected in the repository, and existing synthetic tests have been observed in prior CI runs; no genuine historical dataset has yet validated these components.

| Actual file / interface | Present behavior | Do **not** infer | Follow-up work |
|---|---|---|---|
| `datasets/manifests/pilot.json` and `datasets/cases/pilot.json` | 17 candidate URLs; empty case list | Approved archives, documented cutoffs or ground-truth labels | P1 source/date/rights and case review |
| `scripts/validate_research_manifests.py` | Metadata schema, uniqueness, partition/chronology guard | That any URL was archived at a valid historic version | Curator signoff and real-data tests |
| `scripts/audit_source_artifacts.py` | Local archived-byte SHA-256 verification | Historical publishing date, license rights or independent publisher corroboration | P1 evidence register and rights policy |
| `src/threatragraph/normalized_sources.py` | Bounded, versioned visible HTML and Falco YAML parsing | General unstructured CTI relation extraction, full macro execution or observed incidents | P2 adapters and typed candidate extractor |
| `src/threatragraph/pdf_sources.py` and `evidence_alignment.py` | Versioned evidence locators, exact byte/quote checks for supported content | OCR, visual PDF truth, claim semantics or publisher reliability | P2 normalizer QA and evidence adjudication |
| `src/threatragraph/evidence_graph.py` | SQLite approved source-version and typed sourced-claim ledger; B0/G1 projection by source ID | STIX full ontology, NetworkX/Neptune graph backend, time-valid aliases or future-free semantic model | P2 identity lineage, P3 as-of rebuilding |
| `src/threatragraph/semantic_reviews.py` | Self-declared one-review-per-claim binding to claim/source/evidence | Authenticated expert agreement, blinded annotations or independent later reference truth | P2/P5 annotation governance |
| `scripts/freeze_case_snapshots.py` | Deterministic B0/G1 **source lists** and optional artifact freeze when metadata/bytes pass | Graph feature/alias/taxonomy historical provenance or validity of declaration timestamps | P3 full snapshot / process boundary |
| `scripts/project_case_graph.py` | Offline reviewed attributed claims → source-scoped graph JSON, strict pilot count rules | Automated extraction or empirical readiness from a synthetic count-matching manifest | P0 readiness semantics, P2 real ingestion |
| `src/threatragraph/baseline_b0.py` and `scripts/profile_b0.py` | Isolated early-only reviewed-source assertions + abstention; no inference or invented probability | New fact prediction, case-level research benefit or strict-source approval from JSON alone | P4 pair with G1 on frozen real case |
| M5/M6 | Design/issue only | A functioning similarity engine, reranker, gold-label scorer or measured research outcomes | P4/P5 |

### 18.1 Actual data boundaries versus future target schemas

**M1 source versions:** Manifest metadata contains `source_version_id`, `status` (`candidate`/`approved`), `sha256`, `available_at`, versioned independent dating fields and origin/licensing rationale; original bytes are stored in ignored local content-addressed archive paths. Current pilot contains no approved records. Audit checks source **identity**, not release timing.

**M2 source claim:** `EvidenceGraph.append_source_claim` records a canonical `claim:<64-hex>`, subject/predicate/object, `assertion_kind` (`report_assertion` or `rule_semantics`), polarity, source-version ID, evidence locator/digest and extractor version. The database tracks byte alignment, and `semantic_reviews.py` holds a **separate** reviewer assertion. It is not a single STIX-standard graph object and does not imply publisher truth.

**M3:** `case_views` emits `B0_sparse_report_only` with early sources and `G1_early_plus_historical_background` with the **same** early sources plus eligible background IDs. Both have an explicitly incomplete historical trust boundary until aliases, taxonomies, claim/feature provenance and label-store isolation are implemented.

**M4:** `baseline_b0.py` emits only source-asserted, reviewer-supported target triples in `facts[]` and an intentionally empty `predictions[]`, with abstention and `confidence=null`. Its `research_ready` field is based on supplied structural conditions, **not faculty or historical source approval**, and must be corrected before production study claims.

**M5 [DESIGN ONLY]:** A future `G1Prediction` must be stored separately from ``sourced_claims`; its versioned schema needs candidate triple, uncalibrated ranking score, feature-family contributions, source-verified historical path(s), independence/correlation discount, abstention, cutoff/snapshot and code/config/run hashes. Neither G1 nor an LLM inference workflow exists at this revision.

### 18.2 Contamination and access architecture to implement

~~~mermaid
flowchart LR
  M1["Historically archived approved source versions"] --> GATE["Verify source/date/rights"]
  GATE --> X["Bounded parser + extractor + evidence reviewer"]
  X --> C["Case-local as-of claim/alias/taxonomy view"]
  C --> B0["B0: early reviewed source facts"]
  C --> G1["G1: early facts + eligible background similarity"]
  B0 --> FREEZE["Immutable early profiles + proposed predictions"]
  G1 --> FREEZE
  FUT["Later reference facts and annotation set"] --> EVAL["Separate evaluator process"]
  FREEZE --> EVAL
  EVAL --> REPORT["Paired metrics, negative outcomes, audit"]
~~~

**Trust boundary:**
- `FUT` must never be readable by `GATE`, `X`, `C`, `B0` or `G1`, **including via file paths, environment, shared embeddings, taxonomy revisions, reviewer caches or permissive database connections**.
- The arrows involving `X`, full `C` reconstruction, `G1`, `FREEZE` and `EVAL` represent **unfinished** implementation.
- A process/file-access regression and a zero-future-provenance assertion must pass before the diagram is claimed as built.

## 19. SDD design-change and verification contract

- **Single codebase:** Extend these existing modules in GitHub; the now-closed old issue #1 reflected an incorrect premise that an independent local prototype existed. Do not reopen it as a dependency.
- **Source hierarchy:** Preserve the original study question, scale, and cyberthreat focus in the SRS; source/version/chronology approvals and restrictions override convenient engineering shortcuts.
- **Schema compatibility:** P0.3 introduces [v1 source-view/graph contracts and SQLite legacy migration refusal](P0_SCHEMA_CONTRACTS.md). The new controls check versioned output shapes and stored columns but not every SQL index/constraint, actual evidence-byte authenticity, or complete future inference schema.
- **No fabricated empirical approval:** P0.1 graph and B0 structural outputs now always report `research_ready=false`; successful `--strict`/`--require-all` is still **not** proof that a real pilot is eligible. Require documented independent source/case approval plus P1–P5 gates and separate empirical acceptance before research claims ([P0 readiness contract](P0_READINESS_CONTRACT.md)).
- **Implementation workflow:** PRs include requirement mapping, schema compatibility, positive + adversarial + offline tests, exact SHA and code review, update to [BUILD_PLAN](BUILD_PLAN.md) status, and researcher-facing reproducibility commands.
- **Architecture controls:** Optional FTS5, NetworkX, FastAPI, embeddings, AWS Bedrock/Neptune and LLM generation remain **design choices**, not prerequisites. The primary experimental comparison is deterministic G1 **structural similarity versus B0**, with no LLM.
- **Future review:** Track deviations as ADRs, update controlled SRS requirements first and SDD implementation evidence in the same PR. Close a milestone only when its declared **real evidence gate** is met, not when a synthetic scaffold merges.
