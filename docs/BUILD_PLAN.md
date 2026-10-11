# ThreatRAGraph — Controlled Build and Research Execution Plan

**Plan ID:** TRG-PLAN-001 | **Version:** 0.2.0 | **Updated:** 2026-10-10  
**Authority:** [SRS](SRS.md) (what must be proven), [SDD](SDD.md) (how), this plan (implementation sequence and exit gates)  
**Project origin:** Greenfield. **The GitHub repository is the entire project**; there is no prior local Python prototype to import.  
**Status:** Execution plan; not a claim that all stages are already implemented, approved, tested with real evidence, or empirically effective.

## 1. Mission and success condition

Research question: can **historically available** graph-structural similarity produce a more useful **provisional** profile for a newly emerging container/Kubernetes threat than a report-only baseline seeing the **same first one or two public reports**?

**Success is not just a working app or more generated facts.** It means: a reproducible, paired B0-versus-G1 comparison on 4–6 explicitly chosen historical cases from an approved, diverse approximately 25–40-source pilot; correctly scoped chronology; provenance-backed observations; distinct, explainable hypotheses; independent later reference assessment; uncertainty, errors and negative results reported. A null or negative finding is a legitimate research result.

**Scope boundary:** Single-investigator, offline-first Python research system. No operational SOC detection, automatic remediation, exploit execution, uncontrolled scanning, AWS requirement, or promises of predictive accuracy. An optional readable report or dashboard is secondary to scientific validity.

## 2. Verified status on this planning revision

| Area | Evidence in repository | Status | Not yet established |
|---|---|---|---|
| SRS, SDD, security defaults and CI | `docs/SRS.md`, `docs/SDD.md`, `.github/workflows/quality.yml` | Draft + CI present | Faculty signoff, clean Windows setup and comprehensive CI security checks |
| M1 source registry / chronology | `datasets/manifests/pilot.json`, `scripts/validate_research_manifests.py` | 30 **candidate** entries, including a signed original runc Git tag verified against the release-era keyring and an original GHSA JSON tied to a retained pre-cutoff public push event | **0 approved** real source versions, exact archived bytes and verified public-availability times |
| M1 case design | `datasets/cases/pilot.json`, `docs/research/M1_CASE_CANDIDATES.md` | Candidate research shortlist | **0 selected/approved** real historical case manifests; no frozen reference labels |
| M1 archive audit | `scripts/audit_source_artifacts.py` | Synthetic-tested SHA-256 integrity checking | Approved real archives and evidence of licensing/public availability |
| M2 parser / evidence foundation | `src/threatragraph/normalized_sources.py`, `pdf_sources.py`, `evidence_alignment.py`, `ghsa_candidates.py` | Synthetic-tested normalization/citations plus conservative GHSA 1.4.0 CVE-to-Go-package review candidates only | Full free-text/STIX extraction, multi-field reviewed ledger claims, real extraction quality, OCR, complete Falco semantics |
| M2 graph and review | `src/threatragraph/evidence_graph.py`, `semantic_reviews.py`, new `compound_claims.py` and `scripts/project_compound_case.py` | Synthetic-tested v1 ledger plus opt-in SHA-bound dual-field GHSA compound source claims, manual review, cutoff-filtered separate output | Historic source approval, full alias/ontology as-of reconstruction, authentic reviewer identity, G1-v2 ranker schema integration, real annotation/independent agreement |
| M3 historical inputs | `scripts/freeze_case_snapshots.py` | Deterministic source-level B0/G1 input splits + hash controls | **Full claim/alias/taxonomy/feature-level as-of proof**, approved snapshots for real cases |
| M4 B0 | `src/threatragraph/baseline_b0.py`, `scripts/profile_b0.py` | Deterministic report-only claims, provenance and abstention on synthetic fixtures | Real baselines/paired-case run manifests and measured outcomes |
| M5 G1 | [Issue #21](https://github.com/FardinSamin/ThreatRAGraph/issues/21) | **Partially implemented** v2 typed Jaccard ranker with mandatory, self-declared claim-level exact-only as-of lineage, B0/G1 parity, separate provisional paths, abstention (synthetic tests only) | Genuine vetted corpus, derived as-of aliases/taxonomy/features and independent case-level efficacy; see [M5 algorithm limits](M5_G1_SIMILARITY.md) |
| M6/M7 | Design documentation | Planned | Gold-label evaluator, paired scores, ablations, paper/poster |

PR #36 CI ran **270 synthetic-focused tests on Ubuntu and Windows** (three Windows symlink skips), with security checks and genuine original-tag verification. Passing tests are **software evidence**, not historical research validation; verify the latest head for any new result.

**P0.1 corrective implementation:** The graph runner and B0 baseline now return `research_ready: false` even after successful strict structural checks. An explicit `readiness` disclosure reports `validation_mode`, `structural_checks_passed` and `independent_study_approval=not_verified`. This **does not** approve data or complete P0; a separately reviewed, auditable study-approval gate remains pending (see [P0 readiness contract](P0_READINESS_CONTRACT.md)).

## 3. Immutable safety invariants — never negotiate these away

**INV-01 / Historical availability:** For every case cutoff, each feature, source version, parsed revision, accepted claim, alias, taxonomy/rule, similarity neighbor and explanation path must have independently evidenced availability no later than that cutoff. Unknown dates are **ineligible**, not early.

**INV-02 / Reference isolation:** Held-out later sources, answer keys and annotation decisions are accessible to the evaluator **only after** predictions are frozen. Never load them into an extractor context, canonicalizer, graph, embedding/index, G1 neighborhood, B0 input or tuning loop.

**INV-03 / Common early input:** B0 and G1 consume exactly the same first 1–2 report versions, extractor output, ontology/normalization and source review status. G1's **sole primary treatment difference** is eligible background structure.

**INV-04 / Citation meaning:** Exact SHA-256 citation alignment ≠ interpreted relation correctness ≠ factual truth. Source-asserted facts, rule semantics, reviewer decisions, novel hypotheses and later outcome labels must remain separate record types.

**INV-05 / Claim-to-source path:** Each scored observed claim must be traceable to its original approved source bytes, source version/time, quote locator and review. Each provisional inference must show all time-valid historical supporting source paths; no source means no prediction.

**INV-06 / Abstention and honesty:** Ambiguous, unsupported, contradictory, unreviewed, unscorable or insufficiently sourced data yields abstention or `not_assessable`, never manufactured positive claims or silently imputed negatives. Similarity scores are **ranking heuristics**, not probabilities.

**INV-07 / Reproducibility:** Every experimental result records repository commit, Python/dependency lock, configuration, ontology/extractor versions, cutoff, source manifest + bytes hashes, claim/graph snapshot IDs, reviewer set, case set and output digests.

**INV-08 / Safe, local default:** No AWS, paid API, live scanning, execution of untrusted snippets, secrets in repo, redistribution of restricted report bodies, or non-reviewable automated data downloads by default.

**INV-09 / Fail closed:** An incomplete corpus, invalid locator, unknown source rights/time, unsupported format, unsafe YAML/PDF, broken review provenance, future alias or contaminated candidate **blocks** the scored experiment. Dry-run diagnostics and synthetic development mode may continue if loudly labeled.

**INV-10 / No false readiness:** Dataset count checks, unit-test passes or a `research_ready` field alone are not scientific approval. A separate, human-reviewed acceptance record must certify actual source selection, cutoff chronology, isolation and extraction/evaluation scope.

## 4. Execution order and dependency graph

~~~mermaid
flowchart TD
  P0["P0: Engineering audit + strictness fixes"] --> P1["P1: Curate one historically valid vertical slice"]
  P1 --> P2["P2: Ingest + extract reviewed real source claims"]
  P2 --> P3["P3: Rebuild true as-of graphs and freezes"]
  P3 --> P4["P4: Paired B0 / G1 run + separate ranker"]
  P4 --> P5["P5: Independent label + quantitative evaluation"]
  P5 --> P6["P6: Reproduction, faculty review, research outputs"]
  G1["M5: G1 algorithm with synthetic fixtures"] --> P4
  P0 --> G1
  P1 --> FULL["Scale to 25–40 approved sources / 4–6 cases"]
  FULL --> P5
~~~

**Critical-path rule:** The real-data vertical slice and M5 synthetic engine may advance **in parallel**, but neither alone is an experiment. Never let many more synthetic-only modules substitute for an actual approved end-to-end case.

## 5. Work packages with measurable exit gates

### P0 — Stabilize the greenfield repo and close known correctness gaps

**Target:** Reproducible checkout plus a trustworthy machine-checkable implementation inventory.

**Do**
- Add and keep updated `docs/IMPLEMENTATION_STATUS.md` (requirement ID → actual code path → test name → status: implemented / partial / missing / design only). Distinguish *parser*, *extractor*, *graph*, *historical reconstruction*, *baseline* and *experiment*.
- Run tests/CI in clean Python 3.12 on Linux and representative Windows PowerShell; record commit, OS and exact versions. Maintain `pip` constraints/lock or reproducible wheel versions (version pin alone is not a fully locked environment).
- **Partially implemented in P0.2:** Ruff basic import/error lint, detect-secrets tracked-content scan, pip-audit runtime advisory checks, and runtime version pin validation. See [P0 security gates](P0_SECURITY_GATES.md). **Still missing:** full formatting/type checks, historical Git secret scan, wheel-hash locking and required GitHub branch protections; existing preflight remains heuristic.
- **Done in P0.1:** Fix misleading `research_ready` semantics: structural gates now always disclose unverified independent study approval. **Still needed:** authenticated/protocol-reviewed empirical readiness gate once data exists; never infer corpus approval from `--require-all` or synthetic fixtures.
- **Partially implemented in P0.3:** exact version-1 historical source-view and graph projection contracts at graph/B0 integration boundaries, plus SQLite ledger/reviewer table compatibility validation and no silent evidence-status migration. See [P0 schema contracts](P0_SCHEMA_CONTRACTS.md). **Remaining:** complete machine-checkable `SourceVersion`, `Claim`, `Review`, `B0Profile`, future `G1Prediction` and `RunManifest` output schemas, full SQLite index/check/foreign-key verification and explicit version-migration testing.
- Add an ADR for source-version identity, deterministic corpus freezing and the eventual label-store access boundary.

**Exit gate P0:** Fresh clone + documented install passes all tests on supported platforms; CI must fail on a deliberate invalid future source, unsupported source hash and malformed reviewed claim; implementation matrix has no invented feature claims; branch protection and approval policy documented.

**Evidence:** CI run links, command log, status matrix, dependency lock and signed-off ADRs.

### P1 — Curate a genuinely historical vertical slice, then freeze the full pilot (M1)

**Target:** One **clearly marked development-only** real-world mini-case first; grow to 25–40 approved versions and 4–6 independent case studies only when the protocol works.

**Do**
- Pre-register case inclusion/exclusion criteria *before* looking at whether G1 can predict the later answer. Shortlist candidates independently of method performance; record rejected cases. **Gate target/method compatibility first:** existing CVE/vulnerability case units are unsupported by G1 v2; see [P1a case–method eligibility](research/P1A_CASE_METHOD_ELIGIBILITY.md). [P1b SCARLETEEL](research/P1B_SCARLETEEL_CAMPAIGN_SCREEN.md) screens a genuine named campaign and a tentative early `USES` feature. [P1b same-type peer follow-up](research/P1B_SCARLETEEL_CAMPAIGN_PEERS.md) adds 2021 Chimaera and 2022 Kiss-a-dog **source-named XMRig campaign peers**. [Chimaera original-URL chronology follow-up](research/P1B_CHIMAERA_HISTORICAL_BIBLIOGRAPHY.md) additionally pins **two historical 2021/2022 Git bibliography references** and replays their exact bytes in CI. The [original MITRE ATT&CK v12.1 STIX file witness](research/P1B_MITRE_ORIGINAL_TEAMTNT_2022.md) now verifies publisher-owned 2022 **TeamTNT intrusion-set data**, including the Chimaera 2020-label/2021-citation conflict; that is **not** an authenticated 2021 campaign report or an extra independent behavior claim. The [Common Crawl original HTML candidate intake](research/P1B_COMMONCRAWL_PRIMARY_WARC_INTAKE.md) now verifies offline CDX/WARC byte range integrity and cutoff claims without approving any sources. [P1d GH Archive independently recorded December 23 2022 public PushEvent](research/P1D_KISSADOG_PUBLIC_PUSH_WITNESS.md) now joins the real archived public event, Securonix historic Git commit and both source-file blobs, giving a defensible public-by observation for a **secondary reference pointer only**, NOT for the original Cado article body or a reviewer-approved behavior claim. [P1c Cado/CrowdStrike single-peer campaign path](research/P1C_KISSADOG_SAME_PEER_CHAIN.md) identifies two original **Kiss-a-dog** investigation lineages (CrowdStrike Docker and Cado own Redis honeypot) and a candidate **XMRig shared feature → XHide additional relation** with 2 prospectively declared groups on *one peer*. The original article versions remain unapproved and XHide is **not** a proven SCARLETEEL prediction. **No primary publisher page has been actually acquired or authenticated**, and G1 lacks two independent groups *per peer's proposed candidate relation*. Still **unapproved and G1-ineligible**; blinded later labels also remain missing. Do not relabel CVEs as malware or accept trivial component overlap.
- For each source, capture canonical URL, publisher/type, stable version ID, permissible exact archived bytes, SHA-256, licensing/retention constraints, `published_at`, independently supported earliest `available_at` (UTC), acquisition date, confidence and independence/syndication group.
- Use actual archived revision (vendor version history, date-stamped release or defensible archival evidence); a web page's present-day publication label, content hash, today's last-modified header or filename **does not prove prior public availability**.
- Document primary early 1–2 reports, historical cutoff, background sources known then, and independent later references for each case. Maintain reference annotations separately and blinded from the profiler.
- Include actual historical ATT&CK/STIX revisions and Falco rule/version availability; fail or exclude if no defensible old revision exists. Do not mislabel modern data as historical.
- Run `validate_research_manifests.py --strict`, `audit_source_artifacts.py --require-all`, duplicate/syndication audit, rights review and manual date-evidence spot checks. These checks complement, **not replace**, independent research review.

**Exit gate P1a (mini-slice):** At least one documented real case with 1–2 approved early sources, legitimate dated background, later reference isolated, rights clear, exact bytes/hash verified and an investigator-reviewed cutoff; mini-slice is explicitly **not full study-ready**.

**Exit gate P1b (full):** Approximately 25–40 approved source versions, 4–6 distinct defensible cases (or faculty-approved deviation), complete inclusion/exclusion records, verified source bytes and chronology, rights and independence decisions; all required manifest validations and review signed off. **No count-only pass.**

**Evidence:** Frozen `datasets/manifests/*` and `datasets/cases/*`, source audit JSON, rights/date evidence register, exclusion log, approval metadata (private archives stay ignored by Git).

### P2 — Real extractor, entity identity, evidence alignment and human review (M2)

**Target:** A real, reproducible `source bytes → parsed/normalized segments → candidate typed claims → reviewed graph` pipeline.

**Do**
- Implement deterministic, versioned STIX object/relationship adapters, CVE/advisory revisions and Falco rule-field extraction first. **The GHSA 1.4 scoped adapter now also has an authentic pinned original-source CI replay** ([P1a real candidate replay](research/P1A_GHSA_LIVE_REPLAY.md)); this proves exact byte-and-field processing only, not approved research or full extraction quality. **Initial partial GHSA 1.4.0 Go-package candidate adapter exists** (see [M2 GHSA review candidates](M2_GHSA_CANDIDATES.md)); it produces two-field review queue entries only, not approved ledger claims or free-text relationships. Use `evidence_alignment.py`, `normalized_sources.py` and `pdf_sources.py` to validate locators; recognize that these modules **do not currently produce arbitrary CTI relationship candidates from prose**.
- Add a conservative free-text candidate extractor for the chosen reports, initially explicit rules/structured templates; unresolved prose remains unreviewed. Any optional LLM adapter must be isolated, opt-in, budgeted and disclosed as potentially pretrained on future events.
- Implement source-grounded entity identity resolution: stable STIX/ATT&CK/CVE IDs, type-safe aliases with first-evidenced timestamps, explicit review for fuzzy merges, versioned ontology and reversible/recorded decisions. Avoid retroactively importing future aliases.
- Distinguish benign syscall and Falco detection logic from **incident observation**. Reject unverifiable rule-to-attack execution claims.
- Validate source/quote hashes and semantically review candidate claims using a written rubric; preserve uncertain/negative/contradictory decisions. **GHSA candidate-only compound review packets now support two field hashes and a separate self-declared append-only review store**, but they never enter the approved source-claim ledger; see [M2 compound review boundary](M2_GHSA_COMPOUND_REVIEW.md). Record independent annotation where possible, inter-reviewer disagreement and adjudication.
- Build actual extraction quality labels, split by document/case independence, and measure entity + relation precision/recall/F1 **with denominators and error categories**. Do not tune on held-out evaluation references.

**Exit gate P2:** One real mini-case imports end to end offline; every promoted claim has verified bytes, typed endpoints, a source/version and a reviewer decision. Demonstrate at least one intentionally rejected fabricated citation, false Falco incident inference, future alias and incompatible relation. Extraction precision/recall/F1 is **measured and reported**, not guaranteed to meet a fabricated threshold.

**Evidence:** Versioned extraction outputs, audit/quarantine records, annotation files, errors/metrics, snapshot-local entity map and CI fixtures.

### P3 — Actual historical reconstruction, beyond source-level allowlists (M3)

**Target:** As-of graph truthfulness at **every derived layer**, not just the source list.

**Do**
- Rebuild eligible claims/edges **from scratch per case**; enforce `available_at <= cutoff` for source, taxonomy, rule, accepted claim review/decision, aliases and derived feature. Do not build a modern graph once and hide future nodes afterward.
- Maintain historized canonicalization/merge decisions. Exclude modern STIX/ATT&CK/Falco/CVE labels added after cutoff unless a **constant ontology** is transparently applied identically to B0 and G1 without leaking novel facts.
- Exclude target-specific copies, near-duplicates and later target reports as background neighbors; hash-identical detection alone does not find rewritten syndication.
- Keep source text, embedding/index (if later added), source aliases and feature/degree counts snapshot-local; a full-corpus feature index can leak even when retrieved results are filtered.
- Materialize B0 and G1 *sealed inputs* with exact early source IDs/hashes, permitted background graph checksum, allowed alias/taxonomy decisions, excluded IDs/reasons, extractor versions, artifact/schema hashes.
- Separate evaluator/reference storage, process and credentials/config from profilers; add a test proving the profile subprocess cannot read evaluation labels.

**Exit gate P3:** Adversarial replay of future report, later alias, new ATT&CK technique, updated Falco rule, mirrored story, future-adjudicated merge, cached future embedding, reference-label contamination and unknown-date source results in rejection/no-leak. The same early evidence is hashed identically in B0 and G1.

**Evidence:** Per-case input manifests + SHA-256, as-of graph checksums, exclusion log, negative tests and researcher signoff. Current M3 implementation meets **only the source-level subset**.

### P4 — Freeze B0, implement G1 and run a paired development comparison (M4 + M5)

**Target:** A transparent, **separate** graph-similarity ranker and provisional candidate artifact, compared to already implemented B0 on identical early target facts.

**Do**
- Reuse `baseline_b0.py` rather than writing a second baseline. Assert its inputs are M3-eligible, byte-aligned and semantically reviewed. If reference eligibility is unclear, abstain.
- Implement G1 against the **sealed snapshot**: type-compatible historical neighbor entities, comparable feature families (technique/component/behavior/syscall/rule conditions), weighted Jaccard or equally transparent frozen method, explicit path-level historical provenance, independent-source discount and deterministic tie-breakers.
- Restrict eligible analogy candidates to **historically known non-target entities**, with post-cutoff and target-mirror exclusions. Do not propagate actor attribution, exploit success, malicious intent or runtime occurrence merely from shared generic syscall features.
- Propose only **new, ontology-valid target relations** absent from early observations. Keep them in a distinct `Prediction` schema/plane, not `sourced_claims`. Include feature-weight contributions, source and graph paths, reviewer/normalizer status, uncalibrated ranking score and abstention reason.
- Predeclare top-k, family weights, minimum independent corroboration, ranking/abstention thresholds on development cases. If there are too few independent cases to tune, use clearly fixed exploratory defaults and report sensitivity without claiming optimization.
- Build paired B0/G1 runner that records input parity before allowing output comparison. Freeze both profiles and run hashes **before** evaluator can access later outcomes.

**Exit gate P4a:** Synthetic G1 fixtures demonstrate explainable similarities, 0 known temporal leaks, provenance, abstention, contradiction, independent-source discounts, deterministic output, and no predicted edge masquerading as sourced fact.

**Exit gate P4b:** At least one approved real mini-case produces a **development-only** B0 and G1 paired run from the same earliest reports. Real study evaluation requires P1b/P2/P3 and frozen parameters, not just runnable output.

**Evidence:** G1 schema/config docs, PR, tests, sealed profile/hypothesis outputs, run manifest and independent input parity audit.

### P5 — Independent scoring and empirical study (M6)

**Target:** Test the hypothesis rather than demonstrate a preferred answer.

**Do**
- Freeze selected cases, hypotheses, extraction mode, ontology, G1 feature weights, top-k, thresholds and output hash *before* opening held-out references for scoring. Keep prediction/rank files unchanged; amendments create new run IDs.
- Define canonical later reference relation units; label `SUPPORTED` / `CONTRADICTED` / `NOT_ASSESSABLE` / `DUPLICATE_OR_OUT_OF_SCOPE` with citations. Review independent from inference where feasible; keep disagreements visible.
- Compute (a) source claim extraction precision/recall/F1, (b) B0 vs G1 per-case reference recall/completeness, (c) **assessable** provisional prediction precision, counts of unsupported/contradicted/NA, (d) coverage/abstention, and (e) source-path evidence quality. Report raw denominators, undefined metrics as undefined, not zero.
- Distinguish observed early facts from *net new* predicted facts. "Not mentioned later" ≠ false by default. Include sensitivity treating NA differently.
- Compare same cases and source inputs. Add planned ablation (e.g. G1 without syscall/Falco features). Report effect sizes per case, mean/median, variability and sensitivity, not unwarranted significance for 4–6 cases.
- Separate development/parameter tuning cases from final assessment where feasible; disclose leakage/overfitting or too-small-sample limitations. Reconstruct environment on a second clean checkout and compare hashes.

**Exit gate P5:** Every reported metric traceable to frozen case/source/prediction/annotation records and numerator/denominator; no post-freeze changes to held-out or prediction artifacts; all cases (including failures/negative ones) reported. Passing scientific outcome **does not mean the hypothesis must be supported**.

**Evidence:** `artifacts/runs/<run_id>/` immutable run/score manifest, paired per-case tables, annotation agreement and leakage audit, reproduction log; private evidence stays outside Git if rights restricted.

### P6 — Reproduce, faculty review and publish responsibly (M7)

**Target:** A defensible, self-contained scientific deliverable.

**Do**
- Re-run offline from an identified Git commit/environment with publicly redistributable fixtures and exact instructions; provide the private-rights/source acquisition procedure as appropriate without leaking restricted bodies.
- Submit methodology, temporal validity, provenance, cost, accuracy **and negative findings** for faculty/mentor review. Update SRS/SDD/ADRs against implemented reality.
- Write methods, dataset selection/case chronology, B0/G1 treatment, results, ablations, failure analysis, limitations, research ethics, replication and budget report.
- Produce symposium presentation/poster and source traceability appendix from frozen results. Decide repo/data licensing only after ownership and source-rights review.
- An AWS/Neptune/Bedrock deployment is **optional** and requires a separate, explicitly approved cost/permissions plan, budget alarms, kill switch and teardown; default cloud spend = $0.

**Exit gate P6:** Clean-room reproduction confirmed, approval/release checklist signed, publication rights checked, no hidden exclusions, all result claims tied to accessible evidence.

## 6. Every PR must satisfy this Definition of Done

1. Exactly scoped issue/requirement IDs, expected result and **non-goals** in the PR.
2. Versioned schema/contract updates, backward-compatibility or explicit migration, and updated implementation status.
3. Unit tests for happy path, malformed data, edge cases, idempotence and determinism.
4. Integration and adversarial tests for **post-cutoff sources/aliases/taxonomies, held-out labels, duplicate/mirrored evidence and fabricated claims** if the component can encounter them.
5. Each run/test has reproducible commands, dependencies pinned, fixtures synthetic or legally redistributable, no secrets or paid services.
6. CI **green on the exact PR head**, not a previous commit; no skipped required jobs. Review failure logs and independent evidence paths.
7. Run an offline smoke path from clean checkout, capture changed schema/outputs and regressions. For security-critical code, avoid assuming source-unit tests alone are sufficient.
8. No false completion claim: actual real source evidence and human signoff checked separately; manual dependencies remain open.
9. Squash/merge only after the above; update issue, commit/link, release note and next actionable backlog item.

**Stop-the-line failures:** future evidence anywhere in an inference input; model/extractor hallucination silently promoted to a sourced fact; missing/wrong source hash; unsupported/corrupt file silently accepted; held-out reference read before prediction freeze; cloud spend without explicit permission; secrets or nonredistributable data committed; unresolved mismatched B0/G1 early inputs. Fix the gate before continuing.

## 7. Backlog order and explicit next three PRs

**[PR-A / Issue #23](https://github.com/FardinSamin/ThreatRAGraph/issues/23) — Repo hardening / readiness truthfulness (P0, first):**
- requirement matrix; clear distinction between syntactic “strict” and researcher-approved experiment readiness;
- reproducible dependency environment, Windows + Linux smoke, CI secret/dependency/lint checks;
- tests proving empty/fictional approved data cannot be described as a completed empirical study;
- contract audit for current modules; branch protection and review policy (document if GitHub settings cannot be changed through available tools).

**[PR-B / Issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24) — One historical development case (P1a):**
- **Signed-release provenance subtask:** an offline [runc release/ref/tag witness verifier](research/P1A_RUNC_RELEASE_WITNESS.md) can cross-check GitHub's PGP verification claim, annotated-tag target and public release timestamp; this does **not** independently certify 2024 original web bytes, permissions or a research-ready source.
- **Byte acquisition achieved, not case approved:** [pinned runc tag raw bytes obtained in GitHub CI](research/P1A_PINNED_TAG_ACQUISITION.md) (1,525 bytes; SHA-256 receipt retained 14 days). Signature trust, exact historic public release availability, reuse rights and researcher-approved cases remain blocked; there are 0 approved source-version manifest entries.
- **Local release-era signature verification achieved, not case approved:** isolated GnuPG has verified the original tag against the **historically pinned runc v1.1.12 project keyring**; see [measured signature evidence and limits](research/P1A_RUNC_SIGNER_VERIFICATION.md). Independent signer identity, exact public timestamp, rights and human acceptance remain P1 blockers.
- select one candidate with verifiable original and follow-up reporting dates **before reviewing prediction outcome**;
- collect permitted exact archived versions outside Git, source rights and hash/date evidence;
- freeze initial 1–2 report split and background/later reference separation; manually review in GitHub using metadata only;
- generate audit diagnostics; no “full-pilot complete” label.

**PR-C — Extract-and-graph vertical slice (P2/P3, alongside M5 synthetic tests):**
- implement one real source adapter with typed evidence-linked claims;
- validate citation and reviewer status; freeze source/alias/taxonomy version lineage;
- produce paired B0/G1 input artifacts, and **show a deliberate future-source injection is blocked**.

**M5 Issue #21** is an existing independently actionable feature branch after PR-A; algorithm/test development can parallel PR-B but **real G1 comparisons cannot be considered results until P1–P3 gates pass**.

## 8. Operational decision log and stop/go checklist

| Decision | Default | Needed before changing |
|---|---|---|
| Graph store | Local SQLite sourced-claim ledger / in-memory projections | Evidence that alternate backend improves research or scale |
| Extractor | Deterministic parser/rules for structured formats; conservative text candidate review | Measured errors, opted-in LLM, future knowledge and cost controls |
| Similarity | Interpretable, versioned weighted-feature ranking | Preregistered dev-only improvement and explanation audit |
| LLM synthesis | **Off** for primary B0/G1 experiment | Optional separate mode and contamination/citation study |
| AWS | **Off** | Explicit approval, current pricing, hard alerts, automated teardown |
| Pilot size | 25–40 approved versions; 4–6 cases | Recorded faculty-approved deviation; actual evidence available |
| Historical unknown time | **Exclude** | Independent date evidence, not an inferred guess |
| No review / contradiction | **Refuse or abstain** | Documented adjudication, never silent deletion |
| Missing license/rights | **Do not publish source bytes** | Verified grant/terms allowing use |

**Go/no-go for any claim of experimental readiness (all required):**
- [ ] Source bytes/hash/rights/timestamps manually verified, frozen, and independence reviewed.
- [ ] Case inclusion, cutoff, early reports and later references approved; outcome partition isolated.
- [ ] Extractor/normalizer/ontology/alias decisions are as-of valid; real extraction quality measured.
- [ ] Each scored source assertion has an aligned quote and human semantic decision.
- [ ] B0 and G1 early evidence identity matches exactly; no future feature/source/label in either profiler.
- [ ] G1 predictions separate from sourced claims and supported by historically eligible evidence paths.
- [ ] Full-pilot cases, approval record and frozen code/config/run artifacts exist.
- [ ] Evaluator reads predictions **after** freezing, uses independent labels, and reports both successes and failures.

Fail any box → **not empirically research-ready**. A run may be useful development work, but it must be labeled as such.

## 9. Change control

- **SRS:** edit first if objectives, requirements or acceptance conditions change. Preserve original research proposal framing unless the investigator/faculty explicitly revises it.
- **SDD:** track interfaces, actual implementation files, mismatches, architecture/ADR revisions and the as-of trust boundary.
- **This plan:** update status/checklists **in the same PR** whenever a stage is completed or dependencies change. Leave next issue actionable; never close an issue merely because a scaffold or synthetic-only helper exists.
- **Reproducibility:** every stage signs off exact version/commit, source/case/experiment hashes and evidence links, with no invented dates, ratings, results or source authenticity claims.

The plan is designed to **make incorrect results difficult to publish and easy to detect**, not to promise that all software, third-party reports, dates or scientific inferences can be made infallible.
