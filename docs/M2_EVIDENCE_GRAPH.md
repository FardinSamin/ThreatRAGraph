# M2 — Evidence-Backed Claims and Historical Graph Projection

**Status:** Implemented as a testable, independent reference component. **Not integrated with the investigator's original local prototype. No real extraction or GraphRAG predictions have been performed.**

**Tracking:** [Issue #9](https://github.com/FardinSamin/ThreatRAGraph/issues/9)  
**Requirements:** SRS FR-09–16, FR-19–21, DR-01–10, NFR-02–03; SDD ``5–9.

## 1. Research purpose and scope

ThreatRAGraph must distinguish (a) facts **asserted by historical sources**, (b) graph-generated **provisional predictions**, and (c) **later reference evidence** used only for scoring.

This component implements **only (a)**: an evidence-attributed claim ledger in SQLite and source-allowlisted B0/G1 graph projections. A CTI report can itself be mistaken, and Falco rule conditions represent **detection logic**, not actual incidents. No predicted relation enters this ledger.

### Data flow

~~~mermaid
flowchart LR
  SRC["M1 approved source versions"] --> AUD["M1 archive hash verification"]
  AUD --> LEDGER["SQLite sourced claim ledger"]
  EXTRACT["Manually reviewed / future extractor JSONL"] --> LEDGER
  CASE["M1 case metadata + cutoff"] --> SNAP["M3 B0/G1 source lists"]
  LEDGER --> PROJ["Allowlisted graph query"]
  SNAP --> PROJ
  PROJ --> B0["B0 early-only graph"]
  PROJ --> G1["G1 early + historical background graph"]
  HELD["Later references + outcome labels"] -. "Excluded from profiler" .-> EVAL["Future evaluator"]
~~~

Graph projections select **only claim source versions explicitly allowed by the validated view**. The design does not generate unrestricted present-day graph features and then rely on a display filter to hide later claims.

## 2. Sourced-claim data model

File: `src/threatragraph/evidence_graph.py`.

SQLite tables:
- `source_versions` — version ID, originating source ID, exact content digest, public-availability time and date-evidence rationale.
- `sourced_claims` — content-derived immutable-ID assertion, typed subject/predicate/object, signed/uncertain polarity, source version ID, evidence locator/digest, extractor version, and `report_assertion` / `rule_semantics` kind.

Sourced claims are not confirmed truth. Duplicate triples supported by different reports produce independent multi-edges; exact repeat submissions are idempotent. Source metadata cannot be silently changed through the repository API; direct privileged SQLite writes remain possible, so this is **application-level append-only**, not cryptographically immutable storage.

Example **fictional**, not valid research evidence:

~~~json
{
  "source_version_id": "srcver:synthetic",
  "subject_id": "malware:synthetic",
  "predicate": "USES",
  "object_id": "attack-technique:T1059",
  "assertion_kind": "report_assertion",
  "polarity": "positive",
  "evidence_locator": {"kind": "text_span", "segment_id": "segment:1", "start": 1, "end": 10},
  "evidence_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "extractor_version": "fixture-parser-v1"
}
~~~

The extractor must ultimately demonstrate that the cited evidence span/field actually matches archived bytes/normalized text. The presence of a locator and digest **does not yet verify alignment**.

### Controlled relation ontology (v1)

| Predicate | Subject types | Target types |
|---|---|---|
| USES | threat-actor, malware, campaign | tool, malware, attack-technique |
| EXPLOITS | threat-actor, malware, campaign | vulnerability |
| AFFECTS | vulnerability | software-product, container-component, kubernetes-resource |
| TARGETS | threat-actor, campaign | software-product, container-component, kubernetes-resource |
| HAS_BEHAVIOR | malware, attack-technique | attack-behavior |
| INVOLVES_SYSCALL | attack-behavior, falco-rule | system-call |
| DETECTED_BY | attack-behavior, attack-technique | falco-rule |
| APPLIES_TO_COMPONENT | falco-rule, vulnerability | container-component, kubernetes-resource |
| INDICATES | indicator | malware, campaign |

Unrecognized relation types and incompatible endpoints are rejected. This is a **narrow preliminary subset** pending as-built prototype review and ontology version control.

## 3. B0/G1 graph provenance boundary

- **B0**: Only source-asserted relationships in the first one or two historically permitted target reports.
- **G1**: Exactly the same early sources and additional *pre-cutoff* approved background sources.
- **Held-out references**: Not loaded into either output, not named in profiler-facing graphs, and prohibited as input claim versions.

The projection checks the view schema, allowed source role, exact source version identity/hash/UTC availability time in ledger, cutoff eligibility and 1–2 initial report requirement. Unknown/mismatched/future sources are rejected, not simply hidden.

**Not yet solved:** Temporal evolution of aliases/canonical IDs, backfilled ATT&CK/Falco versions, inferred edges, extractors that hallucinate facts, model pretraining memorization, actual human provenance review, and genuine later reference outcome isolation in a full graph pipeline.

## 4. CLI and executable interface

File: `scripts/project_case_graph.py`. This CLI is **offline**, **read-only with respect to archived content**, and generates an in-memory SQLite graph. It does not call AWS, scrape websites, invoke LLMs or execute report text.

After the corpus and case manifests have been populated and source files archived:

~~~powershell
python -m scripts.project_case_graph --case-id YOUR_CASE_ID --claims "C:\research\approved-claims.jsonl"
~~~

Default mode requires **25–40 approved historical source versions and 4–6 selected cases** plus matching content-addressed archives for all approved versions. It checks the M1 byte-audit and M3 source partition first.

Each line of the claim input is one evidence-backed JSON object. **Claims from sources not allowed for the selected case (including later references) make the entire run fail**, rather than being silently skipped.

The explicit `--development-only` option relaxes only the corpus/count requirements for **synthetic fixture experiments**, keeping source approval, archive byte integrity and cutoff checks in place; outputs are labeled `research_ready: false`.

Current repository manifests contain **14 candidate URLs, zero approved sources and zero selected cases**, so no real profile can be generated yet.

## 5. Tests and verification

~~~powershell
python -m unittest discover -s tests -v
python -m scripts.project_case_graph --help
~~~

Synthetic tests cover stable source claims, independent multi-edge provenance, Falco rule vs. incident distinction, ontology validation, invalid locators, source re-registration protection, future source rejection, source byte corruption, disjoint B0/G1 views and CLI refusal of held-out claims.

## 6. Next integration work

1. Import and audit original local prototype under [M0 #1](https://github.com/FardinSamin/ThreatRAGraph/issues/1).
2. Implement **evidence-span verification** against frozen normalized source records and measure precision/recall.
3. Curate actual versions/case cutoffs under [M1 #3](https://github.com/FardinSamin/ThreatRAGraph/issues/3).
4. Integrate historical per-cutoff alias decisions and graph construction using M3 views.
5. Add interpretable structural similarity and a **separate prediction** object store.
6. Pair G1 and B0 with independent later labels and scientifically valid scoring.

This deliverable is **sourced graph infrastructure**, not a completed research experiment.

## 7. Evidence-alignment update

The end-to-end CLI now attaches the [M2 citation verifier](M2_EVIDENCE_ALIGNMENT.md) to the SQLite claim ledger: an approved source archive must match its own SHA-256, and a supported text-span or JSON-pointer locator must reproduce the claimed evidence digest. Otherwise the claim is rejected before insertion. The graph edge exposes `evidence_status=aligned`; direct test/developer ledger insertions without a verifier are labeled `unverified`. **Byte alignment is not semantic correctness or independently verified truth.** YAML/PDF normalizers and historical alias controls remain outstanding.

## 8. HTML and Falco normalization update

The evidence verifier now recomputes a versioned HTML visible-text view or safely parses a pinned Falco YAML rules file from the **original, hash-verified archive bytes** at insertion time. Those derived locators carry explicit normalizer versions. Falco YAML citations must remain `rule_semantics`, not observations of an incident. See [M2 normalization](M2_HTML_FALCO_NORMALIZATION.md). Raw PDF/OCR and semantic extraction verification are still not covered.

## PDF page-scoped evidence update

The source-assertion graph CLI now validates pinned `pdf_page_span` citations against the **exact approved archived PDF source version**, extracting text per page, normalizing whitespace, checking cited offsets and recomputing the evidence SHA-256. See [PDF provenance](M2_PDF_PAGE_PROVENANCE.md). No OCR, visual verification or automatic factual/semantic correctness is implied.
