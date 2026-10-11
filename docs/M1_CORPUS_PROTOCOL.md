# M1 — Pilot CTI Source and Historical Case Manifest Protocol

**Status:** Metadata-contract implementation and draft templates. **No real sources or threat cases have been selected or experimentally validated.**  
**Tracking:** [Issue #3](https://github.com/FardinSamin/ThreatRAGraph/issues/3)  
**Requirements:** SRS RC-01–06, FR-01, FR-06, FR-19–21, FR-27, EV-08; SDD §§5, 7, 9.

## 1. Why this comes first

The research question compares a cold-start profile (only one or two early public reports) with a graph-bootstrapped profile that draws on **only intelligence publicly available at the historical cutoff**. Later public reports are held out as **evaluation reference**, never background knowledge. A reusable source-version manifest and case manifest make eligibility inspectable and testable.

The supplied URFS proposal targets around **25–40 public sources** and **4–6 retrospective threat cases**, emphasizing container/Kubernetes vulnerabilities, attack behaviors, system calls, Falco rules and broader CTI/ATT&CK.

## 2. How to validate

The case registry is still **empty**, while the source registry holds **29 unapproved candidate source versions**. The [case shortlist](research/M1_CASE_CANDIDATES.md) and [original-advisory witness](research/P1A_ORIGINAL_ADVISORY_WITNESS.md) record selection and provenance work. Candidate tag/advisory bytes have measured hashes, and the advisory has a proposed public-by bound; approved digest/date fields remain unset pending independent review. Draft structural validation does not approve this evidence.

~~~powershell
python scripts/validate_research_manifests.py datasets/manifests/pilot.json datasets/cases/pilot.json
~~~

Expected status: "draft_valid", with warnings that no evaluation cases have been selected (and no approved source versions).

The readiness gate must fail until the corpus is actually curated:

~~~powershell
python scripts/validate_research_manifests.py datasets/manifests/pilot.json datasets/cases/pilot.json --strict
~~~

Strict mode requires **25–40 approved source versions and 4–6 cases**. Both modes reject malformed metadata and leakage in any cases that do exist. Exit codes are **0** (valid), **2** (validation errors) and **1** (file/JSON read error). Runs are offline; no API keys, AWS calls or network access are used.

~~~powershell
python -m unittest discover -s tests -v
~~~

The validator does **not** download source files, annotate ground truth or build the graph. It validates manually curated metadata only.

## 3. Source version registry

File: datasets/manifests/pilot.json

Root fields: **schema_version** (currently "1.0"), **dataset_id**, **dataset_version**, **sources** (array), optional description.

Example **synthetic** record (not a real curated source):

~~~json
{
  "source_id": "src:example-report",
  "source_version_id": "srcver:example-report:v1",
  "source_kind": "cti_report",
  "title": "Synthetic example only",
  "publisher": "Example publisher",
  "url": "https://example.org/report",
  "status": "candidate",
  "published_at": null,
  "available_at": null,
  "date_confidence": "unknown",
  "date_evidence": "",
  "independence_group": "",
  "sha256": null,
  "redistribution": "unknown",
  "selection_rationale": ""
}
~~~

Accepted source_kind values: **cti_report**, **otx_pulse**, **attack_stix**, **falco_rule**, **kubernetes_doc**, **cve_advisory**, **other**.

A source record is *one immutable document or dataset version*. **source_id** links revisions; **source_version_id** uniquely identifies a frozen version. Use the full lowercase SHA-256 digest of the precise archived/source bytes, not a title or arbitrary placeholder. Identical raw content imported twice must not be presented as independent corroboration.

Required for status="approved":
- sha256 is a valid full 64-character lowercase hex digest;
- available_at is an unambiguous verified historical availability timestamp;
- date_confidence="verified" and date_evidence states how it was checked;
- independence_group documents copied/syndicated/derivative material;
- selection_rationale justifies inclusion.

The scanner does not **prove** that an approved source's chronology or hash is genuine. Curators must verify publisher, archive version, metadata and report rights. Sources with uncertain historical availability must stay candidates/excluded from evaluated snapshots.

**Time field convention:** ISO UTC seconds, e.g. "2024-01-12T14:00:00Z". A source's **available_at** is the earliest defensible public availability for the **specific version**, not the download date, event onset or unverified claimed date. Unknown is null, never assigned a convenient earlier date.

**Rights:** "allowed" / "restricted" / "unknown" means redistribution rights status, not blanket permission to use or publish text. Metadata and links can be retained where compliant; review terms before storing or redistributing full documents.

## 4. Case registry and split contract

File: datasets/cases/pilot.json

Root fields must match the source manifest: schema_version, dataset_id and dataset_version. Each case has:

| Field | Meaning |
|---|---|
| case_id | Unique stable ID |
| target_entity_id | Canonical name/ID of newly emerging threat or vulnerability |
| selection_rationale | Why this is historically meaningful and evaluable |
| cutoff_at | Last moment of permitted early knowledge, in UTC |
| early_source_version_ids | Exactly **one or two** approved early report versions |
| background_source_version_ids | Approved graph background sources historically available by cutoff |
| later_reference_source_version_ids | Approved, genuinely post-cutoff versions used **only for scoring** |

The validator enforces:
- All referenced versions exist and have "approved", verified timestamps;
- Early and background versions must satisfy **available_at <= cutoff_at**;
- Later references must satisfy **available_at > cutoff_at**;
- IDs cannot repeat within or between early/background/reference partitions;
- **independence_group** cannot cross these partitions (potential duplicated or syndicated evidence);
- Unknown dates, future versions, unapproved versions and malformed cutoffs are rejected.

**Caution:** This only catches *declared* source-version and mirrored-group violations. It cannot detect future information hidden inside a misdated article, aliases learned later, pretrained-model memorization, contaminated embeddings, incorrect fact extraction or semantic copies with different declared groups. M3 snapshot construction must independently enforce all of those protections.

Example case skeleton **illustrative only** (do not add it to the active pilot without real verified sources):

~~~json
{
  "case_id": "case:example",
  "target_entity_id": "vulnerability:CVE-EXAMPLE",
  "selection_rationale": "Example, NOT a real historical case",
  "cutoff_at": "2024-01-15T00:00:00Z",
  "early_source_version_ids": ["srcver:example-early"],
  "background_source_version_ids": ["srcver:example-background"],
  "later_reference_source_version_ids": ["srcver:example-later"]
}
~~~

For an actual case, document the exact timestamp evidence for each source, justify that the first one/two early reports represent the intended cold-start setting, and select a later reference set independently of algorithm outcomes.

## 5. Corpus curation workflow

1. Researcher lists candidate reports, OTX pulses, ATT&CK/STIX version releases, Falco rules, Kubernetes security documents and selected container-based CVE/advisories.
2. Record publisher, canonical HTTPS URL, public release/availability evidence, license rights, independence group, and inclusion rationale.
3. Save a permitted immutable source copy/metadata snapshot **outside Git when restricted**; calculate its real SHA-256 and fill the approved source version record. Do not paste dummy hashes into approved records. Follow the [source byte-integrity procedure](M1_SOURCE_INTEGRITY.md) and verify the actual locally archived bytes. Historical publication time remains a separate, independently evidenced claim.
4. Select 4–6 evaluable cases with independently verified early cutoff and later material. Record the case splits.
5. Run non-strict validation after each edit, strict validation before freezing the pilot.
6. Subject selections, historical timestamps and outcome-label protocol to faculty/research review. Freeze manifest content hashes for experiments, and track revisions rather than silently changing source history.
7. Connect validated registries to the greenfield extraction and graph modules already implemented in this repository; evolve adapters against real CTI sources rather than inventing another codebase.

## 6. Additional research acceptance gates not fully automated here

- Verify 25–40 source coverage is useful and diverse, not just 25 copies of one feed.
- Verify actual source hashes match immutable archived versions.
- Confirm publication dates from trusted contemporaneous evidence, not from current modified pages.
- Avoid using target-specific later information to select graph neighbors, aliases or outcome labels.
- Ensure exact early report choice, held-out scoring criteria, annotation adjudication and exclusions are approved.
- Separate observed facts, hypotheses and later ground-truth labels.
- Re-run case leakage checks in the final graph snapshot system; passing a metadata validator is only an initial safeguard.
- Audit and extend the actual repository extraction/graph implementation against M1 schema requirements; no pre-existing prototype import is needed.

**Status note:** The source registry contains 28 unapproved candidate source versions; the case registry is empty. Neither the manifests nor the new byte-integrity tool constitute a completed dataset or empirical result.
