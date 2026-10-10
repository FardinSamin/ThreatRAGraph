# M0 — Greenfield project clarification (supersedes prototype intake)

**Status: Original intake requirement cancelled as inapplicable.**  
**Tracking:** [Issue #1](https://github.com/FardinSamin/ThreatRAGraph/issues/1) (closed as not planned following clarification).  
**Source of truth:** The investigator directly confirmed on 2026-10-10 that **ThreatRAGraph is being developed from scratch**. No earlier local Python prototype or independent implementation exists to locate, import or audit.

## What was corrected

An early planning assumption interpreted a description in the URFS proposal as evidence that a separate local Python extraction/graph prototype already existed. The investigator has clarified that assumption was false. The original M0 document incorrectly instructed the investigator to find, preserve, scan and import such a prototype; **none of those actions is required**.

The repository itself is the first and only ThreatRAGraph codebase of record. Its SRS/SDD and new offline Python modules, schemas, case/snapshot metadata contracts, historical graph components, evidence validators and B0 baseline form the actual starting implementation. The files and synthetic CI tests must be assessed on their own merits, not attributed to a prior prototype.

## Corrected M0 / future engineering work

- **Initial greenfield setup:** repository and draft architecture established; security-conscious Git workflow and automated tests in place.
- **Ongoing engineering audit:** compare code actually committed to this repository with SRS/SDD functional requirements, maintain CI, and flag unimplemented features honestly.
- **M1 corpus:** approve historical source versions, verify availability/rights, independently review 4–6 case selection and reference facts. Current 19 URLs are candidate-only.
- **M5:** implement G1 explainable graph similarity separately from the merged B0 baseline (see [Issue #21](https://github.com/FardinSamin/ThreatRAGraph/issues/21)).
- **M6:** run paired evaluations only after authentic source/case evidence and appropriate annotation are available.

## Optional future external code intake

The historical `scripts/preflight_import.py` remains as an **optional, limited heuristic** for examining any third-party code introduced later. It is **not** proof that an original local prototype exists and is **not** required to run or work on the current repository.

For normal greenfield development, use the instructions in the [README](../README.md). Never commit credentials, restricted raw CTI, or secrets; and avoid provisioning cloud services without explicit budget approval.

The original intake text is preserved in Git history for traceability. Its unsupported premise must not be repeated in future milestones or completion reports.
