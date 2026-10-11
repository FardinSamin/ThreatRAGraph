# P0 — Structural Validation Is Not Scientific Readiness

**Contract:** research-readiness-v1  
**State:** Implemented in the graph runner and B0 baseline on the P0 branch  
**Traceability:** SRS FR-27–31 / AC-01–07, SDD `18–19, [controlled build plan](BUILD_PLAN.md), [Issue #23](https://github.com/FardinSamin/ThreatRAGraph/issues/23).

## Defect addressed

Before P0, a Python runner returned `research_ready: true` whenever **strict structural validations passed**, even with entirely synthetic sources, invented publication attestations and self-declared semantic reviews. That was misleading. A hash can verify archived bytes but cannot establish when those bytes first became publicly available. A review record can attest to judgment, but the current ledger does not authenticate an expert reviewer or independently confirm their annotations.

The difference matters: the project has **no approved historical corpus or real study cases**, so no automated combination of current manifest counts, hashes and review JSON may certify a genuine research experiment.

## Manifest CLI disclosure

Strict metadata success now reports `status: strict_metadata_valid` instead of `research_ready`. All CLI results include `research_ready: false`. Draft/invalid statuses and exit codes are unchanged. A synthetic 25-source, four-case regression demonstrates strict success without research approval. Consumers matching the old success string must use the new status or unchanged zero exit code for metadata validity only.

## Contract, v1

A successful `scripts.project_case_graph.run()` and `baseline_b0.build_b0_profile()` now return:

~~~json
{
  "research_ready": false,
  "readiness": {
    "readiness_contract_version": "research-readiness-v1",
    "structural_checks_passed": true,
    "validation_mode": "strict_structural",
    "independent_study_approval": "not_verified",
    "empirical_evaluation": "not_performed",
    "research_ready": false,
    "reason": "Structural checks passed, but independent historical source/date/rights approval, case selection, reviewer independence, temporal feature reconstruction, paired predictions and held-out evaluation have not been established by this executable."
  }
}
~~~

This snippet shows **only the readiness fields**, not the entire graph/profile JSON. `validation_mode` is `development_only` when the explicit development flag is used. Both modes return `research_ready: false`; this is intentional, not an indication that the structural checks failed. The independent approval status remains `not_verified` even when all *synthetic* strict pilot counts, source hash checks and manual-review stubs pass.

The strict mode **continues to enforce** its existing corpus/case counts, source bytes, case chronology, approved-format source states and supported semantic reviews. This change does **not** relax any checks or create a route to accept unreviewed evidence.

`status="structurally_validated_graph"` replaces the previously ambiguous generic strict graph status. The CLI returns a valid B0 and G1 projection as a **development/research-preparation artifact**, never an automatically approved experiment.

The standalone B0 baseline continues its deterministic early-only assertion behavior, contradiction and abstention policy. Its `profile_id` content digest includes the updated disclosure, so historical output hashes will change: **schema-level/consumer migration is required** if previous JSON was cached.

## What must happen before a real study can become ready

This P0 slice deliberately provides **no override flag or bypass** to set `research_ready: true`. The future approval system must separately check/record:

1. Original source-byte archive and independent historical availability timestamp evidence, rights and independence of source versions.
2. Investigator/faculty-reviewed case selection, temporal cutoff and separate later-reference labels.
3. Reproducible extraction, alias/ATT&CK/Falco revision history, and as-of feature validity beyond source-level allowlisting.
4. Independent human annotation of CTI assertions; semantic decisions must not be self-certified by the model.
5. B0/G1 same-early-evidence parity, frozen inference configuration and output hashes, evaluator process unable to access held-out labels before the freeze.
6. Paired benchmark evaluation with transparent denominators, abstentions and negative/unassessable outcomes.
7. Versioned approval/run manifest with a separately verified reviewer identity and explicit scope; a self-declared string field is **not sufficient**.

Only then should an entirely separate acceptance module, with its own tests and signed-off protocol, be permitted to produce externally publishable study readiness. Avoid an insecure `--approve` CLI switch that trusts unverified user-provided JSON.

## Reproducibility/CI additions

GitHub Actions now runs Python 3.12 on **Ubuntu and Windows**, using GitHub checkout v5 / setup-python v6 (Node 24-compatible). Each matrix job independently installs pinned PyYAML and pypdf, records the resolved package set in logs, runs the unit/integration tests, source/case manifest checks, archive audit, source snapshot dry run, compilation and CLI smoke tests. Version pinning is not a complete platform-specific transitive/hash lock: build-plan P0 still requires deeper dependency and security auditing before closeout.

The new ``tests/test_readiness_contract.py`, ``tests/test_semantic_reviews.py` and ``tests/test_b0_baseline.py` explicitly assert that **strict synthetic full-pilot fixtures cannot set scientific readiness to true**. Tests are an assurance about the software contract, not an empirical CTI result.

## Remaining P0 work

- Verified branch-protection configuration and an explicit authorized approval policy.
- Reviewed dependency lock/hash-based supply-chain policy and vulnerability scanning.
- Full lint/static type/security workflow with baselined findings.
- Machine-checkable schemas and migration policies for all data artifacts.
- Clean production-like Windows setup outside CI as appropriate.
- Complete readiness approval protocol only after real historical sources and independently reviewed study cases exist.

These are tracked in [P0 Issue #23](https://github.com/FardinSamin/ThreatRAGraph/issues/23). Do not close that parent issue for this first safety-focused PR.
