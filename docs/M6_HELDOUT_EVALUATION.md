# M6.2 — Separate candidate held-out evaluation scorer

**Status:** Draft code and 22 synthetic/adversarial tests authored; none has
been executed in CI or verified against a genuine historical study case.
This requires parent draft PR #52. No empirical B0/G1 results or source
approval have been produced.

## Research isolation

The new scorer lives in a separate module and separate offline command.
B0, G1, their sourced graphs, and the upstream pairing code NEVER import
the held-out evaluator. The CLI first reads and validates existing frozen
B0/G1 profiles, paired parity audit, and content-addressed engineering run
lock. Only after these checks pass does the CLI open the later-reference JSON.

This establishes a fail-closed program read order, NOT independent proof that
the predictions were frozen before a researcher viewed reference sources.
Self-hashes alone are not timestamps, signatures, true publisher provenance,
independent reviewer authentication, or WORM storage.

## Candidate reference-partition schema

Pass a separately prepared JSON object containing exactly these fields:

- schema_version = 1.0
- artifact_kind = heldout_reference_adjudications
- case_id, target_entity_id, cutoff_at, reference_window_end_at
- review_protocol_version
- review_status = candidate_unapproved
- sources: at most 1,000 later versions with source_version_id,
  SHA-256, available_at and independence_group
- adjudications: 1–10,000 canonical, unique typed relation triples
  with decision, later source_version_ids, two distinct *declared*
  reviewer_ids, and a nonempty manual rationale
- partition_id = reference: followed by the canonical JSON content hash
  of all other fields

Allowed decisions are supported, contradicted, not_assessable, duplicate,
and out_of_scope. Explicit supported/contradicted relations MUST have a
later witness source. All reference sources MUST be dated *after* the case
cutoff and no later than the declared window end. Out-of-scope records,
malformed/duplicated fields and conflicting duplicate triples are rejected.

The Python helper seal_reference_partition adds the content hash to a draft
partition after structural validation, but it cannot convert unverified
annotation records into trustworthy gold labels.

## Offline usage

First produce frozen engineering output artifacts using M6.1:

    python -m scripts.freeze_paired_run ... --write

Then, in an independent evaluation command:

    python -m scripts.evaluate_frozen_paired_run \
      --b0-profile /path/to/frozen-b0.json \
      --g1-profile /path/to/frozen-g1.json \
      --paired-audit /path/to/frozen-audit.json \
      --run-lock /path/to/frozen-lock.json \
      --reference-partition /path/to/private-candidate-labels.json

By default this prints a minimal summary without raw reference text. Add:

    --write --output-dir artifacts/heldout_evaluation

to write a hash-addressed candidate scoring artifact. Private labels, raw
publisher reports, investigator credentials and annotation bodies should stay
OUTSIDE Git; the repository already ignores artifacts/.

Each scored relation includes a digest and its explicit reference decision
or the no-label not-assessable state; later witness source IDs are preserved
for manual traceability. This is not equivalent to verifying semantic quality.

## Denominators: never impute negative labels

The scorer reports four separated views:

1. B0_observed — early source assertions, not novel predictions
2. G1_observed — the identical early assertions, checked for parity
3. G1_novel_proposals — only provisional graph-derived predictions
4. G1_combined_profile — observed plus novel for descriptive coverage

Only explicitly supported and explicitly contradicted later evidence enters
assessable precision:

    assessable_precision = supported / (supported + contradicted)

Unmentioned proposals are not_assessable, NOT false. Explicit
not_assessable, duplicate, and out_of_scope outcomes are excluded and counted
separately. A zero assessable denominator yields JSON null (not 0% or 100%).

For each method, supported_reference_coverage has a numerator/denominator
over explicitly positively labeled relations in this reference partition.
It is NOT population recall because reference-list completeness is unknown.
Rank scores are uncalibrated Jaccard heuristics, not probabilities.

The pure aggregate_candidate_evaluations helper reports descriptive micro
assessable precision across unique candidate case reports; no inferential
significance, calibration, or real-case effect size is claimed.

## Remaining scientific and engineering gates

- Independently date and rights-review publisher originals, review extracted
  claims, confirm aliases/ATT&CK/Falco revisions and first one/two sources
  for each case; currently 0 approved real cases and 0 approved sources.
- Independently confirm reviewer credentials, label scope/coverage and that
  held-out label material never entered feature extraction or model context.
- Protect the freeze with an independently authenticated chronological record
  before reference labels become available to the evaluator.
- Run synthetic adversarial tests locally, audit scorer precision/denominator
  and label controls, then run full Linux+Windows CI when Actions quota returns.
- Build a multi-case orchestration CLI, extractor evaluation, and carefully
  reported real paired study results. This draft does not complete FR30/FR31.

Research readiness stays false. Do not merge any untested draft or suggest
that fake unit-test labels are authentic historical study outcomes.
