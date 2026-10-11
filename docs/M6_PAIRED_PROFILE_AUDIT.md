# M6.0 — Offline paired B0/G1 output audit

**Status: implementation drafted; tests authored but not executed on this branch.
Not approved for research use.**

This stage builds the output-side validation necessary for FR-28, while GitHub
Actions' included quota is exhausted. It does NOT complete FR-28 end to end.
The input-side source bytes, reviewer decisions and historical cutoff still
require independent verification, and real cases remain unapproved.

## Inputs and output

Supply existing deterministic B0 and G1 profiles, separately generated from
their already-frozen pre-cutoff input views and sourced graphs:

    python -m scripts.audit_paired_profiles --b0-profile b0.json --g1-profile g1.json

No network, AWS, future outcome labels, gold store or originals are accessed.
The CLI accepts only local regular JSON files up to 8 MiB each. It prints a
single deterministic structural-audit receipt or returns a refused status with
nonzero exit code.

The receipt includes exact profile identities, the common B0 view digest,
early-source-version IDs, hashed early observed fact list, provisional
prediction count, and explicit no-held-out-label/no-research-approval flags.
It does not export report bodies, create metrics or certify ground truth.

## Fail-closed conditions

- Incorrect profile_id hashes, method contracts, schemas or case identity
- Different B0/G1 early source-version IDs, B0 source-view digests or early facts
- G1 not bound to the exact B0 profile ID
- Any B0 inferred prediction, unsupported observed-fact provenance, invalid
  typed source triple or duplicate observed fact (incoming sourced target
  relations remain allowed; only G1 predictions must originate at the target)
- G1 proposed edges overlapping source-observed facts, repeated predictions,
  nonprovisional prediction status, probability-like score or no independent
  historical corroboration paths
- Embedded held-out/gold fields or inconsistent G1 abstention
- Unbounded local JSON inputs or symlinked input files

A pass means only the *outputs* are mutually consistent. Matching hashes can
be fabricated, and the check cannot authenticate original public-availability
dates, frozen code/dependencies, chain of custody or any researcher identity.

## Further buildable work

1. FR-29 immutable run-lock/manifest, tying source views, graph digests, code
   revision and configuration to both profiles and to this receipt.
2. FR-30 separate held-out reviewed reference partition, opened by an offline
   evaluator **only after** predictions have been externally frozen.
3. FR-31 denominator-bearing supported/contradicted/not-assessable scoring
   and casewise/aggregate reports; absence in later sources is not negative.
4. FR-18 export/import with versioning and content-hash round-trips.
5. FR-13 time-versioned aliases only with explicit, independently dated input
   and conflict adjudication. No guessed future alias mapping.
6. Reduce on-push GitHub Actions expenses before any renewed CI budget.
7. After engineering build-out: run offline unit/integration/adversarial tests,
   real Cado archival positive-control replay, then full cross-platform CI and
   independent source approvals; no draft is merged on assumed green status.

No source rights, independent historical case approval, gold labels or empirical
B0/G1 results have been created by this scaffolding.
