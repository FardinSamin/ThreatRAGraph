# M5.2 — Fail-closed as-of feature lineage and exact-only identity policy

**Status:** Implemented as a **synthetic-tested input contract** for the G1 v2 ranker. **Not independent historical authenticity or case approval.**
**Code:** `src/threatragraph/feature_lineage.py`, `src/threatragraph/similarity_g1.py`, `scripts/profile_g1.py`, `tests/test_feature_lineage.py`.
**Issues:** [M5 #21](https://github.com/FardinSamin/ThreatRAGraph/issues/21), [P1a #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24), [M1 #3](https://github.com/FardinSamin/ThreatRAGraph/issues/3).

## Problem being addressed

A source-level cutoff alone is not enough: a modern ATT&CK technique identifier, Falco rule interpretation, current alias table, or feature vector built from post-cutoff material could leak the answers into a purported historical prediction. M5.1 correctly refuses explicit future **source versions** but cannot determine how a canonical entity or graph feature was created.

## Narrow implementation — what is actually enforced

The v2 G1 process requires a **fifth separately supplied input artifact**, `g1_asof_feature_lineage`, in addition to the four sealed B0/G1 view/graph files.

The lineage artifact has a closed versioned structure. It binds the exact case/cutoff, G1 source view fingerprint and canonical graph edge-set SHA-256. It must contain exactly one claim-lineage entry per reviewed graph edge, with canonical claim-ID ordering and no extra fields. Every entry must match **the graph's exact claim ID, source version, source archive hash, evidence digest, typed subject/predicate/object and declared source availability**.

Only `identity_policy=exact_source_assertion_no_alias_or_external_enrichment` and `derivation=direct_source_claim_only_v1` are accepted. Each `feature_known_at` must equal the associated source version's declared `available_at`, which must already be on/before the cutoff. **Any declared alias lookup, modern taxonomy mapping, derived feature, new Falco enrichment, future feature date, missing/duplicate claim, mismatched source/quote or altered graph hash fails closed.** The contract applies to all graph claims, not just the candidate relations that score highly.

The graph-edge digest is canonicalized by claim ID. Merely reordering JSON graph edges or valid lineage records generated in canonical order does **not** change G1's output. The algorithm version is now `g1-historical-typed-jaccard-v2-lineage`; this deliberately changes the G1 input contract but **does not change the existing B0 baseline**.

### Mandatory CLI input

~~~powershell
python -m scripts.profile_g1 --b0-view .\data\private\b0-view.json --b0-graph .\data\private\b0-graph.json --g1-view .\data\private\g1-view.json --g1-graph .\data\private\g1-graph.json --feature-lineage .\data\private\g1-asof-lineage.json
~~~

**This is not an approval generator.** There is deliberately no production CLI that automatically emits a trusted lineage from arbitrary graph JSON. A real lineage record must be established from independently audited original source bytes, verified excerpt spans, source chronology and identifier/vocabulary provenance with an investigator reviewing the evidence. Our synthetic tests create *synthetic* lineage fixtures solely to exercise the rejection logic.

## Important limits — what passing does *not* prove

- The metadata fields are assertions. A forged but structurally self-consistent JSON source graph and lineage may pass. This validator **does not open or rehash archived original source bytes**, independently verify first public dates, or authenticate reviewers.
- The `exact_source_assertion` policy is **not a verifier that a literal entity identifier was printed in the original text**. Real extraction must prove or adjudicate that separately with historical source excerpts. An original ATT&CK technique ID might have been assigned later even if the described behavior predates the ID.
- This version refuses all externally mapped alias/taxonomy/revision enrichment rather than pretending to reconstruct historical ATT&CK or Falco knowledge. An authenticated, independently dated taxonomy snapshot and a separate, signed alias history protocol would be needed to support such features.
- The source `available_at` currently comes from the sealed source view. If that date is unverified or forged, as-of lineage **cannot repair it**. This is still blocked on real historical source approval #24/#3.
- Independent publisher groups, copied sources, observed incidents, true cyberattack occurrence and downstream predictive accuracy are not authenticated by this contract.
- B0 still accepts exactly the original early-only artifacts and needs no lineage input; G1 keeps provisional hypotheses separate and always returns `research_ready=false`.

## Regression gates

Run `python -m unittest discover -s tests -v`, CLI `--help`, Ruff, tracked-file secret scanning, PyPI runtime advisory audit and Python 3.12 Ubuntu/Windows CI. New tests reject forged alias versions, post-cutoff mappings, missing or duplicate claims, re-timed features, mismatched original source/quote hashes, changed graph/cutoff, unauthorized vocabulary fields, and prove deterministic edge-order invariance.

**Next:** strengthen independent historical source-byte/rights/reviewer verification, then allow only verified, dated external vocabulary/alias feature versions under a new explicit reviewed lineage schema (not by silently weakening v1). Run a real first-case paired B0/G1 trial only after the P1a researcher acceptance gates.
