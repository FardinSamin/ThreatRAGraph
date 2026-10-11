# M5 — Explainable G1 historical graph similarity (v2: exact-only lineage)

**Implementation:** `src/threatragraph/similarity_g1.py`, `src/threatragraph/feature_lineage.py`, `scripts/profile_g1.py`, `tests/test_similarity_g1.py`, `tests/test_feature_lineage.py`.
**Tracking:** [M5 Issue #21](https://github.com/FardinSamin/ThreatRAGraph/issues/21) · [SRS](SRS.md) FR-20–25 · [SDD](SDD.md) §8.
**Status:** Versioned **synthetic-tested research algorithm**, not evaluated on an independently approved historical corpus.

## Experimental difference

- **B0:** first one or two early reports, **only** their reviewed, source-asserted target facts; `predictions=[]`.
- **G1:** the exact same B0 source-version metadata and **identical reviewed early claim objects**, plus separately eligible historical background sources/claims. The G1 implementation actually calls the existing B0 algorithm; it refuses changed early source hashes, altered early claim content, wrong graph/view fingerprints, mismatched cutoffs or case/target IDs.
- Source allowlisting and exact recorded cutoffs are **syntactic as-of controls only**. Earlier learned aliases, changing ATT&CK/Falco taxonomies and upstream publisher/date authenticity are **not independently verified** by the ranker; those require the pending M1/M2/M3 human evidence and derived-feature history gates. Do not call this a finished leakage-proof research experiment.

## Conservative v1 method

1. Accept **five sealed, locally supplied JSON artifacts**, including the mandatory G1 exact-only as-of feature-lineage record, instead of only four: `B0` source view, `B0` reviewed graph, `G1` source view and `G1` reviewed graph. No full case registry, held-out reference/gold labels, web retrieval, LLM, cloud services, embeddings or API calls.
2. Require exact B0/G1 early input equivalence. Reject later/future source roles, any post-cutoff source, background claim that directly mentions the target, and any background publisher **independence group shared with an early source**.
3. Only **positive, aligned, semantically supported `report_assertion`** claims participate in similarity. `rule_semantics` (Falco rule logic) **cannot become evidence of actual incident behavior**; negative and uncertain early claims prevent that relation from being proposed. **G1 reuses B0's conflict-resolved early feature set**, and conflicting negative/uncertain historical claims suppress both corresponding peer-matching features and proposed target relations.
4. Match historically known **same-type peer subjects** to the target using exact typed outgoing features (`USES` and `HAS_BEHAVIOR`). No aliases are inferred. Remove features attached to more than `max_peers_per_feature` eligible background peer entities to avoid popularity-only matches.
5. Compute deterministic, **uncalibrated equal-weight Jaccard** = shared feature count / union feature count. It is **not a probability**. No train/test feature tuning or empirical calibration has occurred.
6. From overlapping peer features, propose **previously unseen positive source-reported relations** in that same restricted family. Require **at least two independent historical background publisher groups** across the shared feature and candidate-relation supporting claims. The independence requirement is heuristic: it does not certify real publisher independence, syndication absence or factual correctness.
7. Emit `status=provisional_graph_analogy_not_sourced_fact`, score, matching feature contribution, `early_support`, `historical_support`, candidate source claim paths (IDs, version IDs, original evidence locators, evidence hashes), peer ID, and source-independence groups. Never insert a predicted triple into the sourced-claim SQLite ledger.
8. Sort scores and tie breakers deterministically; select bounded top-k, or **abstain** for no supported overlap/independent background support. Keep separate `observed_early_facts` copied from the B0 output and `predictions` containing only explicitly provisional hypotheses.

**Current guardrails are intentionally conservative.** Even a structurally valid prediction could be wrong; strong graph similarity does not prove a new malware technique, attack occurrence, exploit success, or actor attribution. Only empirical review can assess usefulness.

## Offline CLI

~~~powershell
python -m scripts.profile_g1 --b0-view .\data\private\b0-view.json --b0-graph .\data\private\b0-graph.json --g1-view .\data\private\g1-view.json --g1-graph .\data\private\g1-graph.json --feature-lineage .\data\private\g1-asof-lineage.json --top-k 5 --min-background-groups 2
~~~

The five inputs must originate from an audited M1/M2/M3 preparation pipeline; a forged JSON file can *self-declare* prior semantic review and release dates. The G1 CLI cannot independently authenticate source bytes or reviewers. Its output always contains `research_ready=false` and the `research-readiness-v1` disclosure. If a required input or contract fails, the CLI prints a small `status=refused` response, not raw source evidence.

### Output fields

| Field | Semantics |
|---|---|
| `method_version=g1-historical-typed-jaccard-v2-lineage` | Frozen algorithm label for reproducibility |
| `b0_profile_id` | Content-derived hash of the unchanged B0 report-only result |
| `observed_early_facts` | Exactly B0's eligible early source assertions; not external truth |
| `predictions[]` | Separate provisional new target relations, historical analogy score, peer/matching features and source-claim provenance paths |
| `abstention` | Whether candidate inference was refused for insufficient support |
| `configuration` | Frozen top-k, feature overlap, group threshold and popularity cap |
| `readiness` | Structural validation only; independent source/dating/real research approval NOT established |
| `feature_lineage_sha256` / `feature_lineage_contract` | Mandatory per-claim source/date binding; no independent original-byte authentication |
| `profile_id` | Deterministic content digest of the complete G1 result |

### Non-goals / remaining research gates

- **No genuine historical pilot yet:** 19 source URLs are candidates, **0 approved real versions and 0 case manifests**; there are **0 real B0/G1 results**.
- **M5.2 now checks declared exact-only per-claim source/date lineage**, refusing aliases and external taxonomy/rule enrichment. Actual historic identifier and original-byte authentication, real taxonomy versions and cache replay remain **unverified**. See [M5.2 contract](M5_ASOF_FEATURE_LINEAGE.md).
- **No independent gold-label store, outcome scorer, feature ablation, calibrated ranking probabilities, historical publication proof or human reviewer authentication.** All remain pending in P1–P5.
- **No synonym merging, graph embeddings, LLM inference, NetworkX requirement, cloud backend or operational detection product.**
- **Two group support is a deliberately conservative heuristic**, not a statistically validated threshold. Predeclare/study sensitivity only on development cases, not post hoc held-out outcomes.

## Validation

`python -m unittest discover -s tests -v` plus CI Windows/Ubuntu, Ruff lint, secret scan and runtime vulnerability audit. Synthetic adversarial cases include source/cutoff leakage, mirrored reporting groups, target-specific background, Falco rule false inference, absent reviews, contradictions in early evidence **and** historical source claims, generic/popular features, unknown aliases, score determinism and CLI refusal. A passing suite certifies only these implementation properties, not a live cybersecurity threat profile.
