# M2 — Versioned compound sourced-claim extension (v1 untouched)

**Status:** bounded, synthetic-tested engineering **extension**, not researcher authorization or real-case evaluation. [Issue #11](https://github.com/FardinSamin/ThreatRAGraph/issues/11), [P1a #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24). Follow-ups to [candidate review packets](M2_GHSA_COMPOUND_REVIEW.md) and the [authentic original GHSA CI replay](research/P1A_GHSA_LIVE_REPLAY.md).

## New scientific-ledger capability (strictly scoped)

The original v1 `sourced_claims`, `semantic_reviews`, `historical_sourced_graph`, B0 profile and G1 v2 contracts stay **completely unchanged**. Instead, `src/threatragraph/compound_claims.py` adds **two separate, versioned tables in the existing approved-source SQLite database**, called `compound_sourced_claims_v1` and `compound_semantic_reviews_v1`.

A compound claim requires an **already registered approved advisory source version** in the M2 `source_versions` ledger **and** an `EvidenceVerifier` attached to exact immutable archived source bytes. It checks that the source manifest declares `status=approved`, `source_kind=cve_advisory`, the registered SHA-256 matches, and that the original archive itself still matches that digest. It re-derives the exact pinned GHSA CVE/Go-package candidate and its **two independently verified original JSON scalar locators/digests** from actual archived bytes. There is no trust in a caller-supplied candidate, packet ID, source triple or field list.

The new compound claim schema is `ghsa-compound-sourced-claim-v1`, requiring **exactly** `schema_version, source_version_id, source_sha256, candidate_id, packet_id, subject_id, predicate, object_id, assertion_kind, polarity, field_evidence, extractor_version`. At this stage the only supported typed relation is explicit `vulnerability:CVE-... AFFECTS software-product:go/...`; the existing GHSA 1.4 Go-package adapter validates it. There is **no prose interpretation, exploitation assertion, version-range interpretation, Falco incident inference or generic free-text relation extraction**.

A separate `ghsa-compound-semantic-review-v1` record has exactly `schema_version, claim_id, source_version_id, compound_evidence_sha256, decision, reviewer_id, reviewed_at, rationale`. Review decisions use the existing vocabulary `supported_by_excerpt / unsupported_by_excerpt / uncertain`. The reviewer is **self-declared**, not cryptographically authenticated; reviews are manually submitted to this new table and never imported automatically from the **candidate-only** `ghsa_candidate_reviews` store. The claim, source ID, two-field compound digest, decision, timestamp and rationale are bound into a content-derived review ID. Re-appending identical records is idempotent; conflicting changes are refused rather than overwriting frozen review decisions.

Both new tables use explicit schema columns and foreign keys, and incompatible previously created versions are rejected without a silent migration. The v1 core tables and their old `PRAGMA user_version=1` compatibility contract are retained; **this is a separate opt-in table extension, not an automatic upgrade of existing v1 claims or a new default B0/G1 schema**. A hostile SQLite file still requires additional P0 integrity/constraint audit; this is not a database-signature solution.

## Temporal isolation and separate projection

`CompoundSourcedClaimLedger.project(view, require_supported=...)` first delegates **all source-role, metadata fingerprint, SHA-256, exact UTC cutoff and approved source allowlist checks** to the existing M2 `EvidenceGraph.project` validator, then selects **only** the compound claims for those allowed source IDs. It emits `ghsa-compound-evidence-view-v1`, with provenance for both fields and manual review status.

- **B0** gets only its early allowed sources.
- **G1's separate compound evidence view** gets early plus permitted historical background sources. Held-out reference versions cannot be loaded as early/background and cannot be included in the early sealed projection.
- Strict views refuse missing, uncertain or unsupported semantic reviews. An unsupported fact does **not** become a positive graph edge.
- `research_ready=false` and `g1_ranker_input_eligible=false` are unconditional. This extension **never** feeds `src/threatragraph/similarity_g1.py`, upgrades candidate reviews, or changes the known unsupported-vulnerability target behavior.

## Offline runner

`scripts/project_compound_case.py` uses the existing source/case manifest validator, `case_views` chronology builder, all-approved-source **byte integrity audit**, allowlisted claim JSONL, optional versioned review JSONL, and the new compound ledger. It emits paired but **separate compound evidence** B0/G1 views; they are not the existing G1 ranker inputs. Under `--development-only`, only the pilot **count requirement** is relaxed and all other source/archive/cutoff/claim/refusal gates apply. Normal strict runs also require 25–40 approved source versions, 4–6 valid cases and explicit semantic reviews, but still do **not** claim investigator/faculty approval or scientific efficacy.

~~~powershell
python -m scripts.project_compound_case --help
python -m unittest discover -s tests -v
~~~

A real submission requires externally reviewed case manifests, archived source bytes, a manually assembled JSONL of the exact versioned compound claim objects and a separately authored JSONL of their compound review objects. **No genuine source was approved or placed in the corpus by this implementation.** Existing `datasets/cases/pilot.json` remains empty; default invocation must refuse rather than invent a case.

## Acceptance status and next actual research blockers

- The production `EvidenceVerifier` now offers `read_approved_bytes(source_version_id)` for re-reading SHA-256-pinned approved source archives. It retains the same symlink, size and byte-hash checks as the original `verify` method.
- Unit tests use *only synthetic, explicitly marked fixture approvals* to verify byte-aligned dual-field registration, conflict-free idempotence, source-status refusal, mismatched field/packet/CVE refusal, archive tampering, exact cutoff filtering, held-out exclusion, distinct reviewer metadata, rejection of unsupported/uncertain reviews, and ledger-schema refusal. A small synthetic manifest end-to-end runner is included.
- No historical GHSA source is formally approved. The real GitHub pinned-original byte replay remains **candidate-only** until publication-time, rights, selection, independence and researcher review are completed.
- Before any empirical G1 research, a **new versioned scientific B0/G1 output contract and independent evaluator** must explicitly accept and test these compound claims. This PR **does not** teach G1 to predict vulnerability `AFFECTS` relationships, change feature thresholds or claim a positive result.
