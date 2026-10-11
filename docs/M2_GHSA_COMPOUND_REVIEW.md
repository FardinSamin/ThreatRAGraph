# M2 — Pinned GHSA compound-evidence review packets (development-only)

**Status:** bounded multi-field evidence verification and **self-declared candidate review records** are implemented and synthetic-tested. This is **NOT** research approval, an authenticated review, an approved sourced claim, or a G1 prediction. See [M2 GHSA candidate extractor](M2_GHSA_CANDIDATES.md), [semantic reviews](M2_SEMANTIC_REVIEW.md), [case-unit eligibility](research/P1A_CASE_METHOD_ELIGIBILITY.md), [M2 #11](https://github.com/FardinSamin/ThreatRAGraph/issues/11) and [P1a #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24).

## Why the boundary is necessary

The original GHSA extractor yields `vulnerability:CVE-2024-21626 AFFECTS software-product:go/github.com/opencontainers/runc` as a **candidate**, not a verified semantic claim. Its evidence comes from **two distinct JSON scalars**: `/aliases/<index>` supplies the CVE and `/affected/<index>/package/name` supplies the package. Neither scalar, by itself, proves the full relationship. The existing `sourced_claims` v1 schema supports **one locator and one evidence digest**, and `SemanticReviewLedger` only permits a reviewer decision for an already-existing, byte-aligned sourced claim. Automatically reusing either one of those scalar field digests as the complete supporting excerpt would misrepresent what was reviewed.

## Implementation

- `src/threatragraph/ghsa_review_packets.py` **re-extracts** the candidate from the supplied SHA-256-pinned original bytes rather than trusting a caller-supplied candidate JSON. Both scalar paths are independently resolved through existing `evidence_alignment._evidence_bytes` and rehashed. Candidate ID and packet ID commit to exact source bytes, typed triple and ordered field locators/digests. The packet never includes source body text.
- Optional reviewer attestations use the existing M2 `supported_by_excerpt / uncertain / unsupported_by_excerpt` decision vocabulary and reviewer-ID/time format, with a meaningful bounded rationale. Decisions are **self-declared**, not independently authenticated; even a `supported_by_excerpt` review does not approve the source or create a real scientific claim.
- `CompoundCandidateReviewLedger` persists an attestation in a **separate append-only SQLite store/table** named `ghsa_candidate_reviews`, after independently reconstructing the packet from original bytes. Identical repeated attestations are idempotent; different reviewer/decision/rationale records for a frozen packet conflict and require a separately versioned run or review adjudication. It refuses sharing a database with `sourced_claims`, `source_versions` or `semantic_reviews`.
- `scripts/review_ghsa_candidate.py` is a bounded offline CLI. Previewing a packet does not create a database. Recording requires both explicit `--review-file` and `--database` arguments; no source bytes are committed to the repository.

## Windows PowerShell workflow

1. Privately preserve permitted original source bytes and verify the [independently retained historical witness](research/P1A_ORIGINAL_ADVISORY_WITNESS.md); independent source rights and historical cutoff signoff remain separate.
2. Run `python -m scripts.extract_ghsa_candidates --input-file .\data\private\runc-ghsa-original.json --source-version-id candidate:runc-ghsa-original:20240131 --expected-sha256 <original_verified_digest>` to obtain a deterministic `candidate_id`.
3. Inspect both source fields and write a **manual** JSON review file in ignored private storage with the following exact keys: `schema_version="ghsa-compound-candidate-review-v1"`, `packet_id`, `candidate_id`, `source_version_id`, `source_sha256`, `decision`, `reviewer_id`, `reviewed_at`, `rationale`. Generate `packet_id` first using the command below without the review/database options.
4. Preview (no write):

~~~powershell
python -m scripts.review_ghsa_candidate --input-file ".\data\private\runc-ghsa-original.json" --source-version-id "candidate:runc-ghsa-original:20240131" --expected-sha256 "<original_verified_digest>" --candidate-id "<exact_candidate_id>"
~~~

5. Once the manual decision has been recorded outside Git, persist it to the **independent candidate review database**:

~~~powershell
python -m scripts.review_ghsa_candidate --input-file ".\data\private\runc-ghsa-original.json" --source-version-id "candidate:runc-ghsa-original:20240131" --expected-sha256 "<original_verified_digest>" --candidate-id "<exact_candidate_id>" --review-file ".\data\private\ghsa-review.json" --database ".\data\private\ghsa-candidate-reviews.sqlite"
~~~

No cloud account, network, paid service, LLM, or real-source fixture is needed for the normal command. The database and original bytes must remain outside Git. Both commands refuse bad source bytes, incorrect hash/IDs, wrong reviewer linkage, malformed JSON and unsupported types. Database writing occurs **only** on the explicit review path.

## Research and integration limitations

- The standalone candidate review table is **intentionally not** `sourced_claims` or `semantic_reviews`. The actual scientific M2 ledger remains gated on separately **approved source versions, authentic time-eligible source archives, one-or-more claim evidence fields with a versioned schema, and independent human semantic review**. No migration or promotion to the scored graph has been implemented.
- The packet verifies **two field byte identities**, not that the source's claim is true, not the publication time, and not actual exploitation. The source manifest remains candidate-only. The reviewing individual's identity is not authenticated.
- The reviewed vulnerability target still **cannot run as an eligible G1 v2 analogy target**, because `USES` and `HAS_BEHAVIOR` exclude vulnerabilities. The combined fields establish no predictions or later-outcome labels.
- No source, report body, archive, private reviewer file, or real empirical evaluation is committed. The synthetic regression tests exercise tampering, exact provenance binding, isolation and conflict refusal, not scientific approval.

**Next required work:** after approval of real source rights/cutoff and a versioned design, add verified multi-field claim support to the actual sourced-claims/evaluator schema (with migrations and fail-closed temporal tests), then independently review/score extracted claims. Do not silently convert this sidecar review into a `semantic_reviews` record.
