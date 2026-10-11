# P1a — Original GHSA live structured-evidence replay (candidate-only)

**Status:** this job fetches actual source bytes in an isolated ephemeral GitHub Actions runner and runs a local hash-pinned M2 extraction + two-field packet audit. It does **not** certify source rights, timestamp chronology, human semantics, research approval, a valid G1-v2 case, or successful historical prediction.

**Provenance link:** [original GitHub push event and source-byte witness](P1A_ORIGINAL_ADVISORY_WITNESS.md), [pinned 13,105-byte source SHA receipt](P1A_ORIGINAL_ADVISORY_RECEIPT.md), [compound evidence contract](../M2_GHSA_COMPOUND_REVIEW.md). Related [Issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24) and [Issue #11](https://github.com/FardinSamin/ThreatRAGraph/issues/11).

## Why this is a substantive next development check

Earlier tests used synthetic JSON to verify that the new GHSA adapter and companion reviewer store refuse fabricated locators. Now a **separate fifth CI job** downloads the actual original January 31, 2024 GitHub Advisory Database JSON from the **exact pinned public source commit** and verifies its **previously measured** SHA-256 (rather than merely trusting current HTML, commit dates, or claimed metadata).

The offline script `scripts/replay_original_ghsa_candidate.py` must independently confirm the original GHSA ID, exact `vulnerability:CVE-2024-21626` target, exactly one supported `AFFECTS` package candidate, original `software-product:go/github.com/opencontainers/runc` relationship, and **both actual original scalar byte digests** via `ghsa_review_packets.build_packet`. The source is never interpreted as an actual exploited incident. The job fails closed if the upstream file changes, any pinned digest differs, the expected scoped structured relationship changes, or either evidence locator no longer resolves.

## CI acquisition and local replay

- Source URL is commit-pinned:
  [GitHub Advisory Database JSON at 02a8b9a4...](https://github.com/github/advisory-database/blob/02a8b9a4f9d305f0e028ef58f0dcf28f55bf10ae/advisories/github-reviewed/2024/01/GHSA-xr7r-f8xq-vfvv/GHSA-xr7r-f8xq-vfvv.json).
- HTTPS-only download, timeout/size cap, no checkout or execution of third-party code, no AWS/Neptune/Bedrock/paid services.
- `python -m scripts.replay_original_ghsa_candidate --input-file <privately_preserved_original_bytes.json>` rechecks source version identity, size, sha, two exact JSON scalar evidence pointers and bounded candidate packet.
- Successful output is **`original_pinned_ghsa_field_bytes_verified_candidate_only`** and includes source SHA, byte count, candidate ID, packet ID and **hashes/locators only**. The source text itself is not printed or uploaded.
- A 14-day GitHub Actions artifact stores only the JSON receipt. The runner's temporary downloaded bytes are discarded.
- Unit tests are **synthetic negative/shape checks**. The CI original-source job (not those unit tests) is the actual authentic-byte exercise.

## What it does NOT establish

1. The original GH Archive event/commit push was independently replayed in a prior P1a manual witness, **not in this CI job**. Pinned Git source identity and modern HTTPS download do not alone prove when the bytes were originally publicly available; investigator acceptance of the GH Archive event evidence remains required.
2. Exact original text can be used for extraction **development**, but no source or reviewer is presently formally approved. The source registry's `sha256`/`available_at` approval fields remain unset.
3. The `AFFECTS` association is a **structured review candidate**, not an inserted M2 sourced claim. Two fields support it; the currently single-locator `sourced_claims` schema cannot silently promote it, even with a self-declared candidate review.
4. A vulnerability target is still **unsupported by G1 v2**. No later report was consulted or scored as held-out ground truth.
5. This is **one authentic historical source version**, not the needed independent early pair, background source groups, held-out novelty adjudication, 25–40 approved sources or 4–6 approved cases.

Passing this job verifies a **real original-source engineering vertical slice** and means nothing more. No empirical B0/G1 comparison exists.
