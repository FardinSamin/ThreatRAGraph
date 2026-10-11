# P1g — Original Common Crawl CDXJ byte-range discovery without the rate-limited index API

**October 11, 2026 EDT.** **Research disposition: alternate direct-source-index retrieval has been demonstrated, but the lookup must reproduce the already-known genuine Cado record before any new CrowdStrike absence or candidate claim is trusted. No new original CrowdStrike/Sysdig page HTML has been certified in this phase.**

## Why an alternate route was necessary

In P1f, eight direct searches for CrowdStrike first-party, its CrowdStrike-authored Cloud Security Alliance republication and the early Sysdig article returned **HTTP 504** from `index.commoncrawl.org`. Common Crawl [explicitly warns](https://commoncrawl.org/faq) that its public CDXJ API is heavily rate-limited, with 503 errors a reason to slow down rather than retry aggressively. A 504 is likewise an access problem, **not a negative article-archive observation**.

Common Crawl [documents direct indexed archive files](https://commoncrawl.org/cdxj-index): each monthly crawl publishes a sorted **`cluster.idx`** and compressed **`cdx-*.gz`** index blocks, accessible over public HTTPS through `data.commoncrawl.org`, without paid AWS Athena or other AWS account services. The direct-CDXJ method searches the **existing archived index bytes**, not alternative proxy routes to evade API usage constraints.

I implemented `scripts/probe_direct_original_cdxj.py` to use that distinct data-access method:

- Allowlist specific original investigator/publisher URLs and exact 2022–23 monthly crawl IDs from the existing source register; no arbitrary code execution or webpage scraping.
- Query each crawl's `cluster.idx` using an HTTPS HEAD to learn the bounded size and a **serial, bounded binary search** over byte-range reads; require actual HTTP 206 and exact `Content-Range`, never accept HTTP 200 full-file substitution for an intended partial range.
- Use sorted SURT URL boundaries to identify at most **five** relevant compressed `cdx-*.gz` index members per exact query; verify offsets and lengths before reading, decompress to a bounded 16 MiB, and use the **exact archived JSON `url` field** to identify the publisher page. This is necessary because historical SURT normalization can differ, e.g., `www` handling. Prefer exact observed URL over guessed canonical URLKEY.
- Emit only metadata (CDX timestamp, first-party URL, WARC locator and digest, bounded original index-local hash/byte-range provenance), **never article bodies or malware scripts**.
- Mark capture records **`original_article_body_recovered=false`**, independent date provenance unknown, source approval false, rights unknown, `research_ready=false`. Any later WARC payload must pass the existing strict byte-level verifier and independent review.
- **Known positive control:** the search only counts as independently validated for CC-MAIN-2023-06 when it finds the already independently verified **2023-02-06 12:05:44 UTC original Cado capture** at the exact WARC locator/digest from [P1e](P1E_CADO_FEB2023_REAL_PRIMARY_WARC.md). `--require-cado-positive` fails closed rather than allowing a broken index parser to report a false "not archived."

## Real first run and its explicit flaw

In GitHub Actions [run 38112369253](https://github.com/FardinSamin/ThreatRAGraph/actions/runs/38112369253), the direct index reader successfully downloaded **actual byte ranges** from the **151,525,217-byte CC-MAIN-2023-06 `cluster.idx`** and several bounded CDXJ gzip members, without touching the rate-limited search endpoint or incurring paid cloud charges. The initial query reported zero exact-URL matches for the two Cado aliases and two CrowdStrike aliases.

**That zero is *not a valid historical absence finding*.** P1e already demonstrated the original Cado 2023-02-06 HTML capture using both a real official CDX row and its independent **22,387-byte actual WARC member**. Thus, the initial direct-CDXJ implementation was demonstrably missing a known source. Diagnostic output showed the selected SURT boundary region correctly included the Cado and CrowdStrike host neighborhoods. I corrected an unsafe URLKEY-filtering assumption: **do not require a reconstructed stripped-`www` URLKEY prefix when exact archived source URL is authoritative**; older CDXJ URLKEY variants may preserve host labels.

I additionally made the **known real Cado positive control mandatory in the exploratory CI job**. If a real Cado CDXJ row cannot be reproduced, the job refuses validation rather than purporting to disprove historical article availability or report that CrowdStrike has no capture. All source-version and claim approvals stay false.

## P1g follow-up: preserved-www keyspace coverage (unverified on real index)

The initial source-index probe searched only the normalized apex SURT key. A
separate unit test already accepted JSON records whose actual CDXJ key retains
`www`, but it did **not** prove the cluster-index locator reached that keyspace.
The updated offline search independently bounds and probes both apex and
preserved-`www` SURT positions for registered `www.` URLs, deduplicates matching
WARC locators, and reports coverage failures separately from misses. A regression
fixture places the genuine known-Cado locator under preserved-`www` after twelve
sorted apex chunks, beyond the original five-block neighborhood. Only the
exact archived JSON source URL and original WARC locator can satisfy the positive
control. This is an engineering correction and synthetic validation, **not
verification of the live historical index**. Do not merge until current-head
CI starts and the real positive control and all twelve jobs pass.

## P1g index-record chronology hardening (candidate-only)

The bounded CDXJ reader now checks that the indexed-line capture timestamp
matches the embedded JSON timestamp, refuses duplicate JSON fields and
oversized/malformed index lines, and hashes each observed original CDXJ
metadata record. Regression tests cover inconsistent dates, duplicate-key
spoofing and deterministic record fingerprints. The digest is a **record
identity receipt**, not an independent publication-time certificate.
Replaying the exact Common Crawl index bytes and matching the previously
authenticated original Cado WARC record remains a mandatory unfulfilled
live verification step.

## Exact positive-control WARC identity hardening

The mandatory Cado positive control now checks the **complete original archive
record identity** pinned by P1e: publisher URL, capture timestamp, HTTP 200,
HTML MIME, original WARC **filename**, compressed record offset/length,
payload digest and pre-cutoff candidate classification. An index entry
borrowing the same numeric offset and digest but pointing to a different WARC
file, or claiming a non-200/non-HTML response, cannot validate the lookup.
Synthetic adversarial regressions exercise each field; neither source rights
nor the first 2022 publication timestamp are independently certified here.

## Current CI runner constraint

Following multiple successful archived index read runs, [a subsequent workflow run](https://github.com/FardinSamin/ThreatRAGraph/actions/runs/38112454293) and its retry failed **before any job step started**: each job returned an empty step list and runner logs were unavailable (`BlobNotFound`). These are **job orchestration/start failures**, not executed unit-test, WARC-identity, security or index-lookup failures. GitHub [documents Actions job diagnostic steps](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs); the platform status page may show operational even when a particular account's runners cannot start.

**Private-repository quota caution (confirmed via GitHub repository API):** `ThreatRAGraph` currently reports `private=true` / `visibility=private`. [GitHub's official billing documentation](https://docs.github.com/en/billing/concepts/product-billing/github-actions) states that private-repository GitHub-hosted CI consumes included Actions minutes and can be billed beyond the account allowance. **Whether this specific account has exhausted its allotment, has a payment method, or has triggered another runner restriction is NOT verified**. Do not enable a paid plan/spending limit or turn the repository public without explicit user approval. To prevent further redundant private-runner usage once access resumes, the branch adds workflow-level `concurrency` with `cancel-in-progress: true`, grouped separately for each push branch ref and PR ref. This cancels superseded CI heads but preserves the independent final-head push + PR merge criteria.

**No claim is made that latest-head push or PR CI is green. Do not merge this branch on an older run, or automatically waive real-source reproducibility.** Once GitHub-hosted jobs can start again, verify both final-head push and PR workflows (Ubuntu/Windows tests, security and all source receipts), particularly that `known_cado_20230206_positive_control_matched=true`.

## Research next step

Once the verified Cado positive control passes, run direct original-file index lookups across the registered historical CrowdStrike/CSA paths in 2022–23 crawl snapshots. An eligible **original CrowdStrike first-party 200 HTML record** would provide a candidate WARC filename/range/digest to replay, **not automatic approval**. The CSA republication belongs to the CrowdStrike evidence lineage and must never be counted as an independent researcher group. For SCARLETEEL, search only the narrow verified February 28 2023 early report interval; do not move the proposed cutoff silently or read later gold labels.

**Scientific state unchanged:** 30 candidate source versions, **0 approved source versions**, **0 selected cases**, **0 empirical B0/G1**. Existing Cado original HTML WARC is still a byte-verified candidate requiring independent source-rights, observed-time and semantic/variant review.

[Prior first-party Cado historical bytes](P1E_CADO_FEB2023_REAL_PRIMARY_WARC.md) · [Exact original Cado paragraph reviewer SHA-256 cues](P1F_CADO_EVIDENCE_BLOCK_HASHES.md)
