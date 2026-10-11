# P1e — Real byte-verified original Cado Kiss-a-dog research webpage, February 6, 2023

**Scientific disposition: real pre-cutoff original-publisher *capture candidate* recovered and exact HTML bytes replayed; research source version/case STILL UNAPPROVED.** This is a materially different kind of historical evidence from PR #47's Securonix derivative IOC pointer or PR #48's independent GitHub PushEvent of that pointer.

## Actual acquisition and verified historical bytes

I queried the official Common Crawl CDX index `CC-MAIN-2023-06` for the **original Cado-publisher URL**:

`https://www.cadosecurity.com/kiss-a-dog-discovered-utilizing-a-20-year-old-process-hider/`

The genuine live index response (CI run [38110672261](https://github.com/FardinSamin/ThreatRAGraph/actions/runs/38110672261), saved metadata-only receipt) reported **one HTML 200 candidate record**, with an archive **observation timestamp of 2023-02-06 12:05:44 UTC** — **before** SCARLETEEL's *proposed* early-view cutoff **2023-03-01 00:00:00 UTC**.

| Field | Exact verified evidence |
| --- | --- |
| Original 2022 investigator | Cado Security Labs; first-party **Kiss-a-dog Redis honeypot** article |
| First-party page path captured | `/kiss-a-dog-discovered-utilizing-a-20-year-old-process-hider/` (not the present migrated `/blog/` path) |
| Official archive index | `CC-MAIN-2023-06` |
| Raw CDX timestamp | `20230206120544` (2023-02-06 12:05:44 UTC, archive-declared) |
| Archived WARC filename | `crawl-data/CC-MAIN-2023-06/segments/1674764500339.37/warc/CC-MAIN-20230206113934-20230206143934-00755.warc.gz` |
| Compressed WARC HTTP range | `bytes=696857860-696880246` |
| Exact compressed member size | **22,387 bytes** |
| WARC gzip member SHA-256 | `0e2cdbd6b1c58f8ae6737c1570d0000346d660d4c7047d89692d18543755478d` |
| Exact original HTML captured response | **92,875 bytes** |
| Original historical HTML SHA-256 | `b3482293f74524efa323ffcf18e138192b2137f6ceda143ddc89e1302c88ef83` |
| Common Crawl payload SHA-1/Base32 | `IIQQZYE7EHNZFM6CFTJLNT226VHY2D3P` (matches actual reconstructed HTML body and WARC payload digest) |
| Archive HTTP retrieval status | **206 Partial Content**, checked exact `Content-Range` and received member length |
| Archived WARC/HTTP original status | **200 HTML**, original `WARC-Target-URI` and `WARC-Date` agree with CDX |
| Original 2023 HTML title and text checks | Visible `Kiss-a-Dog` / `process hider` title, and literal **Redis, XMRig, XHide** tokens in parsed HTML text, excluding scripts/styles |
| Research source version | `candidate:kissadog-cado-202212:unfrozen` — **not approved** |

The live CI workflow fetched **exactly that bounded byte range from `https://data.commoncrawl.org/`**. The original `scripts/verify_candidate_warc_capture.py` independently decompressed **a single complete gzip WARC record**, enforced WARC and archived HTTP headers and byte counts, recomputed its original HTML SHA-1/Base32 (matching *both* CDX and WARC payload digest) and SHA-256, and returned the metadata-only witness above. The real archived HTTP response legitimately repeats `Vary`: we explicitly permit repeated **`Vary` and `Set-Cookie` only for archived HTTP response headers**, while duplicate security-sensitive fields (e.g. `Content-Length`, `Content-Type`, `Content-Encoding`, WARC digest) **remain refused**. This is supported by regression tests.

A new original-page identity screen uses Python's inert `html.parser.HTMLParser` to inspect **bounded literal HTML text**, skipping script, style and embedded SVG content. It confirms the original article title and these *literal* visible textual identifiers: **Kiss-a-Dog, Redis, XMRig, XHide**. This is a page-matching sanity check, **not** semantic adjudication that any actor/campaign used XHide, or that the paragraph's words establish a predictive result. It performs no script execution or JavaScript extraction.

## What this actual original HTML DOES and DOES NOT prove

**New valid achievement:** a real, byte-verified archived response from the **original publisher's historical report URL** exists in Common Crawl's February 2023 archive. We have the exact **content hash and byte count**, verified WARC/HTTP integrity, and the necessary campaign/XMRig/XHide literal tokens in the original captured **2023 pre-cutoff webpage**.

**Still outstanding:**

- Common Crawl's CDX and WARC timestamp is the **archiving service's recorded observation**; there is no separately audited signed timestamp or independent reviewer attestation yet. It is an archive-level claim; we must not rewrite `available_at` in the approved manifest as if a researcher independently certified first-public time.
- This is **February 6 2023 page HTML**, **NOT** the page's exact first-publication December 2022 version. This page could have changed between publication and capture. We may use it as a candidate **Feb 6 as-of snapshot** (before March 1) after time/rights review, but must never call it a proven December 2022 text version.
- We have **NOT** approved publisher copyright/redistribution rights. Raw HTML and derived proprietary source text are stored **only temporarily** in CI runner storage; the public repository and retained 14-day GitHub Actions artifact include **only original CDX locator metadata / hash-only receipts**. Do not commit/reproduce third-party HTML bodies.
- Visible HTML tokens alone do NOT prove the typed graph claims `campaign:Kiss-a-dog USES tool:xmrig` or `campaign:Kiss-a-dog USES tool:xhide`. An independent reviewer must read the original page legally and decide which variant or campaign each claim actually describes, with byte offsets or robust text-quote locators and positive/negative/uncertain polarity.
- The [CrowdStrike original 2022 article](P1C_KISSADOG_SAME_PEER_CHAIN.md) is still not historically byte-recovered, although a [December 9 2022 Cloud Security Alliance republished copy](https://cloudsecurityalliance.org/blog/2022/12/09/new-kiss-a-dog-cryptojacking-campaign-targets-vulnerable-docker-and-kubernetes-infrastructure) explicitly attributes its material to CrowdStrike. A republication counts as **CrowdStrike's research lineage**, not an independent new investigator group.
- The **original Feb 28 2023 Sysdig SCARLETEEL page** has not been byte-frozen before its extremely narrow **March 1** cutoff. Previous snippets of later research were exposed, so a separate **blinded** gold labeler remains necessary; case exclusion or prospective date redesign must be considered if original early sources cannot be attested.

## Reproduction and strict fail-closed gates

The original CDX metadata is pinned as **actual observed index facts** in:

`datasets/provenance_pointers/cado_kissadog_20230206_ccmain202306.json`

`scripts/replay_original_cado_20230206.py` holds independently checked expected URL, CDX timestamp, filename, offset, byte length, digest, 206 Content-Range and source ID. Any locator modification fails; the script accepts **only the pinned original 2023-02-06 Cado capture**, not arbitrary later captures. It invokes the general strict `scripts/verify_candidate_warc_capture.py` utility, where one explicit Cado historic-page URL alias was added without admitting arbitrary pages on `cadosecurity.com`.

The dedicated **new 11th GitHub Actions job** re-fetches the original exact 22,387 bytes via TLS/HTTP range, enforces the original 206 and decoded WARC consistency, screens original publisher article text for expected identifiers, then retains **only 14-day metadata/hashes**. The **10th new job** queries multiple official historical index collections for the original Cado, CrowdStrike and Sysdig URLs and the CrowdStrike-authorized CSA republication. Its discovery receipts distinguish **HTTP 503 transport/backend errors from definitive absent records**. The live run returned one qualifying Cado index candidate; most other attempted index queries returned **503**, so **they are inconclusive, not negative evidence**.

Command for a permitted offline researcher copy (assuming an independently downloaded exact gzip WARC member and original HTTP Range response headers):

```powershell
python -m scripts.replay_original_cado_20230206 --warc-member data/private/cado-original-20230206.warc.gz --range-headers data/private/cado-original-20230206-range-headers.txt
```

**Remaining science gate:** As-of source version/date and permissions approval, variant-aware original Cado claim review, historical CrowdStrike first-party text, the original early Sysdig report, declared-group independence review and strictly blinded later labels. **G1 two-group minimum unchanged.** 30 source candidates; **0 approved source versions**, **0 approved cases**, **0 actual B0/G1 comparisons**.

[Related P1c same-peer source-path screen](P1C_KISSADOG_SAME_PEER_CHAIN.md) · [P1d independent public pointer witness](P1D_KISSADOG_PUBLIC_PUSH_WITNESS.md)
