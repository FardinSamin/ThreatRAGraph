# P1b — Common Crawl primary-page WARC intake (candidate only)

**Date:** October 10, 2026 EDT. **Scientific outcome:** Not a recovered historical report and not an approved case. Historical target-specific Common Crawl and Internet Archive index endpoints were **unavailable from this browsing/network environment**; no WARC record or index match has been asserted. The new code is an **offline byte-integrity/acquisition gate** that can check a separately obtained authentic capture of a **primary researcher HTML page** instead of another derived citation.

Sources: [Common Crawl's official CDXJ index guide](https://commoncrawl.org/cdxj-index) and [Get Started: URL index and WARC range replay](https://commoncrawl.org/get-started). These establish the retrieval *method*, not the existence of an eligible target capture. Research context: [SCARLETEEL campaign peers](P1B_SCARLETEEL_CAMPAIGN_PEERS.md) and [Chimaera pinned third-party bibliographies](P1B_CHIMAERA_HISTORICAL_BIBLIOGRAPHY.md).

## What this gate actually checks

`scripts/verify_candidate_warc_capture.py` takes three local, untrusted inputs: a single JSON CDX record, **the exact compressed WARC member** fetched by byte range from that record's `filename`, `offset`, `length`, and the project's current draft source registry. It is **offline**, receives no source content from a network, executes no HTML and prints **hash-only metadata**, not the archived page.

It recognizes only three **already registered** unapproved original-research URLs: Sysdig SCARLETEEL (Feb 2023 original), Alien Labs Chimaera (2021 original) and CrowdStrike Kiss-a-dog (2022 original). It refuses an arbitrary target, a later SCARLETEEL report, an approved/fabricated manifest record or a changing source URL. It enforces the proposed **2023-03-01T00:00:00Z** research cutoff on the **self-reported CDX/WARC observation**, not on a date from today's website.

The verifier also rejects any claimed archive capture **before the publisher-reported release calendar date** for that report (Chimaera September 8 2021, Kiss-a-dog October 26 2022, SCARLETEEL February 28 2023). These dates are *screening-only plausibility lower bounds*, not independently certified original publication dates. A later-looking capture can still be modified or falsely dated.

The verifier requires:

1. Bounded official-style Common Crawl CDX WARC path, canonical publisher URL and nonnegative byte offset; exact 200 / HTML CDX metadata and bounded compressed length (**4 MiB max**).
2. One complete valid **gzip WARC record** (decompressed capped at **8 MiB**); refuses concatenated/truncated gzip, hostile paths, excessive content, missing WARC/HTTP framing, duplicate headers and redirects.
3. WARC `response` record, exact `WARC-Target-URI == CDX.url`, exact `WARC-Date` synchronized to the 14-digit CDX UTC timestamp and **strictly before** the proposed cutoff.
4. Complete WARC `Content-Length`, explicit HTTP 200, HTML response with no unexamined content/transfer encoding, and plausible HTML bytes (**4 MiB max**).
5. SHA-1/Base32 of the **captured HTTP HTML body** matching both the CDX `digest` and the WARC `WARC-Payload-Digest`. If WARC block digest exists, it also must match the complete archived HTTP block. SHA-256 of the gzip member and HTML is reported; no full HTML or WARC material is committed or printed.

**This does not prove the CDX JSON or supplied WARC member came from Common Crawl**: a person can fabricate both and compute matching hashes. It also does not independently authenticate the archive's observation timestamp, publisher content licensing, that no version changes occurred after disclosure, or semantic meaning of article statements. No research readiness/source approval/peer corroboration is conferred by a successful offline replay.

## Acquisition procedure for the researcher (manual, no code execution from articles)

First identify **one** matching pre-cutoff **actual** capture from a Common Crawl index. The [official index catalogue](https://index.commoncrawl.org/collinfo.json) enumerates available collections. Candidate months to investigate:

| Target original page | Prospect publication | Candidate archive windows |
| --- | --- | --- |
| Alien Labs Chimaera | 2021-09-08 | 2021's later crawls, such as CC-MAIN-2021-39/43/49; must be **before March 2023** |
| CrowdStrike Kiss-a-dog | 2022-10-26 | Late 2022 crawls, such as CC-MAIN-2022-49; must be **before March 2023** |
| Sysdig original SCARLETEEL | 2023-02-28 | Extremely narrow: a capture **after the public February 28 disclosure and before March 1 UTC**. Older 2023-06 crawls predate disclosure; later 2023-14 crawls generally postdate the cutoff. **A convenient post-cutoff copy does not count as the early source.** |

For an eligible index, manually query the API using the original or `www.` variant of the registered source URL and `output=json`. Do not treat a 404/no result or an inaccessible index as proof no historic page exists.

Select one actual CDX record with `url`, `timestamp`, `filename`, `offset`, `length`, `status`, `mime` and `digest`. Preserve that **one original line** in `data/private/cdx.json` (single JSON object) and record its HTTPS source/HTTP response metadata separately.

Using those **actual** index numbers, calculate `byte_start=int(offset)` and `byte_end=int(offset)+int(length)-1`, and download only that range over HTTPS from:

`https://data.commoncrawl.org/<filename-from-cdx>`

**Use `Range: bytes=<byte_start>-<byte_end>` and confirm HTTP 206 Partial Content, `Content-Range`, returned length, TLS/origin and download metadata.** Do not download a whole multi-gigabyte WARC, accept redirects to untrusted hosts, use fake offsets, or silently fall back to a current webpage. Save the *exact* received compressed member in ignored `data/private/capture.warc.gz`.

Then run:

```powershell
python -m scripts.verify_candidate_warc_capture --index-record data/private/cdx.json --warc-member data/private/capture.warc.gz --source-version-id candidate:chimaera-alienlabs-20210908:unfrozen
```

For the other two, replace `--source-version-id` with `candidate:kissadog-crowdstrike-20221026:unfrozen` or `candidate:scarleteel-sysdig-20230228:unfrozen`. The verifier emits only candidate evidence metadata. **Do not check third-party raw captures into Git.** Keep acquisition receipts and source rights decisions private, and obtain an independent time/origin review before any dataset status promotion.

## Recorded current result, limitations and next go/no-go

- This checkpoint adds **18 adversarial synthetic parser tests** and offline CLI/manifest smoke checks. Green tests prove only implementation properties, **not a genuine primary archive acquisition**.
- Public Common Crawl and Internet Archive archive lookup endpoints were not accessible here (web lookup rejected; direct container DNS unavailable). We therefore did **not** recover original 2021 Alien Labs, 2022 CrowdStrike or Feb 2023 Sysdig HTML bytes. The current 2021/2022 bibliography references remain valid *secondary* reference evidence and are not silently converted into article witnesses.
- If a valid primary pre-cutoff WARC is acquired, hash/provenance and exact permissible article bytes can be independently reviewed, followed by article-specific rights review and byte-aligned semantic candidate claims. G1 still needs the per-peer **two independent supporting publisher groups**, actually novel relation evidence, and independent blind later labels. Don't change G1-v2's thresholds to force a result.
- If the precise early SCARLETEEL public-by/cutoff requirement cannot be met, **screen it out** or propose a methodologically explicit *prospective redesign before labels are examined*; never backdate a later crawler capture.

**Registry status unchanged:** **28 metadata candidates, 0 approved original source versions, 0 selected cases, 0 real B0/G1 empirical results**.
