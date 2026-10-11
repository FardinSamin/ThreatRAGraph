# P1c — Kiss-a-dog original investigator chain: CrowdStrike + Cado

**P1f reviewer-location update:** the [real original 2023-02-06 Cado archived HTML](P1F_CADO_EVIDENCE_BLOCK_HASHES.md) now has *metadata-only exact SHA256 paragraph locators* for XMRig and XHide (including both lexemes in one original paragraph). The typed `USES` claims/variant semantics remain unreviewed, and CrowdStrike/Sysdig original archival discovery is still unresolved due Common Crawl 504 responses.

**P1e evidence update (October 11, 2026):** [Original Cado research page recovered from the genuine Common Crawl **February 6, 2023** historical HTML/WARC bytes](P1E_CADO_FEB2023_REAL_PRIMARY_WARC.md). The original old URL and all **92,875 archived HTML bytes** now have independently recomputed SHA256/CDX/WARC hashes; verified visible text includes Kiss-a-dog, Redis, XMRig, XHide. **Source approval, earliest-public timestamp, reuse rights, reviewer-aligned campaign/variant claims and actual G1 prediction remain absent**. Earlier below "original bytes not recovered" comments are historical to the P1c stage.

**Research checkpoint:** October 10, 2026 EDT. **Disposition: candidate method path found, no source/case approval or experiment.**

[SCARLETEEL v2 case screen](../../datasets/case_screenings/scarleteel_peers_v2.json) identified two historical named campaigns (Chimaera and Kiss-a-dog) with the same tentative XMRig feature, but the G1v2 ranker requires **two historical publisher groups within a single historical peer's matching-plus-new-relation evidence path**, not one publisher for each of two unrelated peers. This follow-up identifies a more concrete, **same-peer** research pair.

## Two distinct original investigators and their *unverified* candidate relations

| Original investigator / report | Original research finding | Proposed typed lead | Original historical source bytes approved? |
| --- | --- | --- | --- |
| [CrowdStrike: “New Kiss-a-Dog Cryptojacking Campaign Targets Docker and Kubernetes”](https://www.crowdstrike.com/en-us/blog/new-kiss-a-dog-cryptojacking-campaign-targets-docker-and-kubernetes/), by Manoj Ahuje, currently displays **October 26, 2022** | CrowdStrike's own Docker/Kubernetes honeypot investigation explicitly calls Kiss-a-dog a campaign; “Use of Dog Pools and Disguised Xmrig” identifies XMRig | `campaign:Kiss-a-dog USES tool:xmrig` | **No** — present page is not a historically frozen October 2022 version |
| [Cado Security Labs: “Kiss-a-Dog Discovered Utilizing a 20-Year-Old Process Hider”](https://www.cadosecurity.com/blog/kiss-a-dog-discovered-utilizing-a-20-year-old-process-hider), by its cloud threat researchers (historical coverage credits Matt Muir) | Cado says its **own Redis honeypot**, unlike CrowdStrike's Docker/Kubernetes vantage, was compromised by a **newer Kiss-a-dog variant**. The researchers inspected payloads, identified XMRig, and actually **tested the XHide process hider** used to camouflage an XMRig process as `sendmail`; the article explicitly acknowledges and distinguishes the original CrowdStrike reporting | Shared feature `campaign:Kiss-a-dog USES tool:xmrig`; **additional hypothetical historical peer relation** `campaign:Kiss-a-dog USES tool:xhide` | **No** — the original Cado URL migrated/redirects to Darktrace; current indexed report body is not byte-aligned to the December 2022 historical page |

**Independent original investigation, not independent truth automatically:** Cado directly cites CrowdStrike's original work and attributes the overarching campaign name to it. The Cado Redis honeypot analysis describes *new observations* rather than simply republishing CrowdStrike. The independent data-collection and semantic/variant scope still need human source review; `independence_group` labels express intended provenance, not verified independence.

## A concrete historical breadcrumb of the otherwise moved Cado article

The security vendor [Securonix's AutonomousThreatSweeper Git commit `79b944c177a8640fb8f5396515daf2c249a43b15`](https://github.com/Securonix/AutonomousThreatSweeper/commit/79b944c177a8640fb8f5396515daf2c249a43b15) records a Git-declared committer time **2022-12-23T11:42:26Z** and includes these two exact source files:

| Pinned original file | Git blob SHA-1 | Material |
| --- | --- | --- |
| [`New_Variant_of_Kiss_a_Dog_Cryptojacking_Campaign/References.txt`](https://github.com/Securonix/AutonomousThreatSweeper/blob/79b944c177a8640fb8f5396515daf2c249a43b15/New_Variant_of_Kiss_a_Dog_Cryptojacking_Campaign/References.txt) | `12bd1a3b9158c39270ba10727d03b349f13302ea` | Original `https://www.cadosecurity.com/kiss-a-dog-discovered-utilizing-a-20-year-old-process-hider/` URL |
| [`New_Variant_of_Kiss_a_Dog_Cryptojacking_Campaign/README.md`](https://github.com/Securonix/AutonomousThreatSweeper/blob/79b944c177a8640fb8f5396515daf2c249a43b15/New_Variant_of_Kiss_a_Dog_Cryptojacking_Campaign/README.md) | `76844e58b73bda7e2af8d296f4cc9d0c2afc201e` | Seven derived sample hashes and a Kiss-a-dog campaign resource URL |

**P1d chronology evidence upgrade:** The [complete original GH Archive 2022-12-23 11:00 UTC public events hour](P1D_KISSADOG_PUBLIC_PUSH_WITNESS.md) now contains **PushEvent ID 26063265903, 2022-12-23T11:42:28Z**, corresponding exactly to the Securonix source commit; its commit/tree/two original Git blob path chain is independently replayed. This **does establish a third-party-recorded public GitHub push by December 23 2022 for the secondary Cado URL/IOCs**, replacing reliance solely on the Git committer timestamp. It **does NOT recover Cado's original report HTML, certify that report's publication time, or create another independently investigated claim**.

The same research title appears in [This Week in 4n6's **December 25, 2022** roundup](https://thisweekin4n6.com/2022/12/25/week-52-2022/), attributed to Cado researcher Matt Muir. These are **two contemporaneous pointer leads**, not a verified publication date for the *exact article content*.

`scripts/verify_kissadog_cado_pointer.py` replays **real exact 2022 Securonix Git file bytes** (using the pinned Git blob SHA-1 formula and SHA-256 of those exact inputs) from HTTPS in a dedicated **eighth GitHub Actions job**. The emitted receipt contains **only metadata**, while the archive downloads remain inside the ephemeral runner. It never repeats sample hashes or malware script text in output or commits third-party bytes. The receipt explicitly disclaims original Cado article bytes, independent server-observed Git public-push time, security rights, case approval and G1 corroboration. No source time is promoted merely because the commit says December 23, 2022.

**Key anti-inflation:** Securonix's reference and IOC list is **derived Cado reporting**, so do not count Securonix as a **third** independent field-investigator research group. The two *prospective* original data-collection groups are CrowdStrike and Cado, not CrowdStrike/Cado/Securonix/roundup.

## Why the actual G1 v2 code could plausibly use this path

Inspect `src/threatragraph/similarity_g1.py` in the loop over each individual `historical_peer_id`: it identifies a **same-type** peer sharing at least one early known `USES` feature; for a *different, previously unobserved relation* it unions publisher groups supporting that peer's shared matching feature and the proposed relation before testing `min_background_groups=2`.

A **hypothetical source-admissible** path (not real approved graph data):

```
early SCARLETEEL    --USES--> tool:xmrig   [Sysdig candidate; early source]
                                            ↕ typed shared feature
historic Kiss-a-dog --USES--> tool:xmrig   [CrowdStrike + Cado investigator leads]
historic Kiss-a-dog --USES--> tool:xhide   [Cado independent Redis variant lead]
                   (ONE peer; two declared original researcher groups in path)
                         |
                         +-- G1 prospective, unproven hypothesis:
                              campaign:SCARLETEEL USES tool:xhide
```

This does **not** assert SCARLETEEL ever used XHide. **Do not look at held-out later sources to answer that now.** Cado's **later variant relative to CrowdStrike** was reported in 2022, *before* the tentative March 1, 2023 SCARLETEEL cutoff; nevertheless, exactly when each 2022 report version became available must be independently verified. **XHide is not XMRig**, and the observed relation must be validated as applying to the particular Kiss-a-dog campaign/variant, not an invented alias or generalized mining technique.

`datasets/case_screenings/scarleteel_kissadog_chain_v1.json` and `scripts/screen_same_peer_candidate_path.py` now preregister and validate that **exact early feature / peer / two matching researchers / proposed XHide relation / source-group** configuration offline, with strict no-future/no-approval/no-ad-hoc-source-substitution rules. Its output reports **2 prospectively declared** per-peer groups, but forces `source_independence_verified=false`, `actual_primary_2022_source_bytes_approved=false`, `candidate_claims_byte_aligned_and_reviewed=false`, `g1_evaluation_eligible=false`, `research_ready=false`, and **zero scored predictions**. It preserves the previously disclosed later search-summary exposure.

**Crucial ranker distinction:** the two groups span **one Kiss-a-dog matching-plus-additional-relation path**. A different Chimaera peer cannot substitute for Cado. Securonix's derived IOC index cannot substitute for Cado independent observation. No G1 production/ranking code or its minimum corroboration has been relaxed.

## Remaining exact real-data gates

1. Acquire independently dated and authenticated **original pre-cutoff CrowdStrike and Cado report bytes** under reviewed rights, not today's migrated pages or a retrospective IOC link.
2. Acquire and approve the **very narrow original February 28, 2023 Sysdig page version** before March 1 UTC; exclude/re-preregister prospectively if impossible. The current verifier [CDX/WARC capture intake](P1B_COMMONCRAWL_PRIMARY_WARC_INTAKE.md) handles private original bytes but does not authenticate archive server origin.
3. Have an independent reviewer confirm both publisher groups independently *observed* `campaign:Kiss-a-dog USES tool:xmrig`, Cado observed XHide within the correctly typed campaign/variant, and no early SCARLETEEL report already asserts XHide.
4. Preregister the predicted relation and exclusion rules before an **independent blind later gold-label reviewer** sees the previously exposed short July 2023 later-source synopsis. Unknown/negative evidence should produce abstention or a correct negative finding rather than cherry-picked new features.
5. Only then consider independent science approvals, full corpus and a first paired B0/G1 run. Do not approve sources or claim genuine predictions via a screened **candidate shape**.

**After this checkpoint:** **30 unapproved candidate source leads, 0 approved source versions, 0 real cases, 0 empirical B0/G1 comparisons.**
