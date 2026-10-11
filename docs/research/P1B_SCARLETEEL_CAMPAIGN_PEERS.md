# P1b follow-up — Two named campaign peers with an exact shared XMRig feature

**Screened 2026-10-10 (EDT)** | **Decision:** *two promising same-type campaign candidates are identified, but G1 v2 is still **not eligible** to make any empirical prediction.* No source or case is approved, no exact historical page bytes are attested, and **no held-out later reference body or labels were read or extracted for this follow-up**.

Prior research: [SCARLETEEL candidate/method gate](P1B_SCARLETEEL_CAMPAIGN_SCREEN.md) and [screen v1](../../datasets/case_screenings/scarleteel.json). Machine-checkable updated candidate decision: [screen v2](../../datasets/case_screenings/scarleteel_peers_v2.json). This v2 file is an *append-only research decision revision*, not a mutation of the earlier v1 record. Run locally: `python -m scripts.screen_candidate_method`.

## Evidence-led candidate discovery

The previous background candidates were reports about **TeamTNT the threat actor**. Under G1 v2 they cannot simply be relabeled as campaigns, and we had not found valid same-type peer subjects. This follow-up found **two explicitly named campaign subjects** in original researcher articles whose *modern accessible copies* explicitly mention the same cryptominer as the prospective SCARLETEEL early relation.

| Prospective typed relation | Original researcher document | Dated on current public page | Concrete location cue | Actual frozen original bytes? |
| --- | --- | --- | --- | --- |
| `campaign:SCARLETEEL USES tool:xmrig` (early) | [Sysdig — SCARLETEEL operation](https://www.sysdig.com/blog/cloud-breach-terraform-data-theft) | February 28, **2023**, from indexed contemporaneous Sysdig items and same-day news | Original article's technical analysis names XMRig executable | **No** |
| `campaign:Chimaera USES tool:xmrig` (background candidate A) | [AT&T Alien Labs / current LevelBlue-hosted — “TeamTNT with new campaign aka Chimaera”](https://www.levelblue.com/blogs/spiderlabs-blog/teamtnt-with-new-campaign-aka-chimaera) by Ofer Caspi | September **8, 2021**, on current host | “Analysis of components used in the Chimaera campaign” → Windows XMRig miner; “Kubernetes root payload component” explicitly says it sets up the XMRig miner | **No** |
| `campaign:Kiss-a-dog USES tool:xmrig` (background candidate B) | [CrowdStrike — “New Kiss-a-Dog Cryptojacking Campaign…”](https://www.crowdstrike.com/en-us/blog/new-kiss-a-dog-cryptojacking-campaign-targets-docker-and-kubernetes/) by Manoj Ahuje | October **26, 2022**, on current host | “Use of Dog Pools and Disguised Xmrig” explicitly connects XMRig to the named campaign | **No** |

The two historical researcher publishers (Alien Labs and CrowdStrike) are **prospectively distinct** and from **different reports about different named campaigns**. Named campaign subject is the *campaign* `Chimaera` or `Kiss-a-dog`, **not** `threat-actor:TeamTNT`. CrowdStrike notes overlapping C2 history with other cryptojacking groups; any inferred common actor or causal attribution would require separate evidence and is **not** asserted here.

**Chronology corroboration (not primary-byte authentication):**
- [MITRE ATT&CK's TeamTNT source list](https://attack.mitre.org/groups/G0139/) identifies the Alien Labs Chimaera research dated September 8, 2021 and a later retrieval date, but the *current catalog* is mutable and its historical state is not independently replayed. It cannot stamp the exact LevelBlue page bytes.
- [Cloud Security Alliance, December 9, 2022](https://cloudsecurityalliance.org/blog/2022/12/09/new-kiss-a-dog-cryptojacking-campaign-targets-vulnerable-docker-and-kubernetes-infrastructure) explicitly attributes its republication to CrowdStrike's **October 26** original. CSA repeats the XMRig passage; it is **derivative from CrowdStrike, not a new independent supporting publisher group** and not the same as the original October file.
- [October 26 2022 independent SC Media contemporaneous coverage](https://www.scworld.com/analysis/researchers-uncover-cryptojacking-campaign-targeting-docker-kubernetes-cloud-servers) corroborates the public *calendar date* of the Kiss-a-dog report; it does not bind the original bytes. Modern posted timestamps do not establish the earliest available version.
- Sysdig's [Japanese-language page dated March 1, 2023](https://www.sysdig.com/jp/blog/cloud-breach-terraform-data-theft) identifies the English February 28 original, while its own content is **after** the proposed March 1 00:00 UTC cutoff and therefore **must not** enter early source inference. Independent republication/translations are not exact original article bytes or independent threat investigations.
- An attempt in this screening session to access Internet Archive CDX snapshot discovery through the available browsing interface returned an access error. **No February 2023 Wayback version was recovered or claimed**.

## Independent dated *bibliography pointer*, not original source-article approval

A follow-up [Chimaera historical Git-bibliography byte witness](P1B_CHIMAERA_HISTORICAL_BIBLIOGRAPHY.md) identifies and replays **two pinned 2021/2022 Git reference files** containing the **original AT&T URL and September 8, 2021 bibliographic citation**. RealityNet's bibliography also has a conflicting `September 2020` internal source-name label, which is explicitly flagged rather than promoted to a publication date. The [original MITRE ATT&CK v12.1 TeamTNT STIX data](P1B_MITRE_ORIGINAL_TEAMTNT_2022.md) proves the conflicting 2020 source-name/2021 bibliographic-date pair also exists in the publisher-controlled 2022 ATT&CK dataset; its entity is a TeamTNT **intrusion-set** and the original 2021 AT&T article **bytes**, original **public-by time**, and the campaign-to-XMRig **claim** remain unverified. A historical link citation is not a separately investigated report or G1 corroborating peer support.

## Why a named same-type peer is NOT yet sufficient for G1

Read `src/threatragraph/similarity_g1.py` around its per-peer candidate loop: for **each individual historical peer**, G1 collects **source independence groups across that peer's shared matching feature AND its proposed not-yet-seen relation** before checking `min_background_groups=2`. Two peer subjects each with one original publisher group **do not aggregate into two groups to validate either peer's proposed relation**. The ranker only combines corroborated per-peer hypotheses after that gate passes; it must **not** count the Alien Labs report for Chimaera as a second witness for an unrelated CrowdStrike Kiss-a-dog claim.

The newly discovered `USES tool:xmrig` relationships themselves are *matching features*, **not** automatically predicted new facts; SCARLETEEL's original report already indicates its XMRig miner, so inferring that SCARLETEEL used XMRig would be duplicate early knowledge, not net-new outcome.

Furthermore, the updated prospects remain zero-supported in the actual evidence graph: no exact historic version, no source rights review, no two independent publishers attesting *the same Chimaera/Kiss-a-dog claim chain*, no selected secondary candidate relation for prediction and no human semantic reviewer. **Do not weaken G1's required two independent groups** to make either peer appear eligible. A distinct research question or G1 v3 would require preregistration and independent review.

## Newly registered artifacts and safeguards

- Two additional *unapproved* source leads in M1 registry (28 total): AT&T Alien Labs Chimaera and CrowdStrike Kiss-a-dog, each with `status=candidate`, `sha256=null`, `available_at=null`, `date_confidence=unknown` and reuse rights `unknown`. A changed host/brand for the Alien Labs page is disclosed.
- [SCARLETEEL v2 screen](../../datasets/case_screenings/scarleteel_peers_v2.json) adds exactly two **typed same-feature candidate peers** and preserves the earlier proposed early source, contemporaneous derived date corroboration, **isolated July 2023 later lead** and `search_result_summary_exposed` risk disclosure. Earlier v1 [screen](../../datasets/case_screenings/scarleteel.json) remains for audit.
- `scripts/screen_candidate_method.py` accepts backward-compatible v1 plus stricter `g1-v2-prospective-case-screen-v2`, where every peer must: be a named, distinct campaign subject; cite an allowed unapproved background source; use exact `USES tool:xmrig` as the target's candidate early feature; have a distinct candidate publisher group; include a bounded location cue; and explicitly indicate `evidence_byte_aligned=false` and `semantic_reviewed=false`. New adversarial tests reject forged case readiness, future reference sources, weak type conversions and grouping tricks.
- Output still says `same_type_peer_verified=false`, `two_group_same_type_peer_claim_support_verified=false`, `g1_evaluation_eligible=false`, `research_ready=false`. The two typed peers are **unverified prospects**, not approved matching evidence or scoring inputs.

## Original publisher archive intake under construction

The [P1b Common Crawl CDX/WARC verifier](P1B_COMMONCRAWL_PRIMARY_WARC_INTAKE.md) now checks an investigator-supplied original HTML WARC member's size, URL, declared pre-cutoff time and exact CDX/WARC/HTTP content digests. The archive services were inaccessible here, so **no actual primary HTML capture has been obtained** and no case/source was approved. In particular, a Sysdig first-publication February 28 report needs an *extremely narrow* archive window before the March 1 UTC cutoff; a later March/April crawl is **not eligible early content**.

## Reproducible next empirical gate

1. Independently recover original **February 2023 Sysdig** bytes with externally supportable earliest public-by UTC timing, plus **2021 Chimaera and 2022 Kiss-a-dog** versions. Only after source licenses, dates, exact hash and reviewer approval can they change status.
2. Align and manually review actual **campaign → USES → XMRig** assertions from all three exact bodies, including entity and tool identifier scope without importing later aliases.
3. Find **independent same-peer corroboration across at least two historical groups**, **including the proposed additional relation** for any prospective candidate prediction. For Kiss-a-dog, Cado's own honeypot follow-up is a plausible separate investigation, but its **currently moved/redirecting publication page was not historically timestamped or frozen**; do not count it yet.
4. Freeze exact source IDs, cutoffs, methods, peer feature/claim families and abstentions **before** independent later reference annotations or results are consulted. Prior search-summary exposure necessitates blind external labeler; if not feasible exclude this case.
5. Request investigator/faculty screening signoff. Only then consider the first **development** experiment, followed separately by the full 25–40 source/4–6 case pilot.

**Disposition:** important positive *case search* advance; no research outcome. **29 candidate sources, zero approved source versions, zero selected cases and zero B0/G1 empirical comparisons.**
