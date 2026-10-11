# P1b — Real original MITRE ATT&CK 2022 STIX record: TeamTNT *actor* and Chimaera citation discrepancy

**Screen date:** October 10, 2026 EDT. **Status:** original *MITRE-curated ATT&CK publisher-controlled* source file is reproducibly Git-blob verified, but not an approved research source. **It is not the original AT&T Alien Labs September 2021 report.**

Related research: [SCARLETEEL campaign peers](P1B_SCARLETEEL_CAMPAIGN_PEERS.md), [2021/2022 historical Chimaera bibliography pointers](P1B_CHIMAERA_HISTORICAL_BIBLIOGRAPHY.md), [original research page WARC intake](P1B_COMMONCRAWL_PRIMARY_WARC_INTAKE.md) and [case eligibility gate](P1A_CASE_METHOD_ELIGIBILITY.md). Tracking: [#24](https://github.com/FardinSamin/ThreatRAGraph/issues/24), [#21](https://github.com/FardinSamin/ThreatRAGraph/issues/21), [#3](https://github.com/FardinSamin/ThreatRAGraph/issues/3).

## A genuinely recoverable historical source **of a different kind**

MITRE itself committed a [STIX 2.0 TeamTNT intrusion-set bundle](https://github.com/mitre/cti/blob/4cbf8cc4bdf2121ee987a23bfe5aac4fe4d2f5b1/enterprise-attack/intrusion-set/intrusion-set--35d1b3be-49d4-42f1-aaa6-ef159c880bca.json) into its `mitre/cti` repository, in the revision labeled **ATT&CK v12.1 Enterprise**.

| Field | Original fixed source |
| --- | --- |
| Original repository | `mitre/cti` |
| Git commit | `4cbf8cc4bdf2121ee987a23bfe5aac4fe4d2f5b1` |
| Git source path | `enterprise-attack/intrusion-set/intrusion-set--35d1b3be-49d4-42f1-aaa6-ef159c880bca.json` |
| Git blob identity | `ce5239cb22093656b3f8e79fbd356a17b1fa5f19` |
| Git declared committer timestamp | **2022-11-08T14:56:14Z** — unverified as first public availability |
| STIX container | `type=bundle`, `spec_version=2.0`, one embedded object |
| Original embedded entity | `type=intrusion-set`, `id=intrusion-set--35d1b3be-49d4-42f1-aaa6-ef159c880bca`, `name=TeamTNT`, `x_mitre_version=1.2` |
| Embedded object modified time | `2022-10-19T21:35:03.147Z` — internal metadata, NOT external publication proof |
| Primary article *reference only* | `https://cybersecurity.att.com/blogs/labs-research/teamtnt-with-new-campaign-aka-chimaera` |
| Contradictory reference source-name label | `ATT TeamTNT Chimaera September 2020` |
| Actual citation text inside that same reference | “AT&T Alien Labs. (**2021, September 8**). TeamTNT with new campaign aka Chimaera.” |

This now identifies an upstream source for the **2020/2021 reference discrepancy** observed in the RealityNet MITRE bibliography. It is not two independent pieces of primary chronology evidence: the RealityNet bibliography appears to reproduce MITRE reference data, and the old Metarget bibliography is a separate dated URL pointer, not original Chimaera report content. **Do not treat a label saying September 2020 as evidence that the Chimaera campaign was published in 2020.**

## Why the STIX object does not solve SCARLETEEL campaign G1

MITRE classifies the entity as **`intrusion-set:TeamTNT`**, the threat group. It cites the separate *Chimaera* campaign's AT&T research in a reference list, but does **not** express `campaign:Chimaera USES tool:xmrig` as a source-asserted relation.

Therefore:

- DO NOT map the STIX intrusion-set object to `campaign:Chimaera`, and do not infer an alias between TeamTNT actor and Chimaera campaign.
- DO NOT use the reference URL/citation as byte-level evidence for XMRig. The original AT&T 2021 article **body has not been archived from an authenticated pre-cutoff source**.
- DO NOT count MITRE's curation, RealityNet's derived bibliography, and the original AT&T article as three independent Chimaera *investigations* or same-peer support groups.
- DO NOT import ATT&CK references, aliases, links or technique edges from a later version into earlier G1 snapshots merely because the referenced threat was described earlier.
- DO NOT treat the source as historic MITRE authorization for an automated scored B0/G1 campaign experiment. It is an **unapproved ATT&CK background source prospect** needing independent publication chronology and reuse rights review.

## What we actually implemented and live verified

`scripts/verify_original_mitre_teamtnt.py` is an **offline, fail-closed original-source byte verifier**, distinct from the previous Git *bibliography pointer* verifier:

1. Input is the complete source **original MITRE JSON bytes**, no network execution or implicit checkout. It enforces **96 KiB max**, regular non-symlink file.
2. Recomputes Git object ID as `sha1(b"blob " + ASCII_BYTE_COUNT + NUL + original_bytes)` and compares to the fixed MITRE blob hash; source edits invalidate it.
3. Strict JSON parse rejects duplicate keys. Requires exact STIX 2.0 bundle and TeamTNT **intrusion-set**, one object, original identity/version/time, exact alias list and one specific AT&T Chimaera source reference with both the mistaken 2020 label and actual September 2021 bibliography date.
4. Emits only metadata-only receipt, full original source SHA-256 and byte count, plus `source_version_approved=false`, `source_availability_independently_verified=false`, `actor_to_campaign_relabeling_authorized=false`, `original_chimaera_report_bytes_present=false`, `g1_evaluation_eligible=false` and `research_ready=false`.
5. A **seventh GitHub Actions job** fetches exactly the original primary `mitre/cti` source bytes at the fixed 2022 Git commit from `raw.githubusercontent.com`, validates them and retains a **14-day hash-only receipt**, not the raw STIX content. The existing source bibliography, signed runc and GHSA jobs remain active.
6. Adversarial tests check byte pin/tampering, wrong bundle/object type, actor/campaign masquerading, additional future aliases, missing/doubled Chimaera citations, wrong 2020/2021 discrepancy, unsafe oversized input and symlinks. No synthetic fixture is claimed as historical evidence.

**Provisional measured provenance:** original Git SHA-1 blob is pinned above. CI computes the actual source byte SHA-256 dynamically and prints it only in a non-sensitive receipt. The candidate manifest's **approved** `sha256`, `available_at`, `date_confidence` and rights fields remain null/unknown until independent investigator review.

The source registry now contains **29 unapproved candidates** (one new `attack_stix` original MITRE version), **0 approved sources**, **0 selected real cases** and **0 empirical B0/G1 results**.

## Next critical work

The verified MITRE record advances **M1 real historical-source and identity mapping capability**, not the SCARLETEEL campaign itself. Continue separate primary original-report byte acquisition for AT&T 2021, CrowdStrike 2022 and Sysdig Feb 2023. Reconcile author/publisher rights and original public-by dates independently of Git committer metadata. If a defensible original early SCARLETEEL report is unavailable before cutoff, **exclude it or preregister a new, prospective cutoff and source protocol before held-out labels**; do not backdate a later revision.

Also locate actual independently authored *per-campaign* corroboration and an as-of genuine **novel relation**; keep the fixed G1-v2 two-group per-peer support rule unchanged. Later gold labels require an independent blind reviewer because early source discovery exposed brief later-result summaries.

**Scientific disposition:** original byte integrity of one real publisher-controlled 2022 ATT&CK file can be verified in CI. There is still **no certified first-public timestamp, no approved right to redistribute, no primary 2021 campaign report, and no research result.**
