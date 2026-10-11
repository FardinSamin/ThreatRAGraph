# P1b — Independently preserved *bibliography pointer* to the 2021 Chimaera report

**Research checked October 10, 2026 EDT. Status: real third-party original-URL citation bytes verified in pinned public Git objects, NOT the original AT&T Alien Labs 2021 article body or public posting time.** See [SCARLETEEL campaign peer dossier](P1B_SCARLETEEL_CAMPAIGN_PEERS.md), [case source registry](../../datasets/manifests/pilot.json) and [research issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24). This advances historical **reference provenance** but does **not** approve even one source.

## Exact independent source pointers

The original [Alien Labs “TeamTNT with new campaign aka Chimaera” article URL](https://cybersecurity.att.com/blogs/labs-research/teamtnt-with-new-campaign-aka-chimaera) (old `cybersecurity.att.com` host, now migrated to LevelBlue) is present **literally** in two separately authored historical Git bibliography files:

| Reference file | Fixed Git commit and original file | Git blob SHA-1 | Citation text | Commit date recorded by GitHub (NOT independently certified public time) |
| --- | --- | --- | --- | --- |
| Metarget's cloud-native-security curated README | [README.md at `9d68fc3a1e7a3790b12d59a120fb78ea2dd2b8d1`](https://github.com/Metarget/awesome-cloud-native-security/blob/9d68fc3a1e7a3790b12d59a120fb78ea2dd2b8d1/README.md) | `29f2948685b187be078a1d3f492d4a886e287e43` | TeamTNT with new campaign aka “Chimaera” (**2021-09-08**) plus original AT&T link | **2021-12-19T10:35:48Z** |
| RealityNet's MITRE attack-coverage bibliography export | [20220505/attack_groups.txt at `a933255173c0d512f712e2cb81a2067aa99a75a7`](https://github.com/RealityNet/attack-coverage/blob/a933255173c0d512f712e2cb81a2067aa99a75a7/20220505/attack_groups.txt) | `c51a7ae9d06cc31451bf9cad5b60a102b6f92aab` | “AT&T Alien Labs. (2021, September 8). TeamTNT with new campaign aka Chimaera.” with original AT&T link, and a **Retrieved September 22, 2021** statement (self-declared bibliography text) | **2022-05-05T14:44:52Z** |

**Upstream provenance update:** [MITRE's original November 2022 STIX TeamTNT record](P1B_MITRE_ORIGINAL_TEAMTNT_2022.md) independently confirms the very same `ATT TeamTNT Chimaera September 2020` **source-name** label and literal September **8, 2021** bibliographic citation within MITRE's publisher-controlled JSON. RealityNet's `attack_groups.txt` thus appears to reuse this MITRE-curated reference metadata; do **not** count the records as independent original threat investigations or assume the mistaken date originated independently.

**Important anomaly:** The RealityNet record labels this item `ATT TeamTNT Chimaera September 2020` in its internal `source_name` field **while the citation sentence says September 8, 2021**. The export's own label therefore conflicts with its dated bibliographic citation. It cannot be used to assign a **2020** disclosure date. The byte-verifier explicitly flags this conflict in its metadata receipt.

These are **two independently hosted reference collections**, not two original threat investigations. There is no inference that their author/committer timestamps were cryptographically timestamped when published, nor that the original 2021 article has the same bytes as the present LevelBlue version. Original Git commit metadata is mutable/self-reported for historical availability purposes. We have **not** independently recovered a contemporaneous public PushEvent for either bibliography commit, nor verified either repo's independent archival publication time.

## Implemented offline replay and genuine-source CI receipt

`scripts/verify_historical_chimaera_bibliography.py` pins those exact two Git commit IDs, file paths and Git **blob SHA-1** digests. Using only locally supplied raw bytes, it recalculates the Git blob identity over `b"blob " + length + b"\\0" + raw`, verifies both the original AT&T link and the corresponding explicit **2021** citation text, and rejects changed bytes, missing links, malformed material, oversized files, invalid UTF-8, unexpected references or a missing documented RealityNet year-conflict marker.

The output `historical-bibliography-pointer-receipt-v1` contains **only metadata**: file SHA-256 measured at replay, expected Git blob SHA-1, byte count, commit/path, original link, explicit validation scope and an unresolved approval flag bundle. It never reproduces raw bibliography or original publisher text. The output always declares:

- `original_publisher_article_bytes_verified=false`
- `original_publisher_article_available_at_verified=false`
- `git_commit_public_push_time_independently_witnessed=false`
- `source_rights_approved=false`; `historical_source_version_approved=false`
- `same_peer_independent_claim_groups_verified=false`
- `g1_evaluation_eligible=false`; `research_ready=false`

A **sixth GitHub Actions job** fetches exactly those pinned historical public bibliography paths over HTTPS, constrained to **600 KiB per file and 30 seconds per request**, then uses the local byte-verifier to refuse if either changed. The CI artifact keeps only two safe metadata receipts for 14 days. This is an **actual public Git-object replay** (not a synthetic assertion), but these files are **references**, not the actual 2021 primary research report.

### Offline reproduction

Retrieve only these two files at the exact pinned Git revisions into a private directory of your choice (do not commit the downloaded research references):

```powershell
python -m scripts.verify_historical_chimaera_bibliography --witness cloud-native-reference-dec2021 --raw-file data/private/chimaera-reference-2021.md
python -m scripts.verify_historical_chimaera_bibliography --witness mitre-reference-may2022 --raw-file data/private/chimaera-reference-2022.txt
python -m unittest discover -s tests -v
```

CI downloads them into the transient runner directory without publishing their raw bodies. The project's **29 candidate** source records and **0 approved** source records remain unchanged in status; `available_at`, `sha256` and `redistribution` approval fields for Chimaera stay unset.

## Why we still cannot run the SCARLETEEL experiment

A bibliography that cites the original URL by 2021/2022 **does not bind the original report body to those years**. It also cannot independently corroborate the exact `campaign:Chimaera USES tool:xmrig` claim, because it reproduces a *reference*, not the report's actual evidence. The same-source publisher grouping for AT&T remains one unapproved group, not multiple peer witnesses.

The [Common Crawl CDXJ index documentation](https://commoncrawl.org/cdxj-index) describes a free archival route. The relevant earlier indexes include **CC-MAIN-2021-49**, **CC-MAIN-2022-49**, and **CC-MAIN-2023-14**, but opening target-specific CDX responses via the available browser returned an error and a separate container network attempt could not resolve the archive hosts. **No real target WARC/CDX capture was recovered or timestamp-verified here.** No inference from a missing query response to absence of a capture is permitted; a researcher may retry the indexes from their own network. Public Common Crawl WARC data may be downloaded through HTTPS and audited privately subject to publisher rights.

**Next external go/no-go:** recover exact pre-cutoff primary HTML body and independent original retrieval times for the 2021 Chimaera, 2022 Kiss-a-dog and February 2023 SCARLETEEL pages (or lawful, publisher-supplied archived versions). Assign separate independent reviewers, bind typed claims to exact bytes, find at least two genuinely independent historical sources **per individual peer's matching and candidate-relation evidence path**, then preregister an actually novel relation before exposing later labels. Existing later-reference preview exposure remains disclosed. **No G1 v2 threshold relaxation and no synthetic stand-in for real approvals.**
