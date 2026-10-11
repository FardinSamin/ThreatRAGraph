# P1f — Exact historical Cado XMRig/XHide reviewer block fingerprints; CrowdStrike/Sysdig archive access audit

**Run date:** October 11, 2026 EDT. **Disposition:** Real byte-pinned original Cado February 2023 article now has *reproducible, metadata-only evidence-block locators for blinded human semantic review*. No new CrowdStrike or early Sysdig archive acquired. **No original source version or G1 prediction approved.**

## Concrete new original-source evidence alignment

P1e recovered and successfully checked a [real 2023-02-06T12:05:44Z original Cado Kiss-a-dog research page](P1E_CADO_FEB2023_REAL_PRIMARY_WARC.md), 92,875 original HTML bytes, SHA-256 `b3482293f74524efa323ffcf18e138192b2137f6ceda143ddc89e1302c88ef83`, from an exact Common Crawl 206 range + WARC/CDX digest receipt.

In live GitHub Actions run [38111634755](https://github.com/FardinSamin/ThreatRAGraph/actions/runs/38111634755), `scripts/replay_original_cado_20230206.py` ran a deterministic, **non-executing original-HTML text-block extraction** on those *actual original first-party archived bytes*, excluding `script`, `style`, `noscript`, `svg` and `template`. It measured:

- **107** original HTML paragraph/list/heading text blocks.
- **15** visible blocks bearing at least one candidate cue among `kiss-a-dog`, `redis`, `xmrig`, `xhide`.
- Both **XMRig and XHide visible in the same original paragraph block #59** (from the zero-based deterministic parser sequence), separately from another XMRig paragraph #52.
- Block metadata includes element `p`, original HTML source line number, normalized plain-text block SHA-256, block sequence index and *only the recognized token names*. The original copyrighted text is not emitted.

| Historical reviewer cue | HTML source line | Normalized original paragraph SHA-256 | Machine observation |
| --- | ---: | --- | --- |
| `source_block_index=52` | 491 | `9f0062acb7d7eae01ba18b57f2b40e5be810f4eefd7aed8164174ccf0d6144f2` | Contains visible token `xmrig` |
| `source_block_index=59` | 539 | `6c45096683853ea31b4a2c486f79bc7698e16aa909e49780da1eb0565595c9d1` | Visible **`xmrig` + `xhide` in one paragraph**, neither used as a confirmed relation |

The real original HTML SHA-256 and these two exact historical **paragraph SHA-256 fingerprints are now pinned in code** and asserted by a live original article CI replay, along with its 107/15 counts. Any byte modification to the original historical source, decompression, content hash, report identity, parser-normalized candidate block or referenced paragraph will fail the strict version check. Hashes are source **locators**, not simulated study data, not source quotes, and not standalone proof of `USES` relations or legitimate derivative-republication rights.

**What the semantic researcher must still do:** With access to the permitted exact February 6 original HTML, find block #59 via the recorded source line/normalized hash and decide (with context and variant scope) whether the original author actually reports `campaign:Kiss-a-dog USES tool:xhide` and `USES tool:xmrig`; annotate modality/polarity and whether later variant belongs to the same historical campaign. Separately review original CrowdStrike's 2022 XMRig claim, ascertain source rights/time and investigate the original early Sysdig SCARLETEEL source **without reading held-out later outcomes**. Block co-occurrence does not authorize a scientific label and a future gold-labeler needs independent blinding because prior later search snippets were exposed.

## Empirical attempted original CrowdStrike and Sysdig archaeology — inconclusive due CDX errors

To seek the next genuinely independent publisher body after P1e, I ran a focused real official Common Crawl index lookup in GitHub Actions [run 38111528282](https://github.com/FardinSamin/ThreatRAGraph/actions/runs/38111528282), using the preregistered publisher URL aliases from `scripts/probe_original_campaign_cdx.py`:

| Target | Crawl index | Queries | Result |
| --- | --- | ---: | --- |
| CrowdStrike original 2022 Kiss-a-dog original and current URL variants | `CC-MAIN-2023-06` | 2 | HTTP **504** from index |
| Cloud Security Alliance attributed CrowdStrike republication | `CC-MAIN-2023-06` | 1 | HTTP **504** from index |
| Sysdig original early SCARLETEEL report | `CC-MAIN-2023-07` | 1 | HTTP **504** from index |
| CrowdStrike original and current URL variants | `CC-MAIN-2022-49` | 2 | HTTP **504** from index |
| CrowdStrike original and current URL variants | `CC-MAIN-2023-07` | 2 | HTTP **504** from index |

**All 8 targeted queries returned 504; none returned an eligible CDX record**. This is **a service access failure, not eight observations that the original pages were absent from 2022 or 2023 crawls**. It cannot justify source/case exclusion or a “no pre-cutoff capture” claim. The original exact February 6 Cado locator and WARC source replay continued to pass on other action runs.

The investigative lookup was deliberately run and documented, then **removed from the recurring 11-job CI pipeline** once all eight queries returned 504, to avoid loading an overloaded public CDX server and wasting time on repeated inconclusive broad lookups. The existing on-demand bounded CLI `python -m scripts.probe_original_campaign_cdx --targets crowdstrike-original-2022 --collections CC-MAIN-2023-06` remains available for a later research attempt when the service is healthy. See [Common Crawl's own guidance](https://commoncrawl.org/url-index) for alternate columnar-index access, which can be locally queried but must not trigger unapproved cloud billing.

## Safe methodology and remaining blockers

The original-Cado `candidate_review_fingerprints` output is **entirely metadata-only** and explicitly includes `literal_source_text_exported=false`, `claim_semantics_reviewer_verified=false`, `same_campaign_variant_scope_verified=false`, `source_rights_approved=false`, `g1_evaluation_eligible=false`, `research_ready=false`. No false investigator sign-off, no primary HTML in Git/artifacts, no malware execution, and no automatic change to source registry `sha256`/`available_at`/rights. Actual G1 source-path independence still requires two human-reviewed original publisher groups *per historical peer* and a blind later-labeler.

**Current status unchanged:** 30 source leads, **0 approved source versions**, **0 approved historical cases**, **0 scored B0/G1 results**. First original Cado February 2023 HTML is byte-verified, not approved. Original CrowdStrike and early Sysdig report versions remain unverified, and the attempted index queries were inconclusive.
