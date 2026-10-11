# P1b — SCARLETEEL as a *prospective campaign* target for G1 v2

**Research screen date:** 2026-10-10 Eastern. **Disposition:** **plausible target/predicate family; NOT an eligible or approved G1 case**. No empirical experiment, exact 2023 source text, as-of ATT&CK mapping, historical classification or later labels have been approved. See [machine-readable prospective screen](../../datasets/case_screenings/scarleteel.json), [P1a case-method gate](P1A_CASE_METHOD_ELIGIBILITY.md), [G1-v2 contract](../M5_G1_SIMILARITY.md), [corpus candidate register](../../datasets/manifests/pilot.json), and [Issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24).

## Why this case is more coherent than repurposing a CVE

The five original historical examples naturally target **vulnerabilities** and are incompatible with the existing G1 v2 `USES` and `HAS_BEHAVIOR` feature family. Rather than relabeling CVE-2024-21626 as malware or changing G1 after studying possible outcomes, this new screen considers **SCARLETEEL**, an operation explicitly named by Sysdig's cloud-incident research, as tentative `campaign:SCARLETEEL`. This is a *campaign research unit* (observed operation), **not** a claim that a fully identified actor or malware family exists.

**Earliest presently located publisher account**: [Sysdig, Alberto Pellitteri, “SCARLETEEL: Operation leveraging Terraform, Kubernetes, and AWS for data theft”](https://www.sysdig.com/blog/cloud-breach-terraform-data-theft), showing **2023-02-28**. It describes a compromised Kubernetes workload used for credential theft, AWS-account enumeration and other activity. In the **Technical analysis → Initial access** section the researcher explicitly identifies an XMRig executable deployed by attackers. A tentative ontology-compatible feature is therefore:

`campaign:SCARLETEEL —USES→ tool:xmrig`

This is **only a candidate extraction hypothesis**. Even though the modern readable page contains the description, the **exact February 28 bytes are not yet independently archived, SHA-256 pinned, byte-aligned or human semantically reviewed**. The `USES` relation itself is not accepted in the M2 sourced ledger. We did **not** model `USES tool:terraform` from a Terraform *state-file theft*, since reading a state file does not establish that the operation actually used the Terraform executable. We also did **not** invent ATT&CK technique IDs from current mappings or count an XMRig download as a verified future behavior.

**Public-date corroboration lead:** [BleepingComputer, Bill Toulas, February 28, 2023, “SCARLETEEL hackers use advanced cloud skills…”](https://www.bleepingcomputer.com/news/security/scarleteel-hackers-use-advanced-cloud-skills-to-steal-source-code-data/) identifies Sysdig as the incident discoverer and reports the same operation contemporaneously. Its publisher page displays 11:00 AM, with timezone not independently established; **do not convert that clock string into a verified UTC `available_at`**. This is useful circumstantial corroboration of publicity by February 28, **not** proof of the exact original Sysdig bytes, first disclosure, distinct source independence or a second initial investigative report. Sysdig and the derivative write-up are deliberately assigned **one evidence-independence group** for this prospect.

## Proposed prospective design — not a frozen experiment

| Dimension | Proposal | Acceptance problem |
| --- | --- | --- |
| Case unit | `campaign:SCARLETEEL` | Reviewer must approve consistent campaign identity across actual early/historical sources, without future aliases |
| Preliminary UTC cutoff | `2023-03-01T00:00:00Z` | Tentative calendar boundary chosen **before semantic labeling**, but independently verifiable original-page availability and exact body are still missing |
| Early report | Sysdig February 28 original account | Need immutable historical version, hash, rights and explicit reviewer decision |
| Same-day time witness | BleepingComputer February 28 article | Derived from Sysdig; do not count as independent CTI group |
| Early method feature | Candidate `USES tool:xmrig` | No byte alignment, no human review, no authentic time-valid feature record yet |
| Historical background pool A | [Intezer, Nicole Fishbein, September 8, 2020, “Abusing Legitimate Cloud Monitoring Tools…”](https://intezer.com/blog/attackers-abusing-legitimate-cloud-monitoring-tools-to-conduct-cyber-attacks) | Mentions **TeamTNT actor** and Weave Scope/Docker behavior, but **actor is not automatically same-type as SCARLETEEL campaign** |
| Historical background pool B | [Trend Micro, July 20, 2021, “TeamTNT Activities Probed…”](https://www.trendmicro.com/vinfo/fr/security/news/cybercrime-and-digital-threats/teamtnt-activities-probed) | Independently authored history, but does **not** by itself establish a valid same-type **campaign** peer or two independent groups supporting the *same exact candidate relationship* |
| Later source lead (quarantined) | [Sysdig, July 11, 2023, “SCARLETEEL 2.0”](https://www.sysdig.com/blog/scarleteel-2-0) | Same publisher/research lineage as early article, so not independent corroboration; no original version, no blinded outcome annotation |
| Case selection | **Not selected** | `datasets/cases/pilot.json` remains unchanged and empty |

Two historic **publishers** are not the required two independent **same-type peer relation support groups**. The G1 engine matches peer *subjects of the same type* with exact `USES`/`HAS_BEHAVIOR` relations and then requires supporting relations across two independent historical research groups. Here, named TeamTNT is primarily an **actor** in the cited Intezer report. It is not responsible to silently relabel `threat-actor:TeamTNT` as `campaign:TeamTNT`, synthesize a named campaign, or use general “both use crypto mining” descriptions as a real prediction. **As screened: peer support UNVERIFIED; G1 eligibility FALSE.**

## Explicit later-reference exposure and leakage response

During initial external source discovery, the investigator's search tool showed **brief indexed summaries** of a July 2023 later SCARLETEEL report. That exposure is now recorded as `later_reference_preview_exposure=search_result_summary_exposed` in the immutable-intent screen and is **not hidden**. No later-reference body was added to the research database, no later-ground-truth relation labels were selected, and no G1 prediction or pilot score was produced. Nevertheless **we cannot claim the screener is blind to all later information**.

Accordingly, future gold-label construction for this case must be assigned to an **independent reviewer who has not seen the early-screen hypotheses or later snippets**, with prespecified labeling criteria and an auditable separation of inference and reference artifacts. Do not infer later labels from the preview or claim independent novelty by merely re-reading later pages. If genuine blinding and independent later reference cannot be obtained, **exclude SCARLETEEL from the scored pilot**.

## What changed in the repository

- Added **five new unapproved candidate versions** in the existing M1 source registry: Sysdig initial source; derived BleepingComputer contemporaneous date lead; historical Intezer and Trend Micro background leads; and a quarantined later Sysdig reference. All have `status=candidate`, `available_at=null`, `published_at=null`, `sha256=null`, `date_confidence=unknown`, `redistribution=unknown`. No historical source bytes/rights/license were fabricated.
- Added `datasets/case_screenings/scarleteel.json` as a **separate prospect from approved `datasets/cases/pilot.json`**. It freezes a tentative subject, cutoff proposal, role separation and a single *unreviewed* ontology-valid early feature candidate, and discloses later-summary exposure.
- Added `scripts/screen_candidate_method.py` to **fail closed** if a prospect asserts case/source approval, claims verified same-type peers or independent relation-group support without original evidence, labels early facts byte-aligned, imports a later source as early/background, double-counts derived reporting, invents a CVE-to-campaign conversion, or embeds extra later predictions/labels.
- Added adversarial synthetic/registry-sanity tests to CI. The screen is **metadata/method-shape-only** and **always says research_ready=false**. It deliberately cannot approve an actual source, run G1, or grant permission to access future reference facts.

## Next *real research* steps, in order

1. Retrieve and independently witness a **February 2023 original Sysdig page version** (archival snapshot, publisher export or verifiable content-addressed public distribution), preserve permitted exact bytes privately, evaluate its rights, version lineage and exact **UTC public-by time**. If unattainable, screen out.
2. Extract at least one early `campaign:SCARLETEEL USES <actual tool or technique>` assertion from those exact versioned bytes and have an independent reviewer confirm its **type, polarity and meaning**; retain invalid/uncertain decisions.
3. Find **genuinely named and sourced campaign-type** pre-March 2023 peers with **matching exact eligible features**, backed by at least two independently researched and time-verified historical source groups. Do not turn TeamTNT actor reports into campaign peer evidence by assumption.
4. Independently document availability of any later report and use a **separate blind labeler** for later genuinely novel assessable relations. A repetition of a February 2023 source fact is not a prediction success.
5. Only after all gates pass and the methodology is accepted: register approved manifest versions, review the first *single* case, freeze its source/claim/taxonomy lineage and evaluate B0 vs. G1. Otherwise retain this as a screened-out prospect.

**Current status:** 26 source candidates, **0 approved versions, 0 selected historical cases and 0 empirical comparisons**. This source shortlist is an increase in **research leads**, not scientific validation.
