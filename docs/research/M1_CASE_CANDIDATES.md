# M1 — Research Case Candidate Shortlist (NOT YET SELECTED)

**Research scan:** 2026-10-10  
**Status:** Preliminary, **not** a validated historical study, approved pilot corpus or source-version snapshot  
**Source manifest:** [datasets/manifests/pilot.json](../../datasets/manifests/pilot.json)  
**Case manifest:** datasets/cases/pilot.json (still **zero** approved cases)  
**Research authority:** URFS proposal, SRS §2 and §7, SDD §7 and §9.

## Purpose and research guardrails

Screen real container/Kubernetes security disclosures for the eventual 4–6-case sparse-report experiment. The list below **does not choose final time cutoffs**, label any ground truth, or assert that a current webpage is historically faithful to its stated publication date.

All 29 source candidates in the draft JSON registry are marked **candidate**, with null available_at, null SHA-256 and unverified historical versions. A publication date shown on a webpage is *not* a verified, exact availability timestamp. Source copies/archives and independent chronology must be reviewed before approval.

The proposed comparison is **B0** (first one or two public sources only) versus **G1** (B0 plus independently historical background graph), evaluated against later factual descriptions without exposing those descriptions during inference.

## Candidate A — cr8escape, CRI-O / CVE-2022-0811

**Observed publication dates:** CrowdStrike's original report is dated **March 15, 2022**. GitLab's vulnerability advisory is dated March 15 and marked updated **March 18, 2022**.

**Links:**
- [CrowdStrike — CRI-O cr8escape original](https://www.crowdstrike.com/en-us/blog/cr8escape-new-vulnerability-discovered-in-cri-o-container-engine-cve-2022-0811/)
- [GitLab Advisory Database — CVE-2022-0811](https://advisories.gitlab.com/golang/github.com/cri-o/cri-o/CVE-2022-0811/)

**Relevant signals:** CRI-O container-runtime configuration, Kubernetes pod settings, privilege escalation, runtime process behavior and affected versions.

**Research caution:** The later advisory may be an updated/repackaged version of facts already disclosed on March 15, not genuinely newly revealed behavior. Verify archived March 15 vs March 18 revisions and whether held-out facts exist that can be evaluated independently; reject the case if not.

**Status:** Candidate only; currently **weak** later-evidence independence.

## Candidate B — Leaky Vessels / runc CVE-2024-21626

**Observed publication dates:** Snyk's initial runc vulnerability write-up is dated **January 31, 2024**. Palo Alto Networks published its analysis **February 5, 2024**; Snyk published an additional technical deep dive **February 6, 2024**.

**Links:**
- [Snyk — original runc write-up](https://labs.snyk.io/resources/cve-2024-21626-runc-process-cwd-container-breakout/?loc=learn)
- [Palo Alto Networks — later Leaky Vessels analysis](https://www.paloaltonetworks.com/blog/cloud-security/leaky-vessels-vulnerabilities-container-escape/)
- [Snyk — later syscall-oriented deep dive](https://labs.snyk.io/resources/leaky-vessels-container-vuln-deep-dive/)

**Relevant signals:** runc, leaked file descriptors, working-directory handling, container build/run boundaries and syscall-centric explanations.

**Research caution:** The *current* Snyk original page says it was later updated; its 2024-01-31 text cannot be reconstructed by merely downloading it today. The Snyk deep dive is from the same research source and may not be independent evidence; use the Palo Alto article as a more independent later candidate, subject to confirmation.

**Status:** **Provenance/extraction development candidate only** for the present G1 v2. Its `vulnerability:CVE-2024-21626` target is not supported by G1's current `USES`/`HAS_BEHAVIOR` feature family, independent background support is insufficient, and actual later-label novelty remains unassessed. See [case–method eligibility gate](P1A_CASE_METHOD_ELIGIBILITY.md).

**P1a screen update (2026-10-10):** [Leaky Vessels source chronology and evidence checklist](P1A_LEAKY_VESSELS_CASE.md) documents a precise upstream release timestamp, revised modern pages, an independent 2019 background candidate, and an independent publisher's February 2024 later analysis. Five additional **unapproved** URLs were registered at that checkpoint (19 then); subsequent original tag and GHSA JSON candidates bring the draft registry to **21**, including original 2019 and 2024 oss-security mailing-list disclosures. The executable case registry remains empty; this is not an approved case.

## Candidate C — NVIDIA Container Toolkit CVE-2024-0132

**Observed publication dates:** NVIDIA's September 2024 bulletin lists an initial revision dated **September 25, 2024**. Wiz's high-level report is dated **September 26, 2024** and explicitly says it withheld some technical details. Wiz published a technical deep dive **February 11, 2025**.

**Links:**
- [NVIDIA — September 2024 security bulletin](https://nvidia.custhelp.com/app/answers/detail/a_id/5582/~/security-bulletin%3A-nvidia-container-toolkit---september-2024)
- [Wiz — initial CVE-2024-0132 analysis](https://www.wiz.io/blog/wiz-research-critical-nvidia-ai-vulnerability)
- [Wiz — later technical deep dive](https://www.wiz.io/blog/nvidia-ai-vulnerability-deep-dive-cve-2024-0132)

**Relevant signals:** NVIDIA Container Toolkit/GPU Operator, container image control, filesystem exposure, runtime sockets and later clarified mechanism.

**Research caution:** Early use of Wiz plus later Wiz creates same-publisher dependence, even if the latter discloses new facts. One possible design is a vendor-only sparse baseline with a later Wiz explanation, but the historical disclosure versions need to be frozen. Also distinguish public disclosure from earlier private vendor reports.

**Status:** **Especially promising** as an early-vs-later knowledge-gap case; selection not final.

## Candidate D — IngressNightmare / ingress-nginx CVE-2025-1974

**Observed publication dates:** Kubernetes Security Response Committee and Wiz posted reports on **March 24, 2025**. Sysdig published additional detection/Falco-related analysis **March 25, 2025** and CrowdStrike discussed detection behavior **March 28, 2025**.

**Links:**
- [Kubernetes — initial security advisory](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/)
- [Wiz — initial IngressNightmare research](https://www.wiz.io/blog/ingress-nginx-kubernetes-vulnerabilities)
- [Sysdig — Falco detection analysis](https://www.sysdig.com/blog/detecting-and-mitigating-ingressnightmare-cve-2025-1974)
- [CrowdStrike — later detection coverage](https://www.crowdstrike.com/en-us/blog/kubernetes-ingressnightmare-vulnerabilities-key-details/)

**Relevant signals:** Kubernetes ingress controller, admission controller attack surface, shared-object loading and behavior/detection-rule mapping.

**Research caution:** The same-day original reports may already contain most details that the later articles discuss. Label **genuinely new post-cutoff facts**, not repetition. The Wiz page has later editorial updates, so it must be archived at or near original public disclosure. A Falco rule appearing later **cannot** enter the background graph for a March 24 cutoff, even if it improves the modern explanation.

**Status:** **Strong Falco/runtime feature candidate**, conditional on independent later labels.

## Candidate E — NVIDIAScape / NVIDIA Container Toolkit CVE-2025-23266

**Observed publication dates:** NVIDIA's July 2025 security bulletin records original version **July 15, 2025**. Wiz's detailed public write-up is dated **July 17, 2025**.

**Links:**
- [NVIDIA — July 2025 security bulletin](https://nvidia.custhelp.com/app/answers/detail/a_id/5659)
- [Wiz — NVIDIAScape research](https://www.wiz.io/blog/nvidia-ai-vulnerability-cve-2025-23266-nvidiascape)

**Relevant signals:** NVIDIA Container Toolkit, OCI hooks, library loading, elevated container runtime execution and component reuse.

**Research caution:** NVIDIA's current online bulletin includes post-July revisions, including November 2025 updates. Recover its **July 15 version** before defining the early baseline. This case shares vendor/component context with CVE-2024-0132, which could be useful legitimate historical similarity *but also* inflate evaluation estimates through correlated case selection. Report the dependence and use per-case sensitivity analysis.

**Status:** **Promising**, especially for a deliberately sparse vendor-advisory baseline.

## Candidate F — SCARLETEEL cloud intrusion **campaign** (separate G1-v2 prospect)

**Natural source-grounded unit:** `campaign:SCARLETEEL`, not a vulnerability or unverified actor/malware alias. [Sysdig's original incident account](https://www.sysdig.com/blog/cloud-breach-terraform-data-theft) displays **February 28, 2023** and describes an operation launched from an exposed Kubernetes workload into AWS. Its discussion of an XMRig executable gives a plausible tentative `campaign:SCARLETEEL USES tool:xmrig` candidate in G1's supported feature family. **No original Feb 2023 source-byte version, field-alignment or manual semantic review is yet verified.**

[Contemporaneous BleepingComputer coverage](https://www.bleepingcomputer.com/news/security/scarleteel-hackers-use-advanced-cloud-skills-to-steal-source-code-data/) bears the same calendar date but credits Sysdig and therefore **must share the same research lineage** rather than count as an independent early report. [Intezer's September 2020 TeamTNT report](https://intezer.com/blog/attackers-abusing-legitimate-cloud-monitoring-tools-to-conduct-cyber-attacks) and [Trend Micro's July 2021 TeamTNT report](https://www.trendmicro.com/vinfo/fr/security/news/cybercrime-and-digital-threats/teamtnt-activities-probed) are historical background leads from separate research publishers. **They do not yet establish exact matching same-type campaign peers**: TeamTNT is an actor in the Intezer original. [Sysdig's July 2023 follow-up](https://www.sysdig.com/blog/scarleteel-2-0) is a possible **later** reference from the same publisher, not independent corroboration.

**Research caution:** A prospective March 1, 2023, 00:00 UTC cutoff is not yet approved or byte-timestamped. Only search-result summaries, not later source bodies, were seen during discovery; that exposure is disclosed and future outcome review must be independently blinded. Neither two-group same-type support nor a genuinely novel later evaluable relation is established.

**P1b follow-up:** [Chimaera and Kiss-a-dog same-type campaign prospects](P1B_SCARLETEEL_CAMPAIGN_PEERS.md) both have a reported `USES tool:xmrig` feature in separate original researcher articles from 2021/2022. They remain **unverified source versions**, and G1 needs **two independent groups per candidate peer's matching-and-proposed relation evidence**, not two peer subjects each with one source group.

**Status:** **Plausible method type and one tentative early feature, but NOT G1-eligible or selected.** Full auditable decision: [P1b SCARLETEEL screen](P1B_SCARLETEEL_CAMPAIGN_SCREEN.md) and [candidate-only machine-readable screen](../../datasets/case_screenings/scarleteel.json). Five SCARLETEEL/TeamTNT-related URLs are registered as **unapproved candidate** sources; the historical case manifest remains empty.

## Selection and exclusion decisions still required

1. **Chronology:** Preserve independently dated copies of the exact public versions. A private disclosure date is not public availability.
2. **Case unit:** Define whether the target is a specific CVE, campaign, actor, malware family or attack pattern; do not silently combine a vulnerability with observed exploitation.
3. **Early stage:** Verify that a selected first one or two reports are actually early, not just the first found during web search.
4. **Later reference:** Identify new assessable facts that appeared after the cutoff. Distinguish newly public detail from mere retelling, and record contradicted/unknown labels.
5. **Independence:** Use the metadata independence_group field conservatively; several same-publisher or syndicated reports must not count as independent votes.
6. **Container focus:** Confirm genuinely relevant Kubernetes/Falco/syscall behavior, not a generic CVE loosely related to containers.
7. **Data rights:** Record license and redistribution restrictions; avoid storing or redistributing proprietary full-text reports without permission.
8. **Selection bias:** Include a spread of mechanisms and sources, and reject cases with no measurable new facts. Similarities among two NVIDIA CVEs need special reporting.
9. **Temporal background graph:** Historical ATT&CK versions, Falco rules and other CTI feeds must also be available before each cutoff. A modern package is never presumed to be historical.

## Next auditable work

- Obtain versioned public source snapshots and compute actual hashes.
- Record **verified** exact UTC available_at evidence; do not invent time-of-day based on a printed calendar date.
- Review dates of specific later reports independently, then approve only eligible source versions.
- Require [target/method eligibility](P1A_CASE_METHOD_ELIGIBILITY.md) and early/reference novelty review **before** approving a G1-v2 evaluation case; never relabel CVEs to bypass unsupported ontology types.
- Add selected cases to datasets/cases/pilot.json **after** each reference and cutoff pass the validator and the reviewer accepts its case-unit/method fit.
- Expand the corpus with versioned ATT&CK/STIX, Falco rules, Kubernetes documentation and other diverse historical CTI; 29 candidate entries are **not** the planned 25–40 approved source corpus.
- Run strict validation and faculty methodological review before an actual experiment.

**No experiments, predictions, extraction quality scores or model comparisons have been run.**
