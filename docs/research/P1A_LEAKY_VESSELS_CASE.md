# P1a — First historical-case screen: Leaky Vessels / CVE-2024-21626

**Investigated:** 2026-10-10  
**Status:** **CANDIDATE SCREEN ONLY — NO APPROVED CASE, NO FROZEN SOURCE VERSION, NO EXPERIMENT**  
**Candidate register:** [datasets/research/p1a_leaky_vessels_screening.json](../../datasets/research/p1a_leaky_vessels_screening.json)  
**Tracking:** [Issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24) under full corpus [#3](https://github.com/FardinSamin/ThreatRAGraph/issues/3).

## Research question and why this case

We are studying a **newly disclosed container runtime vulnerability**, not claiming an actual intrusion. Leaky Vessels includes runc CVE-2024-21626 (leaked file descriptors and process working directory). The case was already present in [the preregister-like research shortlist](M1_CASE_CANDIDATES.md) before constructing a G1 engine. The study must not choose cases based on successful hindsight predictions.

A plausible historical contrast exists: **January 31, 2024** public disclosures; **February 1, 2024 00:00:00 UTC** as a **proposed, unapproved cutoff**; Red Hat's **2019** discussion of the *different* runc CVE-2019-5736 as possible structural historical background; Palo Alto Networks' **February 5, 2024** article as a later independent-publisher *candidate reference*. All candidate source versions require archival and license review.

### Dates actually observed, not yet independently audited historical versions

| Proposed role | Publisher and source | Visible date / evidence | Revision, provenance and independence warning |
|---|---|---|---|
| Early candidate 1 | [Snyk: CVE-2024-21626 runc analysis](https://labs.snyk.io/resources/cve-2024-21626-runc-process-cwd-container-breakout/?loc=learn) | Jan 31, 2024. [Snyk's umbrella Leaky Vessels change log](https://labs.snyk.io/resources/leaky-vessels-docker-runc-container-breakout-vulnerabilities/) says initial 3 p.m. ET release on Jan 31 | Current related overview **last updated May 27, 2025** and includes Feb 7–8 updates. **Not eligible to feed as Jan 31 text** until correct historical bytes are recovered. Same publisher as later Snyk deep dive |
| Early candidate 2 | [opencontainers/runc release v1.1.12](https://github.com/opencontainers/runc/releases/tag/v1.1.12) | **GitHub Releases API observed \`published_at=2024-01-31T20:06:08Z\`**. [Tagged release API](https://api.github.com/repos/opencontainers/runc/git/ref/tags/v1.1.12) exposes an annotated Git tag | Annotated Git tag's **tagger timestamp is Jan 23, 2024**, which is **NOT the public date**. The candidate register stores the official upstream tag-reference API URL, **not any Git object digests**. Resolve and verify the actual object and report-byte SHA-256 before source approval. Before approval resolve tag/commit fully, verify history, collect and hash permitted exact content |
| Background candidate | [Red Hat: It starts with Linux / CVE-2019-5736](https://www.redhat.com/en/blog/it-starts-linux-how-red-hat-helping-counter-linux-container-security-flaws) | Feb 11, 2019, visible publisher date. [Kubernetes also published an advisory Feb 11, 2019](https://kubernetes.io/blog/2019/02/11/runc-and-cve-2019-5736/) | **Different** vulnerability and causal mechanism; potential older graph-neighbor source only, never a direct witness for 2024 CVE. Exact 2019 revision and publisher dependence need review |
| Later reference candidate | [Palo Alto Networks: Container Escape / Leaky Vessels](https://www.paloaltonetworks.com/blog/cloud-security/leaky-vessels-vulnerabilities-container-escape/) | Feb 5, 2024, displayed by publisher and its article index | Independent organization, but article may largely **repeat January facts**. No later “gold” labels are accepted until exact version and truly novel assessable facts are separately annotated **after** predictions are frozen |
| **Exclude as independent reference** | [Snyk Leaky Vessels deep dive](https://labs.snyk.io/resources/leaky-vessels-container-vuln-deep-dive/) | Feb 6, 2024 in prior source shortlist | Same Snyk independence group as early source; cannot cross the early/later reference partition as independent evidence |
| **Exclude present-day body from early** | [runc GHSA-xr7r-f8xq-vfvv](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv) | Initially marked Jan 31, 2024; GHSA database shows **last updated Jul 21, 2026** | Same maintainer dependence group as official release and **mutable** modern advisory. Must first recover dated historical revision before using any claim in B0/G1 |

The **release published_at** and **Jan 23 tagger time** were inspected with GitHub's official release/tag APIs on the research date. They refer to distinct events. The documented API release timestamp is stronger than a current blog's date label, but **it still does not by itself prove the exact bytes of an independently retrieved HTML page existed at that instant**.

No source byte SHA-256, first-public-availability timestamp of the frozen content, reviewer approval or redistribution license has been inferred. Every registered manifest entry remains `status=candidate` with `sha256=null`, `published_at=null`, `available_at=null` and `date_confidence=unknown`. A date observation in the screening register is deliberately **not** the executable `available_at` required by the case schema.

## Why this candidate and not the others *yet*

- **CRI-O cr8escape (2022):** same-day coverage may lack strong independent *later new information*. Screen separately; don't reject permanently.
- **NVIDIA Toolkit / CVE-2024-0132:** promising knowledge-gap contrast because later Wiz detailed report was published months after initial advisories, but early-vs-later content revisions still need verification; reserve as another possible case.
- **IngressNightmare (2025):** strong Falco/runtime features but same-day initial sources may already include much of the later story. Modern rewritten detection rules risk leakage.
- **Leaky Vessels:** maintainers' public release has a precise release API timestamp plus an upstream tag; historical background from a **different publisher** and later analysis from **another** organization are findable. This increases the chance of a defensible source study, **not** a claim it can predict the later answers.

Selection must remain independent of any model output or post-hoc ability to score predictions. If later independent references add no assessable fact beyond the first reports, **discard this case** rather than manipulate the cutoff or count repeats as discoveries.

## Exact acceptance steps — P1a still OPEN

- [x] Record an independently observed official GitHub release publish timestamp and clarify tagger-vs-release chronology.
- [x] Identify two potential early sources, a pre-cutoff 2019 historical source and a different-publisher later-reference candidate.
- [x] Record publisher/date/version dependence warnings, screening-only cutoff and alternative candidate rationale.
- [x] Create a machine-checkable candidate register that **cannot mark itself approved** and is checked in CI.
- [ ] Independently recover **exact historically available January 2024 bytes** of each selected initial source; compute full SHA-256 and store originals under ignored `artifacts/source_versions/sha256/`, subject to rights.
- [ ] Recover exact pre-cutoff historical 2019 background revision and independently date it; decide whether sufficiently analogous without conflating two separate vulnerabilities.
- [ ] Verify release public-availability evidence **for the exact immutable content** (Git tag resolution/audited archive) and choose final 1–2 early sources from the true earliest reports; do not use the private embargo tagger date.
- [ ] Freeze a distinct, rights-cleared February 2024 Palo Alto revision **outside the inference boundary**, and independently annotate *new* later facts, not restatements.
- [ ] Investigate publisher/source syndication groups and duplicate content, maintain inclusion/exclusion decisions. Exclude any same-group later content from independent reference scoring.
- [ ] Record rights/retention, legal archival permissions and a human researcher/mentor cutoff/date decision for every source.
- [ ] Check historical STIX/ATT&CK/Falco revisions and aliases, if used; **no modern rule or taxonomy facts** in background.
- [ ] Only then promote eligible sources from `candidate` to `approved` in the M1 manifest, set independently defensible `available_at`, run archive integrity validation and create a non-study-ready *development* case.
- [ ] Demonstrate a real byte-aligned source-to-reviewed-claim graph and a deliberate post-cutoff/held-out injection refusal.
- [ ] Grow to the approved full 25–40-source / 4–6-case corpus under parent #3, with separate signoff.

**Important:** Do not add a case to `datasets/cases/pilot.json` now. That file is intentionally still empty; adding references to unapproved source IDs would be rejected and would falsely suggest an experiment is ready. The screening dossier is non-executable and does **not** unlock any empirical evaluation.

## Screening validation

~~~powershell
python -m scripts.validate_case_screening
python -m unittest discover -s tests -v
~~~

A valid screening returns `status=valid_candidate_screen_only` and `research_ready=false`, and explicitly reports zero approved sources/cases. The validator rejects a future reference before cutoff, copied publishers crossing source partitions, fabricated archive SHA-256 and unauthorized approval. It **does not** inspect web page history or download reports. Authentic archival review remains a separate next step.
