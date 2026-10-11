# P1a case–method compatibility decision gate (proposed; reviewer signoff required)

**Recorded:** 2026-10-10 (Eastern) | **Status:** screening decision, **not** case approval, G1 method approval, or an empirical result.
**Tracks:** [historical case #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24), [G1 method #21](https://github.com/FardinSamin/ThreatRAGraph/issues/21), [corpus #3](https://github.com/FardinSamin/ThreatRAGraph/issues/3).
**Evidence:** [original advisory witness](P1A_ORIGINAL_ADVISORY_WITNESS.md), [Leaky Vessels screen](P1A_LEAKY_VESSELS_CASE.md), [M5 G1 contract](../M5_G1_SIMILARITY.md), [source candidate shortlist](M1_CASE_CANDIDATES.md).

## Decision being screened

The currently implemented, synthetic-tested G1 v2 engine does **not** support a vulnerability as an analogy target. The ontology admits `vulnerability:AFFECTS` and `vulnerability:APPLIES_TO_COMPONENT`, but G1's **feature and prediction family is limited to outgoing `USES` and `HAS_BEHAVIOR`**. Their allowed subjects are actor/malware/campaign or malware/attack-technique respectively, not vulnerability.

This is an **ontology/method incompatibility**, not a failure of the available historical sources and not a negative experimental result. PR #36 now emits `unsupported_target_type_for_current_features`, preserving B0's early observed facts and no G1 predictions. Do not relabel `vulnerability:CVE-2024-21626` as malware, campaign or technique to bypass the problem.

## Screening the existing candidate population before any G1 outcome evaluation

| Original candidate | Natural shortlisted case unit | Compatible with G1 v2 *as that unit*? | Disposition |
| --- | --- | --- | --- |
| CRI-O cr8escape (CVE-2022-0811) | Vulnerability | **No** | Keep in source/case discovery; no G1-v2 result on the CVE target |
| Leaky Vessels / runc (CVE-2024-21626) | Vulnerability | **No** | Keep as **provenance/extraction development case**; do not claim a G1-v2 evaluation |
| NVIDIA Container Toolkit (CVE-2024-0132) | Vulnerability | **No** | Continue historical-version research without G1-v2 eligibility claim |
| IngressNightmare (CVE-2025-1974) | Vulnerability | **No** | Same; historically valid Falco evidence alone does not fix target type |
| NVIDIAScape (CVE-2025-23266) | Vulnerability | **No** | Same; shared NVIDIA component alone is not a novel prediction |

These are **method-fit classifications for the originally proposed CVE units**, not exclusions of the real incidents/disclosures from all future analysis. A *genuinely separately documented* compatible malware/campaign/technique target may eventually qualify if selected under the same predeclared criteria; simply inventing a campaign ID or converting a CVE into another entity type does not.

## Concrete early-source novelty risk

The exact original January 2024 GHSA JSON recovered in the witness already describes **attacks 1, 2, 3a and 3b**, host-filesystem access and host-binary overwrite scenarios. This observation comes from **early source content only**; no post-cutoff article was opened to assign an evaluation label. Later reporting repeating those same claims is **not net-new gold truth** for a G1 inference. The independent later article candidate must be separately archived, assessed for genuinely new assessable relations, and kept completely outside inference and target-selection tuning.

Original public-source hashes and the proposed public-by time are documented separately; the case still has **0 approved versions**, **no approved case**, and **no scored predictions**.

## Pre-evaluation go/no-go gate for a candidate G1 v2 case

Before any **G1 v2 development comparison** (and before consulting the held-out later reference content):

1. **Entity type:** target must be an actual source-grounded typed actor, malware, campaign, or attack-technique with eligible outgoing `USES`/`HAS_BEHAVIOR` relations; a CVE target fails here.
2. **Early signal:** the selected first one or two genuinely pre-cutoff source versions must contain at least one exact, positive, evidence-aligned, semantically reviewed target feature within that family. Do not fabricate a feature from an advisory title or vulnerability affected-component metadata.
3. **Background comparability:** source-grounded, same-type historical peers with eligible pre-cutoff claims must exist. At least **two substantively independent historical background publisher groups** must support the analogy path under the fixed G1 v2 policy; mirrored reports and early-source publishers cannot be double-counted.
4. **Historical and rights review:** exact permitted archived source bytes, verified availability and version lineage, source rights, cutoff and human reviewer acceptance must be recorded. Source-level date assertions alone are not enough for an empirical study.
5. **Reference separation:** freeze eligibility, the method version, inputs, hypotheses and any abstentions **before** the independent later evidence is used for scoring. Early-fact repetitions never become predicted novelty.
6. **No silent method changes:** adding vulnerability-specific features or relaxing the two-group gate requires a **new versioned method proposal**, adversarial tests, rationale and recorded pre-outcome reviewer signoff. Simple shared `runc`/toolkit component features alone are too generic to establish useful causal analogies.

A failure is reported as **method-ineligible**, **insufficient evidence**, or **not assessable**, not silently reclassified or forced through the ranker. Research readiness remains false.

## Proposed paths and ownership decision

**Preferred short-term path (pending investigator signoff):** retain Leaky Vessels as the first **real-source provenance and extraction development** vertical slice, where exact original GHSA JSON is already historically witnessed. In parallel, shortlist a *separately evidenced* container/Kubernetes-relevant **malware/campaign/technique** research case that naturally supports the pre-existing G1 v2 predicates. Document *all* screened/rejected cases and the decision **before** inspecting their later-outcome labels. This preserves the present method and avoids changing a CVE's type.

**Alternative:** preregister a separate **vulnerability-compatible G1 v3** research method and meaningful mechanism-level features, with a versioned ontology/mapping, historical as-of proof, blinded labels and reviewer approval. It must distinguish vulnerability semantics, observed exploitation, tool behavior and Falco rule descriptions. Do not amend G1 v2 in place merely to force the initial CVE case through.

**Explicit remaining decision:** investigator/faculty reviewer chooses and signs off on method/case-unit direction; neither route has yet been approved. Keep [Issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24) open. The next technical vertical slice can implement a conservative **GHSA structured candidate-claim extraction adapter** for development and manual review without declaring case eligibility or experiment success.
