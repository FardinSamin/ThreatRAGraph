# M2 — Semantic Evidence Review Gate

**Status:** A source-bound, versioned reviewer attestation workflow implemented and tested with **synthetic only** claims. **No genuine researcher annotations, pilot-case outcomes or CTI extraction accuracy have been established.**

**Tracking:** [Issue #17](https://github.com/FardinSamin/ThreatRAGraph/issues/17). Related [Issue #11](https://github.com/FardinSamin/ThreatRAGraph/issues/11), [SRS](SRS.md) FR-11, FR-15, EV-01–03 and [SDD](SDD.md) §§5, 9.

## Problem being addressed

Byte alignment checks **where a quotation came from**. Even an exactly verified sentence can be misunderstood or incorrectly expressed as a relationship. For example, a Falco rule describing detection of a shell **cannot** support the claim that a shell was actually observed in a specific incident.

For scientifically defensible case profiles, a research reviewer must separately assess whether the *particular attributed evidence span* supports the **typed, directed claim as worded**. This is a **manual semantic review**, not a model automatically certifying its own outputs, and not confirmation that the cited publisher's claims are true in the world.

## New workflow boundary

1. M1 validates original version metadata/rights and approved archived bytes.
2. M3 chooses a B0/G1 subset by historical public-availability cutoff, excluding later references.
3. M2 verifies precise evidence bytes/locators from the **archived original** and inserts an \`evidence_status=aligned\` claim into SQLite.
4. The researcher reads **the exact claim and cited excerpt** and produces a versioned JSONL review, separately from the extractor.
5. The review ledger requires the claim ID, source-version ID and evidence SHA-256 to match the already inserted approved claim. Unknown or future-only claim IDs cannot receive accepted reviews.
6. **Strict research graph runs fail closed** unless **every included source claim** has a \`supported_by_excerpt\` review. An unsupported/uncertain claim or missing review causes refusal, never a silently omitted edge.
7. Development-only runs may include \`unreviewed\`, \`unsupported_by_excerpt\`, or \`uncertain\` claims in graph output, but they remain explicitly \`research_ready: false\`. No actual evaluation should treat such outputs as verified data.

## Versioned review contract

Schema: \`semantic-evidence-v1\`. One JSON object **per line**, with these exact keys:

~~~json
{
  "schema_version": "semantic-evidence-v1",
  "claim_id": "claim:<64-character-lowercase-hex-digest>",
  "source_version_id": "srcver:your-approved-version",
  "evidence_sha256": "<full-64-character-lowercase-hex-digest>",
  "decision": "supported_by_excerpt",
  "reviewer_id": "reviewer-01",
  "reviewed_at": "2026-10-10T11:00:00Z",
  "rationale": "The original cited passage explicitly supports this specific typed relationship."
}
~~~

The above angle-bracket placeholders are **not valid IDs or hashes** and must be replaced by the real claim/source evidence data. Claim IDs are stable hashes produced by \`EvidenceGraph.append_source_claim\`; a development projection includes them.

Allowed \`decision\` values:
- \`supported_by_excerpt\`: Reviewer states that the cited text is semantically sufficient for this exact extracted relationship.
- \`unsupported_by_excerpt\`: Cited text does not justify this typed relation, regardless of whether another source might.
- \`uncertain\`: Passage is ambiguous or insufficient; abstain and seek expert adjudication.

\`reviewer_id\` is a bounded pseudonym; **this does not authenticate reviewer identity**. \`reviewed_at\` is a strict UTC timestamp. \`rationale\` must meaningfully explain the judgment. Reviews are stored in a separate \`semantic_reviews\` SQLite table keyed to the existing sourced claim.

A review is content-addressed with a deterministic \`review_id\`; inserting an identical review again is idempotent. Conflicting review updates to the **same claim** are rejected in the same frozen run; use an explicitly new, independently versioned annotation set and record resolution decisions rather than silently altering the result. Source claims and evidence bytes remain unchanged.

## How to run

The case runner can be invoked after historical source approvals and legally retained exact archives. **Research strict mode now requires a JSONL reviews file:**

~~~powershell
python -m scripts.project_case_graph --case-id CASE_ID --claims "C:\research\reviewed-claims.jsonl" --reviews "C:\research\human-semantic-reviews.jsonl"
~~~

To inspect synthetic draft claims/IDs before independent review:

~~~powershell
python -m scripts.project_case_graph --case-id SYNTHETIC_CASE_ID --claims "C:\research\synthetic-claims.jsonl" --development-only
~~~

The second command relaxes pilot **counts only**. It does not bypass source approval, archived-byte integrity, citation alignment or historical cutoff restrictions. Graph edges now include two distinct machine-readable statuses:

| Attribute | Meaning |
|---|---|
| \`evidence_status=aligned\` | Evidence bytes and locator match the approved original source |
| \`semantic_review_status=supported_by_excerpt\` | A human-declared, claim-bound review says the text supports this relation |
| \`semantic_review_status=unreviewed\` | No semantic attestation; **not research-ready** |
| \`semantic_review_status=uncertain\` / \`unsupported_by_excerpt\` | A known concern; refused in strict research mode |

The strict **pilot count, source rights/timestamps and archived-byte checks remain required**. In the current repository, all 19 public URLs are still unapproved candidates and there are zero selected actual cases, so this functionality has only been exercised against synthetic input.

## P0 readiness truthfulness update

Even a **strict** graph run with valid pilot counts, archived-byte hashes and every claim carrying a syntactically valid semantic review **now reports `research_ready=false`**. Successful structural validation is disclosed separately under `readiness` and does not certify publication dates, reviewer authenticity or experimental approval. See [P0 readiness contract](P0_READINESS_CONTRACT.md). Strict reviewer approval is still mandatory to produce the strict *graph preparation artifact*, but no automated readiness approval is available.

## Threats to validity and remaining verification

- A reviewer declaration is **not a verified identity or digital signature** and does not establish blind, independent assessment. Independent faculty review, source annotation guidelines, versioned reviewer decisions, adjudication of disagreements and a separate gold/reference partition remain necessary for formal research.
- A supported quotation does not mean the statement is true, the claimed actor actually exists, or a detection rule ever fired. Preserve the difference between **publisher assertions**, **rule semantics**, **provisional graph predictions** and **independent later ground truth**.
- For proper historical experiments, reviewers should assess **only eligible early text** while hidden from later reference material when feasible; human temporal leakage remains a methodology risk.
- Real source permissions, exact historical availability, source normalization, extraction benchmark labeling, validation of the greenfield source extraction workflow, and quality metrics remain unfinished.
- This workflow does not use an LLM to evaluate its own model outputs.

Test offline:

~~~powershell
python -m pip install -r requirements-normalization.txt
python -m unittest discover -s tests -v
~~~

The synthetic tests include claim ID mismatch, altered evidence hashes, invalid decisions/reviewers/timestamps, conflicting adjudications, strict missing/uncertain gate refusal, and a complete **25-source/4-case synthetic strict-run** that succeeds only with explicit claim-bound reviewer approval.
