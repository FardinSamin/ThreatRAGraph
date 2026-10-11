# M2 — First bounded GHSA structured review-candidate adapter

**Status:** engineering development only; **not** approved source acquisition, empirical extraction quality, source confirmation, human semantic approval, or G1-v2 case suitability. Tracks [P1a #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24), [M2 #11](https://github.com/FardinSamin/ThreatRAGraph/issues/11) and the [case–method gate](research/P1A_CASE_METHOD_ELIGIBILITY.md).

## What is actually implemented

`src/threatragraph/ghsa_candidates.py` supports **GitHub Security Advisory JSON schema 1.4.0**, restricted to an advisory with **exactly one explicit CVE alias** and one or more **Go** affected packages. It reads byte-exact local UTF-8 JSON, requires a caller-supplied **trusted expected SHA-256** and rejects malformed/duplicate keys, unsupported schemas, ambiguous CVE aliases, unsafe package names, unbounded input and unsupported ecosystems.

It emits **only provisional `vulnerability:CVE-... AFFECTS software-product:go/...` review candidates** from explicit `/aliases/<index>` and `/affected/<index>/package/name` scalar fields. Each is backed by **two separately SHA-256-hashed JSON-pointer evidence fields** compatible with the existing M2 evidence alignment contract. The adapter does **not** infer attack mechanics from `details`, interpret version ranges, conclude exploitation occurred, create `HAS_BEHAVIOR` or `USES` edges, or treat GHSA revision dates as authenticated historical timestamps.

**Important schema limitation:** the current SQLite sourced-claim ledger expects a **single evidence locator** and supported semantic review. This output has **two complementary supporting fields**, so it cannot be directly inserted into the ledger as a verified sourced claim. It is a **separate human review queue** for designing a proper multi-field claim provenance record or reviewer-accepted single-span alternative. No automatic source/status promotion is possible.

The output unconditionally contains `approved_source=false`, `approved_claims=0`, `human_review_completed=false`, `g1_v2_target_method_eligible=false`, and `research_ready=false`. Evidence hash correctness alone does not confer time, provenance, rights, semantic truth or independence approval.

## Reproduction against the actual witnessed January 2024 GHSA

Obtain and retain a **permitted exact historical JSON blob privately**, following [the original-advisory public witness](research/P1A_ORIGINAL_ADVISORY_WITNESS.md). Verify its actual bytes, linked source commit and GH Archive event first. The private input file should have SHA-256 matching the **original advisory receipt**, not a digest invented by hashing an arbitrary modern web copy.

On Windows PowerShell, from the repository root, after privately saving those exact bytes:

~~~powershell
# Expected digest is the pinned historical original-advisory value in our existing verifier.
$expected = python -c "from scripts.verify_advisory_public_witness import SOURCE_SHA256; print(SOURCE_SHA256)"

python -m scripts.extract_ghsa_candidates `
  --input-file ".\data\private\runc-ghsa-original.json" `
  --source-version-id "candidate:runc-ghsa-original:20240131" `
  --expected-sha256 $expected
~~~

This command requires **Python only** and performs **no HTTP, Git fetch, paid API, cloud calls, notebook execution, or SQLite writes**. It prints candidate IDs and two field-level evidence digests, **not** the original advisory prose. Save any output under ignored private storage if it contains metadata subject to project confidentiality.

**Expected output type:** `structured_candidates_pending_review`, with zero approved claims and a single CVE-to-affected-Go-package candidate for the pinned original advisory. This last result is a **structural expectation from the original JSON fields**, not a live historical CI run or approval. Unit tests intentionally use artificial GHSA-like JSON only; a new source version requires fresh byte, rights, public-time and semantic review.

## What must happen before a real graph run

1. Reviewer verifies source identity, source-specific rights and independently accepted pre-cutoff availability; candidate registry fields remain unapproved until explicit protocol signoff.
2. Reviewer checks that the compound evidence fields actually support `AFFECTS`, and defines/version-tests how multiple independent field locators enter one supported sourced claim (or chooses a valid independently aligned single-field claim with explicit rationale).
3. Do not promote prose descriptions of leaked descriptors, file paths or attack variants to typed behavior facts without separate evidence spans, semantics and independent review.
4. Obtain eligible historical background and a genuinely assessable later reference; freeze isolated source versions, case unit and B0/G1 inputs before outcomes are inspected.
5. Continue to **abstain for the vulnerability target under G1 v2**; an extraction success here is not a prediction and does not solve the method mismatch.

## Verification

`python -m unittest discover -s tests -v` covers synthetic positive output, repeatability, exact JSON pointer alignment, source hash mismatch, ambiguous CVE aliases, malformed formats, Unicode/nonfinite JSON, unsafe Go package IDs, duplicate packages, source-size limits, ignored free-text attacks and refusal by the offline CLI. Standard Windows/Ubuntu CI and security checks apply.

**No original third-party source body, publication archive or user-owned credentials are committed.**
