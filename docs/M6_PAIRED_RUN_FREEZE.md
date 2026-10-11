# M6.1 — Offline paired execution and reproducibility lock (engineering)

**Status:** Draft, intentionally not tested on GitHub Actions. This is not
research approval or an empirical B0/G1 result. Adds a partial implementation
of FR-28 (one-case paired execution and output parity) and FR-29 (content-
addressed run/provenance manifest). Independent historical validation is
still absent; no held-out data are consumed.

## Usage

Pass **only** sealed pre-cutoff input JSON documents and exact provenance
metadata. The paired runner computes both outputs anew, checks the B0/G1
early-output parity contract, and creates a digest-bound engineering lock.

    python -m scripts.freeze_paired_run \
      --b0-view b0-view.json --b0-graph b0-graph.json \
      --g1-view g1-view.json --g1-graph g1-graph.json \
      --feature-lineage exact-only-lineage.json \
      --metadata metadata.json --g1-config g1-config.json

This is a **preview**. For content-addressed, exclusive-creation disk
artifacts, add: \`--write --output-dir artifacts/paired_runs\`.
Both preview and write modes report SHA-256 of identical canonical JSON
bytes (including the trailing newline). JSON documents with duplicate keys
are refused to avoid silently changed provenance. A repeat run with identical
inputs is byte-stable, and a conflicting
preexisting output at the same digest path is refused.

The output set is \`b0_profile\`, \`g1_profile\`, \`paired_audit\`,
and \`run_lock\`. The audit verifies matching case/cutoff, exact common
early input bindings, reviewed observed assertions separate from provisional
hypotheses, profile fingerprints, independence receipts, and abstention.
The runner uses the existing \`build_b0_profile\` and \`build_g1_profile\`
rather than rewriting their existing safeguards.

### metadata.json

Provide EXACTLY these fields:

- \`git_commit_sha\`: full 40-character lowercase Git commit
- \`dependency_lock_sha256\`: 64-character SHA-256 digest of pinned dependencies
- \`source_manifest_sha256\` and \`case_manifest_sha256\`: SHA-256 receipts
- \`review_set_sha256\`: exact researcher-review partition digest
- \`ontology_version\`, \`extractor_version\`, \`ruleset_version\`: nonempty
  version identifiers describing preprocessing/source-time features
- \`random_seed\`: \`null\` (deterministic B0/G1 do not use RNG)

These are **caller-declared receipts**, not automatically verified against
upstream bytes, signed manifests, authenticated dates, independent reviewers,
or publication rights. Metadata values may be fabricated; presence does NOT
change \`research_ready=false\`.

### g1-config.json

Provide the exact four integer algorithm parameters:
\`top_k\`, \`min_overlap\`, \`min_background_groups\`,
\`max_peers_per_feature\`. The existing ranker validates bounds and
transports them unchanged into its output contract.

## Safety and limitations

The runner accepts *no* later reference labels, assessment answers or future
sources. As-of source eligibility and exact-only feature lineage remain
the responsibility of the existing upstream validators, which themselves
cannot authenticate original publisher dates or reviewer identities.
No scoring takes place; the run lock explicitly records
\`gold_labels_read=false\` and \`empirical_evaluation=not_performed\`.

The manifest binds canonical JSON digests of the five supplied input
objects, the two produced profile IDs, the output audit ID, algorithm config,
metadata and case/cutoff. It records a **software** freeze, not external
WORM storage, a signed certificate or proof of original historical fairness.

Source byte rights approval, real cutoff research, true labels, paired
scoring, and faculty review remain separate future tasks.

**Testing phase:** 13 synthetic and adversarial unit tests are authored
for this module. Run local unit tests and full security suite before merging,
and preserve PR drafts while GitHub Actions cannot allocate runners. The
earlier passing CI heads do not validate new code.
