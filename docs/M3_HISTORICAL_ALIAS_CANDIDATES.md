# M3.4 — Historical typed alias candidate registry (fail closed)

**Status:** Draft engineering-only implementation (FR-13 partial); 21
synthetic/adversarial tests authored and not executed. No human identity,
historical public availability or real entity-link review is authenticated.

## Objective

Model potential aliases in a **per-case, as-of** audit layer, preserving the
original source version, exact source SHA-256, evidence SHA-256, declared
source-availability timestamp and reviewer identifier. Neither name
similarity nor present-day alias dictionaries authorize retroactive changes
to first-report identities or the frozen G1 feature graph.

## Boundary

The alias_history module creates and validates a deterministic
candidate_asof_alias_history artifact. It requires an existing valid, frozen
historical_source_input view and an exactly matching SHA-256 of that view.

Each candidate record contains exactly:

- alias_id and canonical_candidate_id — both typed entity identifiers
- source_version_id and source_sha256 — must match an allowlisted source
- first_known_at — must equal that source's declared available_at and fall
  on/before the case cutoff
- evidence_sha256 — a required original-evidence digest declaration
- reviewer_id_declared — not an independently authenticated identity
- decision — candidate_supported, candidate_rejected, candidate_uncertain

The artifact is content-addressed and rejects unknown fields (including
later labels), unsupported versions, duplicate decisions, source-hash
mismatches, post-cutoff dates, cross-type equivalence (e.g., actor vs.
malware), self-aliases, unsorted histories, and multistep or cyclic mappings.

When the same alias has more than one candidate canonical ID, the audit
reports **ambiguous_candidates_require_adjudication**; it never silently
chooses a winner. Rejected/uncertain aliases remain separately disclosed. If exactly the same
alias/canonical candidate pair has both supported and rejected evidence, the
inspection now reports conflicting_evidence_requires_adjudication rather than
a deceptively unambiguous single candidate. No automatic rewrite is allowed.

## Offline read-only inspection

    python -m scripts.audit_alias_history \
      --view artifacts/snapshots/b0-view.json \
      --history artifacts/private/history.json \
      --entity-id malware:oldname

The command emits only a bounded structural inspection and does not edit
the graph, output an approved canonicalization table, access later labels,
write a database, or train a model.

Every receipt exposes:

- automatic_entity_rewrite_allowed = false
- g1_feature_lineage_enrichment_allowed = false
- reviewer_identity_authenticated = false
- research_ready = false

This remains consistent with M5's existing exact-only feature-lineage
policy. **Do not feed these candidate aliases into B0 or G1** until separate,
independent, real-source historical proof and review establish a proper
source-native entity resolution contract. No such approval exists today.

## Deferred validation and expansion

- Run the new unittest module locally, then full adversarial and cross-OS
  checks when GitHub Actions runners and monthly quota return.
- Independently replay and date each original publisher citation before
  trusting candidate source dates, source rights and alias facts.
- Add human adjudication, contradictory source positions and versioned
  authorized canonicalizer only with genuine reviewer authentication.
- Extend the audit to source-native STIX IDs and historically versioned
  ATT&CK/Falco vocabularies only after the original revisions are acquired.
- Keep the no-future feature/index/label leakage tests, especially aliases
  learned after a case cutoff. Do not silently merge actor/tool/malware types.

This module is deliberately not a general entity-linking engine nor a
claim of completed FR-13. Its output is candidate-only, not a research result.

## Local JSON input hardening (draft)

The standalone alias-inspection CLI uses the shared bounded read-only file
reader for strict UTF-8, nonfinite/duplicate JSON refusal, regular-file and
symlink/junction checks through directory ancestors, and whole-file size
stability. Duplicate/hardlinked `--view` and `--history` inputs are refused.
On POSIX, no-follow directory descriptors also prevent parent-symlink swap
races; Windows filesystem checks need independent live validation.

**21 alias-inspection tests authored, not executed**, including JSON nonfinite,
parent-symlink and same-inode refusals. The shared reader is source code in
this draft; its separate 15-test suite is staged in the independent exchange
branch and later integration candidate, not duplicated here.
