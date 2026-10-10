# M2 — Evidence Alignment Against Approved Source Archives

**Status:** Implemented for direct UTF-8 text and JSON scalar fields; tested with synthetic fixtures only.  
**Tracking:** [Issue #11](https://github.com/FardinSamin/ThreatRAGraph/issues/11).  
**Implementation:** [Evidence verifier](../src/threatragraph/evidence_alignment.py), [SQLite ledger](../src/threatragraph/evidence_graph.py), [historical runner](../scripts/project_case_graph.py).

## Purpose

The first M2 graph stored a source ID, a citation locator, and a **user-supplied** SHA-256 digest. An invented quote could have an apparently valid hash. Now the ingestion path looks up the exact approved archived bytes, recomputes the source SHA-256, resolves the cited span or JSON field, recomputes the evidence SHA-256, and **rejects an incorrect citation before inserting the claim**.

These checks guarantee byte alignment **only**. They do not prove that the extractor has interpreted the cited words correctly, that the publisher's claim is factually true, or that the content existed before the historical cutoff. Each of those must be independently reviewed.

## Supported source/evidence formats

| Locator | Archive format | Check |
|---|---|---|
| `text_span` | Original UTF-8 plain-text bytes | `segment_id` must be `seg:` + the exact source-version ID. Unicode code-point offsets `[start,end)` locate a nonblank substring within the **original entire file**. SHA-256 is calculated over the substring's UTF-8 bytes. |
| `json_pointer` | Original UTF-8 JSON bytes | RFC 6901-style absolute path including escaped `~0` and `~1` and array indices, selecting a scalar. Strings hash as UTF-8 text; other scalars hash as deterministic JSON. |
| `yaml_path` | Falco rule YAML | **Rejected in v1**, even if the user provided a digest. Requires a trusted safe YAML parser tied to a frozen rule revision. |

Binary PDFs, HTML extraction, OCR, UTF-16 reports, and *derived normalized text segments* are **not** supported in this version. They require a separately versioned, reproducible normalizer that retains a checked lineage to the archived original. **Do not simply label a derived PDF paragraph as a raw-text segment.**

## Integrity and historical boundaries

The existing M1 archive-integrity audit still checks content-addressed files at:

~~~text
artifacts/source_versions/sha256/<two-character-prefix>/<full-64-digit-SHA-256>
~~~

The verifier rehashes source bytes during each citation check and rejects missing archives, malformed pointers, invalid text offsets, forged evidence digests and unsupported formats. It never sends source content to a network service or executes embedded instructions.

Historical case ingestion continues to allow **only** the source-version IDs in the M3 B0/G1 view. A held-out, post-cutoff citation is rejected regardless of whether its bytes are available locally. This enforces source-level isolation, not full model or knowledge-level historical blindness.

## Evidence status in SQLite and graph output

The sourced-claim ledger now records an explicit `evidence_status` field:

- `aligned`: Exact evidence digest verified against an approved source archive at insertion time.
- `unverified`: Direct programmatic ledger insertion *without* an attached verifier; not ready for scoring and plainly marked in graph edges.

The end-to-end graph CLI **always uses the verifier**. It will not insert a sourced claim if the supplied evidence locator or digest does not match the approved archive. The developer API still permits clearly labeled unverified claims to enable prototype experimentation; those claims must never be reported as validated extraction.

Falco rule descriptions/conditions represent potential detection patterns, not actual observed malicious runtime events. Aligned text also does **not** turn a source assertion into confirmed incident truth.

## Example research workflow

After independent approval, rights review, and byte-accurate archive storage:

~~~powershell
python -m scripts.project_case_graph --case-id VERIFIED_CASE_ID --claims "C:\research\reviewed-claims.jsonl"
~~~

The optional `--development-only` flag allows small **synthetic** pilot fixtures, not bypass of archive hashing, cutoff enforcement or exact evidence alignment. The current repository has **14 unapproved source candidates and zero real case studies**, so it cannot yet produce experimental threat profiles.

A fictional example plain-text file contains:

~~~text
Malware Alpha uses command execution.
~~~

If its source-version ID is `example-v1`, a substring citation starts with:

~~~json
{
  "evidence_locator": {
    "kind": "text_span",
    "segment_id": "seg:example-v1",
    "start": 0,
    "end": 13
  },
  "evidence_sha256": "<compute the actual full SHA-256 of 'Malware Alpha'>"
}
~~~

The example digest is **not a usable value**. Real claim JSON requires the exact lowercase digest, the approved source ID, typed relationship fields and extractor version.

## Tests and remaining research work

~~~powershell
python -m unittest discover -s tests -v
python -m compileall -q src scripts
~~~

Synthetic tests cover correct Unicode offsets, JSON pointer paths and escaping, spoofed quotes/hashes, wrong source segments, malformed/binary text, missing or mutated archived versions, unapproved sources, unsupported YAML paths, prompt injection as plain data, direct-ledger `unverified` vs. checked `aligned` statuses, and the full graph runner refusing fabricated citations.

Still outstanding: original prototype import and extractor audit (#1), true historical source/case corpus (#3), deterministic HTML/PDF/Falco YAML normalization, semantic claim correctness review, time-valid aliases and embeddings, and actual GraphRAG similarity/evaluation. A source match alone does not establish a correct extracted CTI relationship.
