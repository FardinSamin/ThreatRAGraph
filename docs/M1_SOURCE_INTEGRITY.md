# M1 — Immutable Source Artifact Verification

**Status:** Offline integrity tool available; original runc tag and advisory candidate bytes have been measured, but **zero source versions are approved for research**. See the [original-advisory witness](research/P1A_ORIGINAL_ADVISORY_WITNESS.md).  
**Tracking:** [M1 Issue #3](https://github.com/FardinSamin/ThreatRAGraph/issues/3)  
**Related:** [Corpus and chronology protocol](M1_CORPUS_PROTOCOL.md), [SRS](SRS.md) FR-03, FR-06, DR-03–07, RC-05, [SDD](SDD.md) ``5, 7.

## 1. What it proves — and cannot prove

For each **approved** source-version record with a full lowercase SHA-256 digest, the tool hashes the investigator's locally archived source bytes and compares them to that digest.

It detects absent or corrupted archives, bad digests, symlinked content paths, files exceeding size limits, and exact byte duplicates under different source-version IDs (which require independence review).

It **cannot prove** when content first became public, confirm publisher statements, establish copyright rights, spot near-duplicates with slightly different text, validate CTI extraction, or eliminate pretrained LLM future-knowledge leakage. **A matching SHA-256 proves content identity against a recorded hash, not historical authenticity.**

The existing manifest validator also rejects a pair of different version IDs containing the same full digest when they cross early/background/later case partitions, even if independence groups are incorrectly declared different.

## 2. Content-addressed storage

Under the ignored, local artifact root:

~~~text
artifacts/source_versions/sha256/<first-two-hex-digits>/<complete-64-digit-SHA-256>
~~~

Paths are constructed solely from a validated lowercase SHA-256 digest, never an arbitrary manifest path. File symlinks and symlinked immediate digest-prefix folders are disallowed.

**Do not commit source archives to GitHub by default.** Publicly visible reports are not necessarily licensed for redistribution. Maintain private archives and appropriate permitted backups.

### Candidate-only private capture (new P1a tooling)

Before any original source version has passed historical availability and rights review, **do not put it in the approved case manifest**. The offline helper `scripts/capture_candidate_snapshot.py` can preserve the exact bytes of a *manually downloaded* local candidate, without claiming that they are the historical document revision:

~~~powershell
python -m scripts.capture_candidate_snapshot --source-version-id "candidate:runc-2024-openwall-disclosure:unfrozen" --input-file ".\data\private\runc-2024-openwall.html"
~~~

The content goes into the ignored `artifacts/source_versions/sha256/` store, and a separate ignored candidate receipt records the digest, size, local import time and `historical_available_at=null`. Existing content-addressed files and receipts cannot be silently overwritten. This operation **does not download the original page, verify the document's true publication date, authenticate its source URL, grant reuse rights, change the approved source registry or create a study-ready case**. See [P1a original-disclosure evidence screen](research/P1A_LEAKY_VESSELS_CASE.md). The exact original bytes and rights review are still outstanding.

### Archive an exact version (PowerShell)

After verifying rights and locating a genuinely historical version:

~~~powershell
$sourceFile = "C:\path\to\archived-original-report.pdf"
$digest = (Get-FileHash -LiteralPath $sourceFile -Algorithm SHA256).Hash.ToLowerInvariant()
$prefix = $digest.Substring(0, 2)
$dir = Join-Path "artifacts\source_versions\sha256" $prefix
New-Item -ItemType Directory -Force -Path $dir | Out-Null
Copy-Item -LiteralPath $sourceFile -Destination (Join-Path $dir $digest)
Write-Output $digest
~~~

Only promote a manifest record from **candidate** to **approved** when it has an immutable source version, matching exact digest, verified historical `available_at` time, meaningful `date_evidence`, a defensible independence group, rights status, and a selection rationale. Neither a file name nor an updated website date can supply verified historical publication time.

## 3. Commands and interpretation

Draft-mode audit:

~~~powershell
python scripts/audit_source_artifacts.py datasets/manifests/pilot.json
~~~

Require exact stored bytes for all approved records:

~~~powershell
python scripts/audit_source_artifacts.py datasets/manifests/pilot.json --require-all
~~~

On the current **21-candidate, zero-approved** corpus, these commands do not verify approved research bytes. In particular, an exit code 0 with zero approved sources is **not** a research-readiness result. Strict metadata checks are also required and do not confer independent approval:

~~~powershell
python scripts/validate_research_manifests.py datasets/manifests/pilot.json datasets/cases/pilot.json --strict
~~~

Default archived file size cap is 50 MiB; use `--max-file-mib` only after reviewing resources. `--artifact-root` selects another private local store.

Results report count of approved/candidate sources, byte matches/missing/mismatched content, and per-version status. Outputs contain no report bodies or credentials and no network calls are made. Exit codes: `0` = no validation errors, `1` = manifest read failure, `2` = integrity errors. Warnings still require review.

## 4. Acceptance before an experiment

1. Verify 25–40 approved, varied source **versions** with actual SHA-256 matched against permitted local archives.
2. Separately document defensible exact UTC public availability timestamps; the digest alone cannot establish chronology.
3. Document source rights, publisher dependence, syndication/duplication, and historical ATT&CK/Falco version dates.
4. Define and review 4–6 genuinely historical case cutoffs and independent later references.
5. Re-run metadata validation, required archive audit, and **snapshot-level** as-of provenance checks.
6. Freeze the source manifest/bytes, code revision, graph snapshot, extractor versions, annotations and run configuration.
7. Keep reference labels isolated from the early-profile generation stage.

**The current tools do not claim that source archives, approved cases, evaluated predictions or a complete graph engine already exist.**
