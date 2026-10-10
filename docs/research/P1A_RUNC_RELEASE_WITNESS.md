# P1a — Original signed runc v1.1.12 release provenance

**Reviewed:** October 10, 2026 · **Status:** Primary-source API consistency only, **not approved historical source bytes**.
**Case:** CVE-2024-21626 / Leaky Vessels · [P1a issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24).

## Primary evidence observed from official public endpoints

| Upstream witness | What the currently available record says | Historical limit |
|---|---|---|
| [GitHub release v1.1.12](https://api.github.com/repos/opencontainers/runc/releases/tags/v1.1.12) | Final, non-draft release reported public at **2024-01-31T20:06:08Z**; creation timestamp 2024-01-23T13:13:42Z | A release record and mutable body do not prove exactly which current HTML words were public in 2024 |
| [Annotated tag ref](https://api.github.com/repos/opencontainers/runc/git/ref/tags/v1.1.12) | A tag object, resolving to a target Git commit | The tag ref could move; the pre-release Git tagger date does not establish public access |
| [Signed tag object](https://api.github.com/repos/opencontainers/runc/git/tags/20381324e21b5b232fea74d448b5975d85d34d25) | Signed tag description mentions **CVE-2024-21626** and internal file descriptors; GitHub API reports **PGP verified = true, reason = valid** | Verification recorded **2024-11-07**, after the case cutoff. We have **not** independently verified the PGP signature/key or archived exact original bytes |
| [MARC](https://marc.info/?l=oss-security&m=170673315111385) and [Openwall](https://www.openwall.com/lists/oss-security/2024/01/31/6) | Both index a January 31, 2024 public runc maintainer disclosure, mail Date equivalent to **20:33:01 UTC** | Two archives of the **same original message**, not two independent threat reports; sender-controlled Date is not independent arrival proof |

The official release timestamp, tag and independent message archive are useful chronology anchors. **No source has been promoted from candidate to approved**; the relevant source SHA-256, independently proven public availability of that exact version, rights and approved case are still missing.

## Offline verification of upstream GitHub response linkage

The new `scripts/verify_runc_release_witness.py` reads three **locally saved** GitHub API JSON responses. It checks version, GitHub release time against the proposed cutoff, annotated tag-ref binding, target commit, signed tag payload binding and the **API-reported** PGP verification. It does **not** perform network calls or locally cryptographically reverify a PGP key/signature. It always reports `research_ready=false`, `historical_available_at=null` and unverified rights and historical original bytes. Its signed API payload SHA-256 is **not** the raw Git object or original archive SHA-256.

Run on PowerShell after obtaining the public metadata via your internet connection:

~~~powershell
New-Item -ItemType Directory -Force -Path '.\data\private\runc-witness' | Out-Null
$release = Invoke-RestMethod -Uri 'https://api.github.com/repos/opencontainers/runc/releases/tags/v1.1.12'
$tagRef = Invoke-RestMethod -Uri 'https://api.github.com/repos/opencontainers/runc/git/ref/tags/v1.1.12'
$tag = Invoke-RestMethod -Uri $tagRef.object.url
$release | ConvertTo-Json -Depth 70 | Set-Content -Encoding utf8 '.\data\private\runc-witness\release.json'
$tagRef | ConvertTo-Json -Depth 70 | Set-Content -Encoding utf8 '.\data\private\runc-witness\ref.json'
$tag | ConvertTo-Json -Depth 70 | Set-Content -Encoding utf8 '.\data\private\runc-witness\tag.json'
python -m scripts.verify_runc_release_witness --release-json '.\data\private\runc-witness\release.json' --tag-ref-json '.\data\private\runc-witness\ref.json' --tag-json '.\data\private\runc-witness\tag.json'
~~~

**These commands access GitHub only while fetching the three JSON responses.** The verifier is strictly offline. The JSON is private, is a **current** API response, may contain PGP signature material and should not be committed. The parser accepts UTF-8 with or without a PowerShell BOM. No cloud compute or paid APIs are required.

## Still required for authentic research approval

1. Recover the exact historical source bytes and complete original Git objects; if using PGP as evidence, locally verify the original signed Git tag with a trusted publisher key.
2. Independent evidence of release availability for the exact version by the 2024-02-01 proposed cutoff, not the January 23 private/embargoed tag creation.
3. Explicit licensing and permitted archival/retention, investigator signoff, source group independence and no duplicate reporting.
4. Original dated older background, independently novel post-cutoff references and a human-reviewed prediction/reference isolation protocol.
5. Source-version SHA-256, a private content-addressed approved archive and a first real development case only after prior conditions. **Current status is still zero approved source versions and zero selected cases.**

See the [complete Leaky Vessels research dossier](P1A_LEAKY_VESSELS_CASE.md) and [P1a Issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24).
