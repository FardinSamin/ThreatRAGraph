# P1a — Original pinned runc Git tag byte acquisition

**Status:** Real upstream content-addressed tag bytes **successfully acquired in GitHub Actions**, but **source approval, trusted signer verification, and independent historical public availability remain OPEN**.
**Case:** Leaky Vessels, CVE-2024-21626 · [P1a Issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24) · [Original release witness](P1A_RUNC_RELEASE_WITNESS.md).

## What we actually acquired (not a mock)

An Ubuntu GitHub Actions job uses a bare Git object database and fetches **only the original upstream annotated tag** `refs/tags/v1.1.12` from the public `opencontainers/runc` Git repository. It does **not** checkout, compile, run or otherwise execute the upstream project's code. It verifies the tag ref still points to the preregistered object, uses `git cat-file tag` to obtain raw annotated-tag bytes, recomputes the canonical Git **SHA-1 object identity** from the raw bytes, and confirms the exact tagged commit and the presence of the CVE disclosure message and PGP signature envelope.

| Observed artifact property | Value |
|---|---|
| Upstream Git tag | [`opencontainers/runc` `v1.1.12`](https://github.com/opencontainers/runc/releases/tag/v1.1.12) |
| Git tag object | [View pinned tag object](https://api.github.com/repos/opencontainers/runc/git/tags/20381324e21b5b232fea74d448b5975d85d34d25) |
| Raw annotated-tag byte length | **1,525 bytes**, measured by actual acquisition job |
| Raw object SHA-256 | **`f023cc7393c65bc5…5fcbc70f`** (abbreviated here; full digest in downloadable **GitHub Actions receipt**) |
| Tagged commit | [View pinned commit](https://github.com/opencontainers/runc/commit/51d5e94601ceffbbd85688df1c928ecccbfa4685) |
| First successful artifact-acquisition run | [GitHub Actions run #38098752533](https://github.com/FardinSamin/ThreatRAGraph/actions/runs/38098752533) |
| License provenance lead | `LICENSE` file at `v1.1.12` is **Apache-2.0**, verified via upstream repo; human source-specific retention/redistribution review still pending |

The workflow publishes a **hash-only JSON acquisition receipt** for 14 days as a CI artifact; the actual third-party tag raw bytes are stored only under an ephemeral CI runner's private artifact directory and are discarded with the runner. The registered Git object is retrievable at any time from upstream and the SHA-256 can be reproduced locally. The private archive tool will persist the raw bytes on the investigator's computer when run locally.

**Important:** This is the **first original upstream source artifact whose exact raw bytes were retrieved and hashed**. It was not silently changed into an approved CTI case source. In `datasets/manifests/pilot.json`, `candidate:runc-signed-release-tag:unfrozen` remains `status=candidate`, with `available_at=null`, `published_at=null`, `date_confidence=unknown`, `redistribution=unknown`, and `sha256=null`. The measured digest exists in the external acquisition receipt, **not** an approved source-version record. There are now **20 candidate entries, 0 approved source versions, 0 selected cases, and 0 real B0/G1 performance measurements**.

## Reproduce on your Windows PC (no cloud account or paid tools required)

~~~powershell
# Run these commands inside your ThreatRAGraph repository.
New-Item -ItemType Directory -Force -Path '.\data\private' | Out-Null
git init --bare '.\data\private\runc-release.git'
git -C '.\data\private\runc-release.git' fetch --no-tags --depth=1 'https://github.com/opencontainers/runc.git' '+refs/tags/v1.1.12:refs/tags/v1.1.12'
python -m scripts.acquire_runc_git_tag --git-repo '.\data\private\runc-release.git' --artifact-root '.\artifacts\source_versions\sha256'
~~~

The tool itself has **no network access**. Only the explicit `git fetch` step contacts public GitHub. It refuses a moved upstream tag ref, an unexpected Git object/type/commit, altered raw bytes, a missing CVE marker/signature envelope, invalid registry metadata or corrupt/conflicting private artifacts. Its SHA-256 is computed over `git cat-file tag` **exact raw bytes**, not a GitHub API JSON envelope or mutable release HTML. It reuses the tested local candidate capture utility to retain a non-approved hash receipt, with local capture time. Do not commit raw third-party text or private receipts to the public GitHub repository.

## What this proves and what it DOES NOT prove

**Demonstrated:** The currently reachable original tag object is exactly pinned to the recorded Git SHA-1 object ID, target commit and original Git object contents, and the original bytes can be independently reproduced and SHA-256 hashed. The tag carries an armored PGP signature **envelope**, and GitHub separately reports `valid` PGP verification. Git object ID SHA-1 is a legacy object identifier, not a modern cryptographic signer identity check; the additional SHA-256 records the byte content.

**Not demonstrated:**

- Independent trusted-maintainer public-key verification of the tag's cryptographic PGP signature (`git verify-tag` with a separately authenticated key), not merely the signature envelope or GitHub's public verification status.
- A separate independently evidenced historical **first-public-availability timestamp for these exact bytes** on January 31, 2024. GitHub's official v1.1.12 release record currently reports `published_at=2024-01-31T20:06:08Z`, corroborated by January 31 public mailing-list disclosure; a Jan 23 tagger timestamp is **NOT public availability**.
- Specific human-reviewed retention/redistribution authorization for the tagged message (the parent source tree has an Apache-2.0 license lead), faculty/researcher approval, and provenance-based extraction of reviewed claim spans.
- An **independent second early research report**, historically original 2019 background source, genuinely novel later reference labels and pre-cutoff historical ATT&CK/Falco/alias mappings. Same-publisher runc release, signed tag and mailing-list copies cannot be counted as multiple independent sources.

**Signer update (2026-10-10):** The next milestone [locally verified the pinned tag's actual PGP signature](P1A_RUNC_SIGNER_VERIFICATION.md) using a fresh GnuPG home and Aleksa Sarai's public key from the original v1.1.12 `runc.keyring` Git blob. External owner identity, exact first-public availability, rights and case approval are still outstanding.

**Next evidence gate:** inspect trusted release signing keys and tag verification, document source-message rights, independently corroborate when the exact tag was publicly retrievable, decide the eligible cutoff with reviewer signoff, then acquire original historical background and later reference bytes. Only then promote a **development** case and test actual evidence-to-graph extraction. Source ownership and human adjudication cannot be replaced by more synthetic tests.
