# P1a — Independent local PGP verification using release-era runc.keyring

**Research date:** October 10, 2026 (Eastern) · **Result:** locally cryptographically verified pinned original runc v1.1.12 annotated tag with the upstream project's **same-release** signing keyring. **Not an approved empirical source version.**

## Measured upstream result

Unlike an API-reported `verified` flag, the project now actually executes isolated GnuPG signature verification in CI using only the **original raw tag object** and the **`runc.keyring` file inside the pinned January 2024 commit**. Nothing is fetched from a current keyserver. The keyring is constrained by its canonical Git blob SHA-1 and the expected primary/signing-key identities.

| Evidence component | Measured / pinned value |
|---|---|
| Public upstream tag | [`opencontainers/runc` v1.1.12](https://github.com/opencontainers/runc/releases/tag/v1.1.12) |
| Original tag Git object | [Annotated tag](https://api.github.com/repos/opencontainers/runc/git/tags/20381324e21b5b232fea74d448b5975d85d34d25) |
| Original raw tag bytes | **1,525 bytes**, SHA-256 `f023cc7393c65bc560e37adb6de4d70055424a7c2708a531bc1910dd5fcbc70f` |
| Key source | [Historical `runc.keyring` at v1.1.12](https://github.com/opencontainers/runc/blob/v1.1.12/runc.keyring), from the same pinned upstream target commit |
| Original keyring Git blob | `3fb6d283636d0aef455301c6963815fc8ceed59a` |
| Keyring byte SHA-256 | `66a0f5cca7fb1bb18ae3eee8e0d3888c2e6f1e866e855041c89100c61d84622f` |
| Expected primary key | Aleksa Sarai **C9C370B246B09F6DBCFC744C34401015D1D2D386** |
| Tag signing subkey | **2897FAD2B7E9446F** (also listed by official GitHub release page) |
| Actual result | **GnuPG `GOODSIG` + `VALIDSIG`** with the pinned primary key and signing subkey; tag verification command exited successfully |
| Successful live verification | [GitHub Actions run #38099209073](https://github.com/FardinSamin/ThreatRAGraph/actions/runs/38099209073) · signed JSON witness artifact retained for 14 days |

The project also inspects the original Git repository's **v1.1.12 README**, which states that official runc releases are signed by one of the keys in `runc.keyring`. Thus the project's release-era key authorization is evidenced by the same original version, not by an unrelated modern keyserver. The historical Git object/keyring IDs are immutable *identity* checks; they are not timestamp attestations.

## Implemented verifier

- `scripts/verify_runc_tag_signer.py` checks the tag ref, original byte identity, historical keyring exact Git blob bytes, GnuPG public-key import in a clean temporary home and a real `git verify-tag --raw` invocation. It reads `GOODSIG` and `VALIDSIG` status messages and fails on wrong signer/primary fingerprint, missing signature or explicit bad/revoked/expired/error status. Untrusted text cannot impersonate exit-successful GnuPG verification without compromising the isolated binary or the pinned source material.
- The existing real-source CI acquisition job now **requires both** byte-level hash verification and actual historical-keyring PGP validation, and publishes separate hash-only evidence receipts (no raw source material or keyring exported).
- A new Python test suite rejects fabricated signer statuses, altered primary fingerprints, missing/malformed signatures, suspicious extra signatures, broken historical keyring bytes and missing local repository objects.
- No AWS, paid API, external signing-key server or executable code checked out from the upstream project is required. GitHub Actions uses a temporary bare Git repository and removes the imported keys with its isolated runner.

### Windows reproduction

First fetch the pinned tag as described in [P1a original-byte acquisition](P1A_PINNED_TAG_ACQUISITION.md), and install GnuPG (`gpg`) if not already present. From the ThreatRAGraph repository root:

~~~powershell
python -m scripts.acquire_runc_git_tag --git-repo '.\data\private\runc-release.git'
python -m scripts.verify_runc_tag_signer --git-repo '.\data\private\runc-release.git'
~~~

Both Python tools are offline. The explicit earlier `git fetch` is the only network step. The signing utility may return a failure until a usable `gpg` executable is installed locally; this does not mean it should silently skip signature checks.

## Limits: what this proves and does not prove

**Proven:** The specific original upstream tag bytes carry a valid PGP signature under the historically included project release keyring, with the expected signer and no reliance on a modern external keyserver or the GitHub API's subjective verification flag. The keyring and tag object have pinned exact content identities.

**Still unproven:** Independent out-of-band attestation that the fingerprint is owned by the named human, independent evidence of the **first time the exact signed Git tag was public**, individual source-text retention/reuse approval, faculty/investigator acceptance, a historically eligible and *independent* second initial report, real background/later reference revisions, and evidence-reviewed CTI extraction.

The v1.1.12 tagger time was **January 23, 2024**, but private tag creation/embargo is not a public-availability timestamp. The [GitHub release page](https://github.com/opencontainers/runc/releases/tag/v1.1.12) reports publication on **January 31, 2024 at 20:06 UTC**, with corroborating public oss-security mailing-list archive material; pinning signature bytes does not independently prove precisely when the tag itself was downloadable to the public.

**Study state after this milestone:** **20 source candidates; one original upstream tag byte-captured and cryptographically signed; 0 approved historical source versions, 0 approved development cases, and 0 empirical B0/G1 comparisons.** Both [P1a issue #24](https://github.com/FardinSamin/ThreatRAGraph/issues/24) and [M1 issue #3](https://github.com/FardinSamin/ThreatRAGraph/issues/3) stay open.
