# P1a continuation: independently retained public chronology

Research performed October 10, 2026 (Eastern; October 11 UTC). ThreatRAGraph main was rechecked at `66db406032a14c4383214793ce33c6434a7c42d4`. This dossier accompanies the candidate-only registration and offline verifier; no source or case approval is conferred.

## Result that advances the handoff

The original GitHub Advisory Database JSON for **GHSA-xr7r-f8xq-vfvv / CVE-2024-21626** has a recoverable, byte-verified revision whose containing commit appears in an independently retained public GitHub push event **before the proposed February 1, 2024 cutoff**.

This provides a concrete alternative early source version to the presently mutable advisory page. It supplies a defensible proposed **public-by time of January 31, 2024, 22:46:10 UTC**, subject to the investigator accepting GitHub event timestamps and GH Archive's preservation as historical evidence. It does not establish the first-ever public disclosure time or approve the source for a study.

[GH Archive](https://www.gharchive.org/) documents that it retains public GitHub Events API records in hourly compressed JSON archives. I downloaded the original hourly files, retained them locally, recorded HTTP metadata and hashes, and extracted the relevant original event lines. No paid query service was used.

## Exact evidence chain

1. [The January 31, 2024, 22:00 UTC archive](https://data.gharchive.org/2024-01-31-22.json.gz), line **163762**, contains public `PushEvent` **35293494004** for `github/advisory-database` (repository ID **458364565**).
2. Its server event time is **2024-01-31T22:46:10Z**. Its branch is `refs/heads/main`, and both the push head and commit list identify **02a8b9a4f9d305f0e028ef58f0dcf28f55bf10ae**.
3. That [exact commit](https://github.com/github/advisory-database/commit/02a8b9a4f9d305f0e028ef58f0dcf28f55bf10ae) contains the [original advisory JSON](https://github.com/github/advisory-database/blob/02a8b9a4f9d305f0e028ef58f0dcf28f55bf10ae/advisories/github-reviewed/2024/01/GHSA-xr7r-f8xq-vfvv/GHSA-xr7r-f8xq-vfvv.json).
4. An offline replay independently recalculates canonical Git object identities for the commit, six successive directory trees, and the final file blob. Every directory entry binds the next object's ID. This connects the archived commit ID to the exact advisory bytes rather than relying on a current file URL or commit date alone.
5. The advisory is **13,105 bytes**, Git blob **2a90e030e322bd49c4b3f43410867428e474fa48**, SHA-256 **e13a3fd37dc98874e6e942d3237660a64e7310a7757427ee60953e76a9f6f4a2**. The contained `published` and `modified` fields both say **2024-01-31T22:44:08Z**. Those internal fields corroborate the sequence but are not the external timing witness.

| Preserved object | Byte count | SHA-256 |
|---|---:|---|
| Complete 22:00 UTC archive | 102,934,253 | `0d888a725800cdf7786a4e632ad742e89186f380317c5be4f290c01770de1021` |
| Original event line, including newline | Recorded in the retained archive | `291d43374d69d2485024bca05f2e9c9adcbf07146e2a779d1df4e76a22783e92` |
| Original advisory JSON | 13,105 | `e13a3fd37dc98874e6e942d3237660a64e7310a7757427ee60953e76a9f6f4a2` |

The download reported HTTP `Last-Modified: Wed, 31 Jan 2024 23:05:29 GMT`, also before cutoff. This is supporting storage metadata observed today, not a cryptographic timestamp authority. The commit itself is unsigned; the inference relies on the independently retained event naming its content identity, not on a signature or author-controlled commit time. Checksums measured today cannot retroactively timestamp content.

## What the release-hour archive establishes

[The 20:00 UTC archive](https://data.gharchive.org/2024-01-31-20.json.gz) contains:

| Event | Time UTC | Supported conclusion |
|---|---|---|
| CreateEvent 35289730396, line 22178 | 20:05:36 | The tag name `v1.1.12` was publicly announced. The event does not carry its annotated tag object ID. |
| ReleaseEvent 35289748416, line 24324 | 20:06:09 | Release ID 137479329 was published for `v1.1.12`; its retained release payload says `published_at=20:06:08Z`. |

The complete archive is **107,522,630 bytes**, SHA-256 **0f7d2ce0e058242ff5e57d8f4603682f570e46370395b11c9282ea5a64d2528c**. The release-event line SHA-256 is **2cc2420311b7d209ab5a5811c9397f8ff0d20fa383c1a5a412b471499a520336**.

Neither event binds the exact signed Git tag OID. `target_commitish` is the branch name `main`, not an immutable commit. Therefore the prior exact-tag public-availability question remains unresolved. Historical release text retained inside the event is a distinct possible source artifact, not interchangeable with raw signed tag bytes or current release HTML.

## Rights and independence evidence

The pinned advisory commit's [README](https://github.com/github/advisory-database/blob/02a8b9a4f9d305f0e028ef58f0dcf28f55bf10ae/README.md) identifies **CC-BY 4.0**, and its [LICENSE.md](https://github.com/github/advisory-database/blob/02a8b9a4f9d305f0e028ef58f0dcf28f55bf10ae/LICENSE.md) contains the corresponding license. Both were fetched, preserved, and verified through the same commit/tree chain. License file blob: `4ea99c213c5c0c005ae4e80df8e52169d06896ec`; README blob: `9041b77116cf3a7fc3e13317ec53a553c1793487`.

This makes a source-specific attribution/retention review concrete. It does not automatically license the entire GH Archive dump or referenced third-party pages, establish ownership of every embedded contribution, or substitute for the project's required investigator review. No full upstream source text is being published to the research repository.

The GitHub database copy remains in **runc-maintainer-releases** for substantive CTI independence. The archive independently preserves chronology; it does not create an independent threat report or a second independently corroborating background source.

## Case-design implications

The exact original advisory already contains the described escape variants, the relationship to CVE-2019-5736, mitigations and discussion of other runtimes. A later article repeating those facts cannot make them novel prediction targets. Novelty must be assessed against this original early version before accepting Leaky Vessels as a useful evaluation case. No later-reference labels or model predictions were generated during this acquisition.

Separately, the repository audit established that a correctly typed `vulnerability:CVE-2024-21626` target has no eligible features under the implemented G1 `USES`/`HAS_BEHAVIOR` rules. It abstains even with a structurally valid graph. More source collection alone will not resolve that design mismatch. The case unit and ontology-valid feature scope need to be settled before choosing outcome labels or evaluating G1. Do not relabel a vulnerability as malware to clear the gate.

The current screen also has only one eligible independent background group. The ranker's corroboration policy requires two across its analogy path. Its same-maintainer 2019 disclosure cannot be counted as an independent group simply because it is older.

## Reproduction and measured receipt

The small [replay receipt](P1A_ORIGINAL_ADVISORY_RECEIPT.md) contains hashes and identifiers only. It is an ordinary replay output, not a signed attestation. A reviewer should independently reacquire and verify the evidence.

Download the linked 22:00 archive to ignored `data/private/2024-01-31-22.json.gz`. Acquire Git objects separately without checking out or executing upstream code:

```powershell
git init --bare data/private/advisory.git
git -C data/private/advisory.git fetch --no-tags --depth=1 https://github.com/github/advisory-database.git 02a8b9a4f9d305f0e028ef58f0dcf28f55bf10ae
python -m scripts.verify_advisory_public_witness --archive data/private/2024-01-31-22.json.gz --git-repo data/private/advisory.git
```

This acquisition fetches the complete pinned tree. Filtered acquisition is possible if every required advisory, README, license and parent-tree object is materialized first. The verifier disables Git transport protocols and lazy fetching and makes no network requests. It requires Python 3.11+ and Git; CI uses Python 3.12. Missing objects fail closed.

The verifier refuses altered archive/event hashes, wrong event repository/head/ref, missing or modified Git objects, symlink file modes and cutoffs at or before the public event. Unit tests use small artificial fixtures; passing them is not evidence that the original archive was acquired. The original archive and source bodies remain in ignored private storage.

## Case scope disposition

Retain Leaky Vessels as a provenance and extraction development case. It is not an executable G1 evaluation case under the current method. That limitation is not a negative research result.

G1 now reports `unsupported_target_type_for_current_features` and explicit target-type diagnostics for ontology-valid vulnerability facts. It retains B0 facts without altering ranking, ontology or independence thresholds. A future vulnerability method needs a separately versioned design with meaningful features beyond sharing the same component, reviewed before outcomes are inspected. Alternatively, select a genuinely documented malware/campaign/technique target compatible with the existing ontology. Do not relabel a CVE as malware.

## Acceptance remaining

1. Investigator accepts or rejects the public-by assumption and reviews source-specific rights and attribution.
2. Select the actual first one or two early sources; the recovered advisory is an alternative, not a third report. Its source group remains runc-maintainer-releases.
3. Recover independent eligible background and isolate later reference versions; assess novelty and modern blinded annotation versus historical evidence dates.
4. Resolve case/method compatibility before approving an executable case or observing its G1 outcome.
5. Extract and independently review real source-backed claims.

The registry now has **21 candidates, zero approved versions and zero selected cases**. The new candidate's approved digest/date fields remain null; measured hashes and the proposed bound are recorded in the separate witness. The screening retains it as excluded pending early-source selection. No study or faculty approval is asserted.
