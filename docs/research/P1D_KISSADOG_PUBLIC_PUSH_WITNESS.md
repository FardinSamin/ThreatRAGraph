# P1d — Independently archived public GitHub push of Cado Kiss-a-dog *pointer* (2022)

**Evidence acquisition:** October 10, 2026 EDT; independent public GitHub event at **December 23, 2022 11:42:28 UTC**. **This is a genuinely recovered third-party archived public PushEvent and original Securonix Git object chain**, not the original 2022 Cado article body, a confirmed original publication timestamp, or an approved source. 

## What changed since P1c

Prior research [P1c](P1C_KISSADOG_SAME_PEER_CHAIN.md) recovered original 2022 Securonix Git **reference and derived IOC file** bytes naming Cado's investigative Kiss-a-dog report, but only had a Git **self-declared committer timestamp**. That timestamp was insufficient to establish when the reference was visible on public GitHub.

I therefore acquired and scanned the **actual GH Archive public event stream** for the hour containing that commit. [GH Archive](https://www.gharchive.org/) records the public GitHub event stream hourly. The [precise original 2022-12-23 11:00 UTC gzip archive](https://data.gharchive.org/2022-12-23-11.json.gz) produced:

| Reproducible byte/event evidence | Verified exact value |
| --- | --- |
| Complete compressed hourly archive | **73,677,982 bytes** |
| Archive SHA-256 | `e13cf35c7bbc532d325f82970064b91dd9041e81fc0b1bddcdcb37fbf3bb60a6` |
| Complete original hour's JSON events scanned | **143,380** |
| Exact matching archived public event | **GitHub ID `26063265903`** |
| Public event UTC `created_at` | **2022-12-23T11:42:28Z** |
| Original JSON event **line** SHA-256 | `3d3506ad1a7a2effed5d969cb4f8fdcc4277acdac75dc49d8afff633b28d9b13` |
| GitHub repository and ID in original event | `Securonix/AutonomousThreatSweeper`, ID `359980821` |
| Original event type / visibility | `PushEvent` / `public=true` |
| Original event's branch / Git commit | `refs/heads/main` / `79b944c177a8640fb8f5396515daf2c249a43b15` |
| Exact Git blob in original commit, reference URL | `12bd1a3b9158c39270ba10727d03b349f13302ea` |
| Exact Git blob in original commit, derivative IOCs | `76844e58b73bda7e2af8d296f4cc9d0c2afc201e` |

The corresponding Git **committer** time was `2022-12-23T11:42:26Z`; the third-party archive independently records the public **push event** just two seconds later. The archived `created_at` supports public GitHub visibility **by that 2022 event time**, *subject to acceptance of the GH Archive service/event provenance*, rather than trusting author-supplied commit timestamps.

### Reproducible exact replay in GitHub Actions

- A new dedicated **ninth CI job** fetches the **full exact hourly archive** from `data.gharchive.org`, with HTTPS and bounded **160 MiB** compressed download and 150s request ceiling. It separately fetches only the fixed historic Git commit and Git object tree from the public `Securonix/AutonomousThreatSweeper` repo. **Downloaded research files are never executed.**
- `scripts/verify_kissadog_cado_public_push.py --require-original --git-repo <local-bare-repo>` SHA-256 hashes the **entire** original 2022 gzip archive, insists on the **pinned archive size and digest**, completely parses up to bounded lines/bytes, and requires **exactly one** match for the original `PushEvent`: `public=true`, correct numeric repository ID, repository name, original Git commit as both payload head and member of committed SHA list, branch main, date inside original hour, exact **event ID, UTC timestamp, and SHA-256 of raw JSON event line**. A forged/altered event or a convenient similarly named repo fails.
- The verifier uses the existing `scripts.verify_advisory_public_witness.git_object` / `verify_file_chain` utilities to recompute the Git **commit, tree and exact two blob identities** all the way to their filenames. Both raw pointer/IOC files are run through the prior strict `verify_kissadog_cado_pointer.verify_reference`, ensuring byte-level consistency across the third-party event, Git object tree and prior 2022 candidate reference receipt.
- The CI runner retains **only a JSON metadata receipt for 14 days**, not the full public activity archive, Git clone, third-party index or Cado article body. No malware files are executed.
- Adversarial tests use entirely **synthetic gzip/PushEvent fixtures** to ensure wrong hours, malformed timestamps, fake repositories, private/non-push events, different branches, wrong commit, missing/doubled matching events, modified archive hashes, corrupted gzip and fake Git repo paths **fail closed**. Only the real CI job certifies a match to actual pinned historic public data.

This verification does **not** cryptographically timestamp the original **Cado report** or prove publication rights. It supports a narrow, concrete first-public-reference observation from an independent third-party service. The GH Archive itself is not a cryptographically signed timestamp oracle; it is a separately maintained captured GitHub public event record. Human provenance review is still required.

## What it does NOT prove

- **Not the original Cado article text:** Neither the public event nor the Securonix derived IOC/reference Git objects contain Cado's original Redis honeypot article. The current migrated Cado page is not a pinned December 2022 HTML version. The 2022 recorded link cannot prove exact contemporaneous XMRig or XHide wording.
- **Not a third independent threat investigation:** Securonix's record is a **derivative link/index**, not independent field research corroborating Cado and CrowdStrike.
- **Not automatically the article’s first publication date:** The public event supports *a secondary reference visible by 2022-12-23 11:42:28 UTC*. It does not prove the date/time of the article's first publication, last modification, or the bytes served then.
- **Not a reviewed graph claim or source approval:** `original_cado_report_public_by_verified=false`, `source_version_approved=false`, `copyright_and_use_rights_approved=false`, `independent_semantic_campaign_claim_verified=false`, `g1_evaluation_eligible=false`, `research_ready=false`.
- **Not evidence that SCARLETEEL uses XHide:** The [candidate-only G1 per-peer source path](P1C_KISSADOG_SAME_PEER_CHAIN.md) remains a hypothesis, not a discovered truth or scored experiment; later reference labels remain isolated with prior search-summary exposure disclosed.

### Reproduction

The [quality workflow](../../.github/workflows/quality.yml) automatically downloads the exact original hour into temporary runner storage and shallow-fetches the exact historic Securonix Git commit as Git objects. An operator with private permitted copies can replay offline:

```powershell
python -m scripts.verify_kissadog_cado_public_push --archive data/private/2022-12-23-11.json.gz --require-original --git-repo data/private/securonix-history.git
```

A pass from the strict command, alongside the stored origin/acquisition record and Git object verification, is a candidate evidence receipt—not an approval. **Do not check the downloaded hourly archive or original third-party files into Git**.

## Next real go/no-go

Acquire and authenticate exact **publisher-controlled original 2022 Cado and CrowdStrike report HTML bytes** with independently observed before-cutoff availability, independent field-research claim adjudication, and source rights. Also establish the exact February 28 2023 **early Sysdig** source byte version before the tentative March 1 UTC cutoff; consider replacing the case prospectively if impossible. Original `campaign:Kiss-a-dog USES tool:xhide` still needs variant-scope review, independent same-peer claim-group acceptance, and blinded labels. Neither G1v2's two-group gate nor the source-approval rules were relaxed.

**Registry unchanged:** 30 candidate records, **0 approved source versions, 0 approved cases, 0 scored real B0/G1 comparisons**.
