# M0 — Prototype Intake and As-Built Audit

**Status:** Intake preparation only; source audit not yet possible.  
**Tracking:** [Issue #1](https://github.com/FardinSamin/ThreatRAGraph/issues/1)  
**Architecture:** [SRS](SRS.md) and [SDD](SDD.md), especially SDD `15.

## 1. Goal and initial evidence

The URFS proposal states that a local Python workflow already collects public CTI, extracts threat entities/relationships and builds a graph. GitHub currently has the SRS/SDD and import preparation, **not the prototype**. M0 establishes the actual implementation state and its gap against the research specification. Do not attribute behavior, results or AWS usage to the uploaded repo until code and tests are inspected.

## 2. Locate the original project — Windows PowerShell

In the **original prototype folder**, run:

~~~powershell
Get-Location
Get-ChildItem -Force | Select-Object Name, Mode, Length
git status --short
git branch -a
git log -5 --oneline
~~~

If Git reports that the folder is not a repository, that is fine. Do not share secrets or remote URLs with embedded credentials. **Make a private offline backup of the original project and any existing Git history** before copying or running import commands.

## 3. Safe, conservative import

Use a *different folder* for the GitHub checkout to avoid overwriting the prototype:

~~~powershell
git clone https://github.com/FardinSamin/ThreatRAGraph.git ThreatRAGraph-intake
cd ThreatRAGraph-intake
git switch -c import/local-prototype
~~~

From this fresh checkout, run a **read-only** preflight against the original directory:

~~~powershell
python scripts/preflight_import.py "C:\full\path\to\original\prototype"
~~~

Results: **exit code 0** means no finding in inspected files, not guaranteed safety; **2** means sensitive names/patterns, symlinks or limits need review; **1** indicates script failure. Results list paths and categories **but no file contents or token values**.

Manually review the original project's dependencies, tracked files, untracked files, dataset rights, and any prior Git commits before importing. **Do not blindly copy the entire project.** Copy only approved source, safe fixtures, dependency declarations and legitimate metadata to the clean checkout. Exclude `.git/`, virtual environments, `.env`, tokens/keys, logs, SQLite data, cloud config, restricted CTI source files and generated output.

Run the preflight on the checkout and review both working files and the actual staged set:

~~~powershell
python scripts/preflight_import.py .
git status --short
git add --dry-run .
git add -A
git diff --cached --stat
git diff --cached
~~~

If anything looks sensitive, **stop and unstage it** before proceeding. Check the contents of staged files locally; do not paste keys into issues or chat. Once reviewed:

~~~powershell
git commit -m "chore: import reviewed local prototype"
git push -u origin import/local-prototype
~~~

Open a PR from `import/local-prototype` to `main`; do not merge until safety and functionality are reviewed. This conservative approach preserves the **original local project in place** but imports its current approved source as a new commit rather than replaying the original history.

### History-preservation alternative

If maintaining **published original commit history** is necessary, first comprehensively inspect **every** historical revision for credentials, proprietary material, licenses and restricted CTI. Only after that review can an intentional merge of unrelated histories be considered. Never use a blind `git push --mirror`, forced push or `git merge --allow-unrelated-histories`. A new `.gitignore` does **not** remove files already tracked or secrets from old commits; leaked credentials require rotation and history remediation.

### Limitations of the scanner

The preflight is a simple **heuristic**, not a substitute for proper secret scanners, source-rights review or full Git history scanning. It skips cache/virtual-environment directories, cannot comprehensively inspect binary or large files, and detects only selected credential patterns. No collection, internet traffic, host scanning or AWS calls are performed.

## 4. Actual implementation audit (after import)

### 4.1 Inventory and as-built architecture

Record the following with paths, versions and evidence:
- Local Git lineage, entry points, Python interpreter, package manifests and setup commands.
- CTI, OTX, STIX/ATT&CK, CVE, Falco and Kubernetes adapters actually implemented.
- Extractor providers/models, prompt/config versions, validation and error handling.
- Typed nodes/relationships, graph backend, query code, identity resolution, source provenance.
- Source collection, rights, date metadata, ingestion vs. publication times.
- Presence or absence of cold-start profiling, graph similarity and temporal cutoff logic.
- Unit/integration tests, fixtures, API/CLI/dashboard behavior.
- Cloud configuration and evidence of cloud costs/resources; **do not provision** during audit.

### 4.2 Baseline execution

1. Establish a clean Python virtual environment and dependency versions (do not assume the SDD's proposed stack is installed).
2. Run tests or safe local sample extraction/graph code with **offline fixtures** where possible.
3. Capture exact commands, Git SHA, input manifest/hash, environment, stdout/stderr summaries, observed outputs and reproducible failures.
4. Do not run exploit code, remote scans, suspicious binaries or costly cloud resources.
5. Report verified behavior only; an absent test is **unknown/unverified**, not a passing test.

### 4.3 Requirement coverage matrix

Create `docs/audits/M0_IMPLEMENTATION_AUDIT.md` after inspection, mapping:

| SRS ID | Implementation path | Test/evidence | Status | Risk | Next action |
|---|---|---|---|---|---|
| FR-01 | Pending | Pending | Unknown | Undetermined | Inspect source manifest |
| FR-09 | Pending | Pending | Unknown | Undetermined | Inspect extractor |
| FR-14 | Pending | Pending | Unknown | Undetermined | Inspect graph |
| FR-21 | Pending | Pending | Unknown | High research risk | Inspect temporal graph isolation |
| FR-24 | Pending | Pending | Unknown | High | Inspect baseline |

Continue the matrix for all material SRS requirements. Use only: **Verified**, **Present untested**, **Partial**, **Missing**, **Unknown**. A design document alone is never implementation evidence.

## 5. Exit gate

M0 is complete only when:
1. The local prototype is imported in a **reviewed** PR (or unavailability is documented).
2. An as-built inventory and architecture comparison exist with true tests/failures.
3. Secret/data rights concerns are recorded and resolved or explicitly deferred.
4. The SRS requirement status matrix and prioritized M1 backlog are committed.
5. The original source and its private backup remain intact.

**Do not start a major refactor until these gaps and risks are understood.**
