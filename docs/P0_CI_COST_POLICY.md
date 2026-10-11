# P0 — GitHub Actions budget-aware validation modes (draft)

**Status:** Proposed workflow change in a separate draft PR, not tested on
GitHub-hosted runners. The existing repository may have required check names,
branch protection, or review policies not verified by this code.

## Previous cost pattern

The existing Research repo checks workflow triggers on both feature/** push
and pull_request, so the same commit in an open PR can schedule duplicate
workflow runs. Each ordinary run can fan out into 11 jobs: eight external
original-source witness jobs, one security/lint job, and both Linux and
Windows unittest suites. These were repeatedly unable to acquire runners
after the monthly included Actions allowance was exhausted.

That does not mean the new Python code is wrong: a runner-less job executes
zero validation steps. It also does not prove any green test coverage.

## Proposed default (still guards quality)

- A feature push that belongs to an open PR triggers the pull_request
  event only, not a second push workflow. Push automation is retained for
  the main branch.
- PR/default pushes still run two useful jobs: security-and-quality on
  Ubuntu, and preflight-and-tests on Ubuntu. The ordinary unit suite is
  preserved. Ruff, pinned dependencies, the secret scanner, pip-audit and
  Python unit testing remain present.
- The eight external historical source witness jobs remain in the workflow
  but are skipped unless a person deliberately starts workflow_dispatch and
  opts in to run_historical_witnesses.
- Windows cross-platform unit tests remain available on a manual dispatch
  with run_cross_platform enabled. Ubuntu runs by default for pull requests,
  pushes to main, and manual dispatches.
- Concurrency cancellation stops stale PR jobs in favor of the latest
  commit's run, reducing duplicate spend during active development.
- Workflow permissions remain contents: read and checkout does not retain
  credentials.

Normal PR jobs: 2, instead of 11. This is a *job count*, not a guaranteed
billing-minute or dollar saving. Both remaining jobs still consume included
Actions minutes when runners are available. The dependency audit may make
external requests as part of its security checks.

## Manual full validation later

In the GitHub Actions tab, select Research repo checks, then Run workflow
on the **exact target branch/commit**. For complete cross-platform and
original-source verification, enable both boolean inputs:

- run_cross_platform = true
- run_historical_witnesses = true

This requests the full 11-job collection and may consume significant
Actions allowance. Do not run it until the user deliberately chooses to
start the real validation phase and has checked the available monthly
allowance and current budget. This draft does not change spending caps,
billing information, secrets or repository permissions.

Historical-source jobs should not be interpreted as source approval merely
because they run successfully: independent source/publication chronology,
rights and reviewer review still remain necessary.

## Merge and governance considerations

This workflow change is intended for early integration before starting a
large number of validation runs. It remains a draft until static test
coverage and a workflow parser/reviewer check confirm that dispatch, matrix
expressions, job names and required branch checks behave as designed.
Do not silently relax required branch-protection checks. Since ordinary
PR runs omit Windows and live source witnesses, explicitly require a
manual full validation run before merging major M6 changes.

The repository's static test module test_ci_cost_policy.py contains ten
authored but unexecuted source-text assertions. These cannot substitute for
an actual GitHub Actions YAML/schema validation and successful CI run.
No additional paid overage or runner allocation was authorized here.
