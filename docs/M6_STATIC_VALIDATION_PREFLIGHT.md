# M6.6 — Stacked draft engineering preflight and validation handoff

**Status:** Draft static-inspection tooling, 15 tests authored and NOT
executed. No newly added PR has passing exact-head CI. Do not treat an
unblocked static preflight as successful runtime, integration or research
validation.

## What it solves

An offline, read-only script checks source/test presence, Python AST syntax,
simple local import declarations, the declared minimum number of authored
unittest methods, and a topologically ordered plan for the currently open
draft PRs.

The plan is in docs/ENGINEERING_VALIDATION_PLAN.json and records two groups:

- M6 dependent stack: PR #52, #53, #56, #57, #58, in merge-dependency order.
- Independent drafts: PR #51 (original-source archive discovery),
  #54 (portable evidence graph interchange), and #55 (historical alias
  candidate inspection). These are NOT secretly included in #58.

A given checkout can only contain some branches. A missing independent
component when running with --scope all is EXPECTED until that branch
is integrated. Do not equate that report with a failing runtime test.

## Local commands (no network, zero GitHub Actions minutes)

From the repository root, on the latest draft #59 branch:

    python -m scripts.preflight_validation_plan --scope m6

To produce machine-readable receipts:

    python -m scripts.preflight_validation_plan --scope m6 --format json

Use --scope independent to inspect independent drafts in a checkout
containing them (e.g. during integration), and --scope all only when
the code from all branches has actually been integrated.

The script does NOT run Python test cases, import application modules,
invoke GitHub, open held-out labels, access original CTI archives, touch
AWS, validate external reviewer identities or execute shell commands.
AST parsing does not generate compiled bytecode.

The JSON response sets test_cases_executed=0,
github_actions_triggered=false, git_history_or_pr_state_verified=false,
heldout_labels_accessed=false and research_ready=false.
A static success means only 'ready_for_actual_testing', not 'green CI'.

## Actual validation sequence — intentionally deferred

1. Record precise branch commit SHAs and verify live PR target/base and
   stacked ancestry in GitHub; this read-only script does not do remote PR
   lookups or infer branch lineage from labels.
2. Run targeted unittest discover commands in the validation-plan order,
   starting with paired B0/G1 and ending with multi-case replay.
3. Separately test the archive, portable exchange and alias components.
   Resolve conflicts in docs/IMPLEMENTATION_STATUS.md when integrating.
4. Execute one real-byte-backed SYNTHETIC pipeline and a two-case end-to-end
   example; verify preview/write digest equality, new artifact reload,
   failure injection, cutoff leakage, negative-label exclusion and absence
   of score inflation. Stubs do not replace this integration exercise.
5. Run the full local Python test suite and security/lint checks, then
   exact-head Linux/Windows CI once the existing included allowance resumes.
6. Independently verify source-rights, publisher chronology, true reviewer
   authority, post-cutoff evidence separation, full labels and externally
   witnessed freeze, before any real-case empirical claims or merge approval.

To run all Python tests *later*, one command is:

    python -m unittest discover -s tests -p 'test_*.py' -v

The existing workflow already uses Ruff, tracked-content secret detection,
exact dependency pins, public advisory audits and cross-OS tests. No
passing result from an earlier commit validates these new draft changes.

## Cost and CI duplication observation

As of October 11, 2026, the current .github/workflows/quality.yml triggers
on both feature/** pushes AND pull_request events, so a single pushed commit
on an open draft can initiate two large workflow runs. The workflow also
runs original-source network verification jobs on routine changes.
The last reported M6 Actions runs failed before runner allocation, with
11 of 11 jobs having zero executed steps; these are NOT Python test failures.

This preflight does not alter GitHub Actions settings or billing. A separate
workflow-cost change should later separate fast, low-cost unit checks from
manual/on-demand historical fetch/replay jobs, without disabling essential
research and security gates. Avoid enabling paid overages.

## Known limits

The plan is an explicitly versioned *snapshot* of expected PR numbers/paths
and validation commands. It is not fetched live from GitHub, and it must be
updated on rebases, PR replacements or merges. The tool does not prove
a local checkout contains the correct commit just because file paths exist.

Static Python AST inspection cannot prove runtime imports will succeed,
dependencies are installed, files are semantically correct, source bytes
are authentic, or proposed assertions are supported by publisher reports.
A malicious actor able to edit both plan and code can self-approve static
coverage. Independent review and actual execution remain mandatory.
