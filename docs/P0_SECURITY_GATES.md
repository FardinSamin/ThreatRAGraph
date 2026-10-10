# P0.2 — Security, dependency and quality gates

**Status:** New machine-enforced checks in GitHub Actions; this is **not** full supply-chain certification or the completion of P0.

The existing Ubuntu and Windows Python 3.12 test jobs now install exact, pinned runtime dependencies with `pip --no-deps` and verify installed versions with `scripts/check_dependency_versions.py`. Unsupported, duplicate, unpinned, missing or mismatched runtime packages fail closed.

A new Ubuntu **Security, supply chain and Python lint** CI job uses the pinned `requirements-dev.txt`:

- **Ruff** scans `src`, `scripts`, and `tests` with `E4,E9,F` rules for basic import, undefined-name and syntax errors. Broader formatting, static typing and quality rules remain pending.
- **detect-secrets** scans Git-tracked working-tree files. `scripts/check_secrets.py` fails closed if the scanner fails or emits potential secret findings. Only counts are printed by the wrapper; no matched values are printed.
- **pip-audit** checks the pinned runtime parser requirements against PyPI's public vulnerability advisories, failing the job on known advisories or auditing errors.
- `python -m pip check` checks package-environment consistency.

## Local reproduction

Install the runtime packages and quality tools in a disposable virtual environment:

~~~powershell
python -m pip install --no-deps -r requirements-normalization.txt
python -m pip install -r requirements-dev.txt
python -m scripts.check_dependency_versions
python -m pip check
python -m ruff check --select E4,E9,F src scripts tests
python -m scripts.check_secrets
python -m pip_audit -r requirements-normalization.txt --no-deps --strict --progress-spinner off
python -m unittest discover -s tests -v
~~~

**Network boundary:** install and public advisory scanning may access PyPI. The research source processing and inference code remains offline, with no AWS or paid APIs. If the advisory API is unreachable, the security job fails rather than declaring the dependencies safe.

## Limits and remaining P0 work

1. Exact version pins are **not a cross-platform SHA-256 wheel lock**. Reproducible OS-specific wheels and complete development-tool dependency locking remain pending.
2. The secret scanner scans the **currently tracked working tree**, not entire Git history. It is heuristic, not proof that secrets have never existed. Suspected leaked credentials require rotation and history review.
3. Public vulnerability databases may omit unknown vulnerabilities; green checks are **point-in-time assurance, not a guarantee of security**.
4. Ruff's current error rules are a starting baseline. Extend formatting and type enforcement in a separate reviewed PR.
5. Branch-protection **required status checks are not automatically enabled by a workflow file**. An authorized repository administrator must set/verify protection requiring both OS checks and the security job; this PR does not claim settings were applied.
6. GitHub Actions runs must be reviewed on the **exact PR head**. The project-wide `research_ready=false` disclosure remains in force: security checks do not prove historical source validity or experimental results.
7. Schema migration, provenance approvals, as-of alias/ontology/feature checks and independent gold-label isolation remain substantive P0–P5 obligations.

[Issue #23](https://github.com/FardinSamin/ThreatRAGraph/issues/23) remains open. Follow [BUILD_PLAN.md](BUILD_PLAN.md) and [P0 readiness](P0_READINESS_CONTRACT.md).
