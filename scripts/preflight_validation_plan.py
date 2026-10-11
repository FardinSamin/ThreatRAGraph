#!/usr/bin/env python3
"""Read-only local static preflight for ThreatRAGraph staged draft changes.

Does not execute tests, import research modules, start a workflow, read CTI
archives, load gold labels, authenticate GitHub PR state, or make network calls.
Presence, parseability, and basic direct local imports are NOT passing tests.
"""
from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path, PurePosixPath
import sys

PLAN_RELATIVE = "docs/ENGINEERING_VALIDATION_PLAN.json"
MAX_PLAN_BYTES = 128 * 1024
MAX_CODE_BYTES = 1024 * 1024
PLAN_FIELDS = frozenset({"schema_version", "artifact_kind", "stages"})
STAGE_FIELDS = frozenset({
    "id", "scope", "pr_number", "head_branch", "base_branch", "requires",
    "source_paths", "test_paths", "min_authored_test_methods",
    "test_command", "manual_gates",
})
SCOPES = frozenset({"m6", "independent"})


def _unique_json_keys(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Duplicate validation-plan JSON key")
        output[key] = value
    return output


def _safe_path(raw):
    if type(raw) is not str or not 1 <= len(raw) <= 240:
        raise ValueError("Invalid validation-plan path")
    if "\\" in raw or ":" in raw or "\x00" in raw:
        raise ValueError("Unsafe validation-plan path")
    parsed = PurePosixPath(raw)
    if (parsed.is_absolute() or any(p in (".", "..") for p in raw.split("/"))
            or not raw.endswith(".py")):
        raise ValueError("Expected relative Python source or test path")
    return raw


def validate_plan(plan):
    """Check exact planning schema and a topological PR dependency DAG."""
    if not isinstance(plan, dict) or set(plan) != PLAN_FIELDS:
        raise ValueError("Unexpected validation-plan fields")
    if (plan["schema_version"] != "1.0"
            or plan["artifact_kind"] != "engineering_validation_plan_v1"):
        raise ValueError("Unsupported validation-plan revision")
    stages = plan["stages"]
    if not isinstance(stages, list) or not 1 <= len(stages) <= 32:
        raise ValueError("Validation-plan stage list must be bounded")
    known, prs, branches = set(), set(), set()
    for stage in stages:
        if not isinstance(stage, dict) or set(stage) != STAGE_FIELDS:
            raise ValueError("Stage requires exact fields without labels")
        name = stage["id"]
        if (type(name) is not str or not name.isidentifier()
                or name in known):
            raise ValueError("Duplicate or invalid stage ID")
        if stage["scope"] not in SCOPES:
            raise ValueError("Unrecognized validation-plan stage scope")
        pr = stage["pr_number"]
        if type(pr) is not int or pr <= 0 or pr in prs:
            raise ValueError("Duplicate or invalid PR planning number")
        for key in ("head_branch", "base_branch"):
            value = stage[key]
            if (type(value) is not str or not value
                    or len(value) > 160 or any(c.isspace() for c in value)):
                raise ValueError("Invalid planning branch label")
        if stage["head_branch"] in branches:
            raise ValueError("Duplicate head branch in plan")
        dependencies = stage["requires"]
        if (not isinstance(dependencies, list)
                or len(dependencies) != len(set(dependencies))
                or any(type(n) is not str or n not in known
                       for n in dependencies)):
            raise ValueError("Stage dependencies must precede their consumers")
        if dependencies:
            if stage["base_branch"] != next(
                row["head_branch"] for row in stages if row["id"] == dependencies[-1]
            ):
                raise ValueError("Stack base branch does not match last dependency")
        elif stage["base_branch"] != "main":
            raise ValueError("Independent stages must explicitly branch from main")
        source = stage["source_paths"]
        tests = stage["test_paths"]
        if (not isinstance(source, list) or not source
                or not isinstance(tests, list) or not tests
                or any(type(v) is not str for v in [*source, *tests])):
            raise ValueError("Stage source and test inventories are required")
        paths = [_safe_path(v) for v in [*source, *tests]]
        if len(set(paths)) != len(paths):
            raise ValueError("Duplicate stage file paths")
        if not all(p.startswith("tests/test_") for p in tests):
            raise ValueError("Stage tests must be explicit unittest files")
        minimum = stage["min_authored_test_methods"]
        if type(minimum) is not int or not 1 <= minimum <= 500:
            raise ValueError("Expected authored-test count must be bounded")
        command = stage["test_command"]
        if (type(command) is not str
                or not command.startswith("python -m unittest discover -s tests ")
                or len(command) > 300):
            raise ValueError("Unsupported manual test command")
        checks = stage["manual_gates"]
        if (not isinstance(checks, list) or not checks or len(checks) > 12
                or any(type(v) is not str or not v.strip() or len(v) > 240
                       for v in checks)):
            raise ValueError("Manual verification gates required")
        known.add(name)
        prs.add(pr)
        branches.add(stage["head_branch"])
    return stages


def _local_path(root, relative):
    """Confine a repo-relative source path and refuse symlink components."""
    path = root
    for part in PurePosixPath(relative).parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("Symlinked source component")
    if not path.resolve(strict=False).is_relative_to(root):
        raise ValueError("Source path escapes repository root")
    return path


def _tree(path):
    """Static Python AST only; never execute imports or generate pycache."""
    if not path.is_file():
        raise FileNotFoundError("Required source or test file missing")
    if not 0 < path.stat().st_size <= MAX_CODE_BYTES:
        raise ValueError("Source is empty or exceeds static inspection limit")
    return ast.parse(path.read_text(encoding="utf-8"), filename=path.as_posix())


def _exports(tree):
    exports = set()
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)):
            exports.add(node.name)
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    exports.add(target.id)
        elif isinstance(node, (ast.ImportFrom, ast.Import)):
            for alias in node.names:
                exports.add(alias.asname or alias.name.split(".")[0])
    return exports


def _import_errors(root, source_path, tree, cached):
    """Check direct local Python module paths and explicitly exported names.

    Cannot resolve runtime/dynamic imports or prove dependency installation.
    """
    warnings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level:
            module = node.module or ""
            parents = source_path.parent
            for _ in range(node.level - 1):
                parents = parents.parent
            path = parents / (module.replace(".", "/") + ".py")
        elif node.module and (
                node.module.startswith("scripts.")
                or node.module.startswith("src.threatragraph.")):
            path = Path(node.module.replace(".", "/") + ".py")
        else:
            continue
        try:
            relative = path.as_posix()
            _safe_path(relative)
            target_path = _local_path(root, relative)
            if relative not in cached:
                cached[relative] = _tree(target_path)
            found = _exports(cached[relative])
            for name in node.names:
                if name.name != "*" and name.name not in found:
                    warnings.append(relative + " does not declare " + name.name)
        except (OSError, ValueError, SyntaxError, UnicodeError) as exc:
            warnings.append(path.as_posix() + ": " + type(exc).__name__)
    return sorted(set(warnings))


def audit_stage(root, stage, cached):
    missing, syntax, imports = [], [], []
    count = 0
    files = [*stage["source_paths"], *stage["test_paths"]]
    for relative in files:
        try:
            path = _local_path(root, relative)
            tree = cached.get(relative)
            if tree is None:
                tree = _tree(path)
                cached[relative] = tree
            imports.extend(_import_errors(root, Path(relative), tree, cached))
            if relative in stage["test_paths"]:
                count += sum(
                    isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name.startswith("test_")
                    for node in ast.walk(tree)
                )
        except (OSError, UnicodeError, ValueError) as error:
            missing.append({"path": relative, "error": type(error).__name__})
        except SyntaxError as error:
            syntax.append({"path": relative, "line": error.lineno})
    ready = (not missing and not syntax and not imports
             and count >= stage["min_authored_test_methods"])
    return {
        "stage_id": stage["id"],
        "pr_number_planned": stage["pr_number"],
        "scope": stage["scope"],
        "requires": list(stage["requires"]),
        "files_declared": len(files),
        "missing_or_unsafe": missing,
        "python_syntax_errors": syntax,
        "direct_local_import_findings": sorted(set(imports)),
        "authored_test_methods_detected": count,
        "authored_test_methods_minimum": stage["min_authored_test_methods"],
        "static_preflight": "ready_for_actual_testing" if ready else "blocked",
        "tests_executed_by_preflight": 0,
        "ci_verification": "not_checked",
        "research_approval": "not_checked",
        "manual_test_command": stage["test_command"],
        "manual_gates": list(stage["manual_gates"]),
    }


def audit_checkout(repo_root, plan, scope="m6"):
    """Bounded read-only view; no external PR lookup or project artifact access."""
    if scope not in (*SCOPES, "all"):
        raise ValueError("Unknown preflight scope")
    root = Path(repo_root).expanduser()
    if root.is_symlink() or not root.is_dir():
        raise ValueError("Repository root must be a real local directory")
    root = root.resolve(strict=True)
    stages = validate_plan(plan)
    selected = [s for s in stages if scope == "all" or s["scope"] == scope]
    cached = {}
    reports = [audit_stage(root, stage, cached) for stage in selected]
    blocked = [row["stage_id"] for row in reports
               if row["static_preflight"] == "blocked"]
    return {
        "schema_version": "1.0",
        "artifact_kind": "read_only_engineering_static_preflight",
        "selected_scope": scope,
        "stage_count": len(reports),
        "blocked_stages": blocked,
        "stages": reports,
        "python_modules_imported": False,
        "test_cases_executed": 0,
        "github_api_accessed": False,
        "git_history_or_pr_state_verified": False,
        "github_actions_triggered": False,
        "actual_ci_outcomes_verified": False,
        "heldout_labels_accessed": False,
        "research_ready": False,
        "summary": ("static_checks_only_no_tests_executed"
                    if not blocked else "static_checks_blocked"),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--plan", default=PLAN_RELATIVE)
    parser.add_argument("--scope", choices=("m6", "independent", "all"),
                        default="m6")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        root = Path(args.repo_root)
        plan_file = root / args.plan
        if plan_file.is_symlink() or not plan_file.is_file():
            raise ValueError("Missing or unsafe validation plan")
        if not 0 < plan_file.stat().st_size <= MAX_PLAN_BYTES:
            raise ValueError("Oversized or empty validation plan")
        plan = json.loads(plan_file.read_text(encoding="utf-8"),
                          object_pairs_hook=_unique_json_keys)
        outcome = audit_checkout(root, plan, scope=args.scope)
    except (OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError, json.JSONDecodeError) as error:
        print(json.dumps({"status": "static_preflight_refused",
                          "error_category": type(error).__name__,
                          "tests_executed": 0, "research_ready": False},
                         sort_keys=True))
        return 2
    if args.format == "json":
        print(json.dumps(outcome, indent=2, sort_keys=True))
    else:
        print("Static engineering preflight (NO tests executed)")
        for row in outcome["stages"]:
            print("PR #%s %-18s %s (%s authored methods)" % (
                row["pr_number_planned"], row["stage_id"],
                row["static_preflight"],
                row["authored_test_methods_detected"],
            ))
            for finding in row["missing_or_unsafe"]:
                print("  Missing/unsafe:", finding["path"])
            for finding in row["python_syntax_errors"]:
                print("  Python syntax issue:", finding["path"],
                      "line", finding["line"])
            for finding in row["direct_local_import_findings"]:
                print("  Local import issue:", finding)
            print("  Test later:", row["manual_test_command"])
        print("Results:", outcome["summary"],
              "| scientific approval: not checked")
    return 2 if outcome["blocked_stages"] else 0


if __name__ == "__main__":
    sys.exit(main())
