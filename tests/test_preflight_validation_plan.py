"""Read-only static preflight tests; no actual experimental test execution."""
import copy
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from scripts.preflight_validation_plan import (
    _local_path, _unique_json_keys, audit_checkout, main,
    validate_plan,
)


def plan():
    return {
        "schema_version": "1.0",
        "artifact_kind": "engineering_validation_plan_v1",
        "stages": [{
            "id": "paired", "scope": "m6", "pr_number": 52,
            "head_branch": "feature/example",
            "base_branch": "main", "requires": [],
            "source_paths": ["src/threatragraph/example.py"],
            "test_paths": ["tests/test_example.py"],
            "min_authored_test_methods": 1,
            "test_command":
                "python -m unittest discover -s tests -p 'test_example.py' -v",
            "manual_gates": ["Run tests only during validation phase"],
        }],
    }


class EngineeringPreflightTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.source = self.root / "src" / "threatragraph" / "example.py"
        self.test = self.root / "tests" / "test_example.py"
        self.source.parent.mkdir(parents=True)
        self.test.parent.mkdir(parents=True)
        self.source.write_text("def run():\n    return 42\n", encoding="utf-8")
        self.test.write_text(
            "from src.threatragraph.example import run\n"
            "class Case:\n"
            "    def test_synthetic(self):\n"
            "        assert run() == 42\n",
            encoding="utf-8",
        )

    def tearDown(self):
        self.temp.cleanup()

    def result(self, candidate=None):
        return audit_checkout(self.root, plan() if candidate is None
                              else candidate)

    def test_static_ready_does_not_claim_test_success(self):
        record = self.result()
        self.assertEqual([], record["blocked_stages"])
        self.assertEqual("ready_for_actual_testing",
                         record["stages"][0]["static_preflight"])
        self.assertEqual(1, record["stages"][0]["authored_test_methods_detected"])
        self.assertEqual(0, record["test_cases_executed"])
        self.assertFalse(record["github_actions_triggered"])
        self.assertFalse(record["actual_ci_outcomes_verified"])
        self.assertFalse(record["research_ready"])

    def test_missing_required_source_reports_blocked(self):
        self.source.unlink()
        entry = self.result()["stages"][0]
        self.assertEqual("blocked", entry["static_preflight"])
        self.assertEqual("src/threatragraph/example.py",
                         entry["missing_or_unsafe"][0]["path"])

    def test_invalid_syntax_is_detected_without_importing_code(self):
        self.source.write_text("def run(:\n  return 42\n", encoding="utf-8")
        entry = self.result()["stages"][0]
        self.assertEqual("blocked", entry["static_preflight"])
        self.assertEqual(1, len(entry["python_syntax_errors"]))

    def test_missing_local_import_symbol_is_detected(self):
        self.test.write_text(
            "from src.threatragraph.example import missing\n"
            "def test_synthetic(): pass\n", encoding="utf-8",
        )
        row = self.result()["stages"][0]
        self.assertEqual("blocked", row["static_preflight"])
        self.assertIn("does not declare missing",
                      " ".join(row["direct_local_import_findings"]))

    def test_missing_local_import_module_is_detected(self):
        self.test.write_text(
            "from src.threatragraph.absent import missing\n"
            "def test_synthetic(): pass\n", encoding="utf-8",
        )
        row = self.result()["stages"][0]
        self.assertEqual("blocked", row["static_preflight"])
        self.assertIn("FileNotFoundError",
                      " ".join(row["direct_local_import_findings"]))

    def test_too_few_authored_test_methods_is_blocked(self):
        candidate = plan()
        candidate["stages"][0]["min_authored_test_methods"] = 2
        row = self.result(candidate)["stages"][0]
        self.assertEqual("blocked", row["static_preflight"])
        self.assertEqual(1, row["authored_test_methods_detected"])

    def test_plan_unknown_keys_forbidden(self):
        candidate = plan()
        candidate["later_reference_labels"] = ["secret"]
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            validate_plan(candidate)

    def test_plan_rejects_duplicate_pr_and_stage(self):
        candidate = plan()
        candidate["stages"].append(copy.deepcopy(candidate["stages"][0]))
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            validate_plan(candidate)

    def test_plan_rejects_forward_dependencies(self):
        candidate = plan()
        candidate["stages"][0]["requires"] = ["future"]
        with self.assertRaisesRegex(ValueError, "dependencies"):
            validate_plan(candidate)

    def test_plan_rejects_wrong_stack_base(self):
        candidate = plan()
        second = copy.deepcopy(candidate["stages"][0])
        second.update(id="evaluation", pr_number=53,
                      head_branch="feature/second",
                      requires=["paired"],
                      base_branch="main")
        candidate["stages"].append(second)
        with self.assertRaisesRegex(ValueError, "Stack base"):
            validate_plan(candidate)

    def test_plan_refuses_escaped_python_paths(self):
        for path in ("../secrets.py", "/etc/passwd.py",
                     "src\\evil.py", "C:/evil.py"):
            with self.subTest(path=path):
                candidate = plan()
                candidate["stages"][0]["source_paths"] = [path]
                with self.assertRaises(ValueError):
                    validate_plan(candidate)

    def test_no_symlink_source_components(self):
        with tempfile.TemporaryDirectory() as other:
            alias = self.root / "linked"
            try:
                alias.symlink_to(Path(other), target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks not available")
            with self.assertRaisesRegex(ValueError, "Symlink"):
                _local_path(self.root, "linked/external.py")

    def test_json_duplicate_plan_fields_are_refused(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            json.loads('{"scope":"m6","scope":"independent"}',
                       object_pairs_hook=_unique_json_keys)

    def test_cli_produces_json_without_running_tests(self):
        (self.root / "docs").mkdir()
        (self.root / "docs" / "ENGINEERING_VALIDATION_PLAN.json").write_text(
            json.dumps(plan()), encoding="utf-8",
        )
        buffer = StringIO()
        with redirect_stdout(buffer):
            code = main(["--repo-root", str(self.root),
                         "--scope", "m6", "--format", "json"])
        self.assertEqual(0, code)
        output = json.loads(buffer.getvalue())
        self.assertEqual(0, output["test_cases_executed"])
        self.assertEqual([], output["blocked_stages"])
        self.assertFalse(output["github_api_accessed"])

    def test_independent_scope_excludes_m6_without_guessing_status(self):
        record = audit_checkout(self.root, plan(), scope="independent")
        self.assertEqual(0, record["stage_count"])
        self.assertEqual([], record["blocked_stages"])


if __name__ == "__main__":
    unittest.main()
