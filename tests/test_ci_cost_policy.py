"""Static CI budget policy checks; these never execute a GitHub workflow."""
from pathlib import Path
import re
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/quality.yml"
HISTORICAL_JOBS = (
    "original-runc-tag-witness",
    "original-ghsa-compound-witness",
    "historical-chimaera-citation-witness",
    "historical-mitre-teamtnt-original",
    "original-2022-kissadog-cado-reference",
    "cado-pointer-public-push-witness",
    "original-2022-campaign-archive-index-probe",
    "original-cado-february-2023-warc-bytes",
)


class WorkflowBudgetPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def test_only_main_pushes_trigger_runs(self):
        m = re.search(r"(?m)^  push:\s*\n    branches: \[([^\]]+)\]",
                      self.workflow)
        self.assertIsNotNone(m)
        self.assertEqual("main", m.group(1).strip())

    def test_prs_keep_security_and_linux_tests(self):
        self.assertIn("  pull_request:\n", self.workflow)
        self.assertIn("  security-and-quality:\n", self.workflow)
        self.assertIn("  preflight-and-tests:\n", self.workflow)
        self.assertIn("'[\"ubuntu-latest\"]'", self.workflow)

    def test_dispatch_inputs_default_false(self):
        self.assertIn("  workflow_dispatch:\n", self.workflow)
        for field in ("run_historical_witnesses", "run_cross_platform"):
            chunk = self.workflow.split("      " + field + ":\n", 1)[1]
            self.assertIn("default: false", chunk.split("\n      ", 1)[0])

    def test_all_eight_external_source_jobs_are_manual(self):
        guard = (
            "    if: " + "$" + "{{ github.event_name == 'workflow_dispatch' "
            "&& inputs.run_historical_witnesses }}\n"
        )
        for name in HISTORICAL_JOBS:
            with self.subTest(name=name):
                self.assertIn("  " + name + ":\n" + guard, self.workflow)

    def test_windows_only_manual_opt_in(self):
        self.assertIn("os: " + "$" + "{{ fromJSON(", self.workflow)
        self.assertIn("inputs.run_cross_platform", self.workflow)
        self.assertIn("'[\"ubuntu-latest\",\"windows-latest\"]'", self.workflow)

    def test_security_gates_remain(self):
        for cmd in (
            "python -m ruff check --select E4,E9,F src scripts tests",
            "python -m scripts.check_secrets",
            "python -m pip_audit -r requirements-normalization.txt",
            "python -m scripts.check_dependency_versions",
            "python -m pip check",
        ):
            with self.subTest(cmd=cmd):
                self.assertIn(cmd, self.workflow)

    def test_unit_suite_stays(self):
        self.assertIn("python -m unittest discover -s tests -v",
                      self.workflow)

    def test_real_source_replay_code_is_not_removed(self):
        for name in (
            "scripts.replay_original_cado_20230206",
            "scripts.verify_original_mitre_teamtnt",
            "scripts.verify_kissadog_cado_public_push",
            "actions/upload-artifact@v4",
        ):
            self.assertIn(name, self.workflow)

    def test_superseded_pr_runs_cancel(self):
        self.assertIn("cancel-in-progress: true", self.workflow)
        self.assertIn("github.event.pull_request.number || github.ref",
                      self.workflow)

    def test_permissions_remain_read_only(self):
        self.assertIn("permissions:\n  contents: read", self.workflow)
        self.assertIn("persist-credentials: false", self.workflow)


if __name__ == "__main__":
    unittest.main()
