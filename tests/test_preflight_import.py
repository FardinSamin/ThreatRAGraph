"""Standard-library tests for the non-networking intake preflight."""

from pathlib import Path
import tempfile
import unittest

from scripts.preflight_import import filename_flags, inspect_tree


class PreflightTests(unittest.TestCase):
    def test_env_filename_is_flagged_but_example_is_not(self):
        self.assertIn("environment_secret_filename", filename_flags(".env"))
        self.assertIn("environment_secret_filename", filename_flags(".env.local"))
        self.assertEqual([], filename_flags(".env.example"))

    def test_categorizes_token_without_revealing_it(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            fake_token = "AKIA" + "ABCDEFGHIJKLMNOP"
            (root / "config.py").write_text("TOKEN = " + fake_token, encoding="utf-8")
            (root / ".env").write_text(
                "OPENAI_API_KEY=not-a-real-example-secret", encoding="utf-8"
            )
            report = inspect_tree(root)
            self.assertTrue(report["needs_manual_review"])
            self.assertEqual(2, report["files_seen"])
            self.assertTrue(any(
                "aws_access_key_id" in finding["reasons"]
                for finding in report["findings"]
            ))
            self.assertNotIn(fake_token, str(report))
            self.assertNotIn("not-a-real-example-secret", str(report))

    def test_skips_virtualenv_and_flags_sensitive_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".venv").mkdir()
            (root / ".venv" / "skipped.txt").write_text("AKIA" + "ABCDEFGHIJKLMNOP")
            (root / "secrets").mkdir()
            (root / "secrets" / "secret.txt").write_text("not-scanned")
            (root / "main.py").write_text("print('safe')", encoding="utf-8")
            report = inspect_tree(root)
            self.assertEqual(1, report["files_seen"])
            self.assertEqual(1, report["text_files_scanned"])
            self.assertTrue(any(
                "sensitive_directory" in finding["reasons"]
                for finding in report["findings"]
            ))

    def test_file_limit_is_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "a.py").write_text("pass")
            (root / "b.py").write_text("pass")
            report = inspect_tree(root, max_files=1)
            self.assertEqual(1, report["files_seen"])
            self.assertTrue(report["needs_manual_review"])
            self.assertIn(
                "file_limit_reached_not_all_files_checked",
                report["warnings"],
            )

    def test_clean_fixture_reports_no_risks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "README.md").write_text("Safe test", encoding="utf-8")
            (root / "main.py").write_text("x = 1", encoding="utf-8")
            report = inspect_tree(root)
            self.assertFalse(report["needs_manual_review"])
            self.assertEqual(2, report["files_seen"])
            self.assertEqual([], report["findings"])


if __name__ == "__main__":
    unittest.main()
