"""Offline tests of P0's exact pin and secret-scan result contracts."""
from importlib import metadata
import json
import unittest

from scripts.check_dependency_versions import parse_requirements, check_installed
from scripts.check_secrets import summarize_findings


class RuntimeDependencyContractTests(unittest.TestCase):
    def test_accepts_only_versioned_requirements(self):
        data = parse_requirements("PyYAML==6.0.3  # parser\npypdf==6.20.0\n")
        self.assertEqual({"pyyaml": "6.0.3", "pypdf": "6.20.0"}, data)

    def test_missing_or_uncertain_or_duplicate_pins_refused(self):
        invalid = (
            "",
            "pypdf>=6\n",
            "pypdf\n",
            "pypdf==6.0\nPYPDF==7.0\n",
            "https://example.org/code.whl\n",
            "pypdf @ https://example.org/code.whl\n",
            "-e .\n",
            "pypdf==6.0; python_version>='3.12'\n",
        )
        for text in invalid:
            with self.subTest(text=text), self.assertRaises(ValueError):
                parse_requirements(text)

    def test_missing_or_downgraded_installed_parser_refused(self):
        expected = {"pypdf": "6.20.0"}
        check_installed(expected, installed_version=lambda _: "6.20.0")
        with self.assertRaisesRegex(ValueError, "version mismatch"):
            check_installed(expected, installed_version=lambda _: "6.0.0")
        def missing(_):
            raise metadata.PackageNotFoundError("pypdf")
        with self.assertRaisesRegex(ValueError, "Missing"):
            check_installed(expected, installed_version=missing)


class SecretReportContractTests(unittest.TestCase):
    def test_empty_report_accepted(self):
        self.assertEqual((0, 0), summarize_findings(json.dumps({"results": {}})))

    def test_real_finding_summary_does_not_expose_value(self):
        report = {"results": {"private/file.py": [
            {"type": "Secret Keyword", "line_number": 4, "is_secret": False}
        ]}}
        self.assertEqual((1, 1), summarize_findings(json.dumps(report)))

    def test_bad_or_missing_scanner_report_refused(self):
        for data in ("", "not-json", "{}", '{"results": []}', '{"results": {"x": null}}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                summarize_findings(data)


if __name__ == "__main__":
    unittest.main()
