"""Research readiness truthfulness contract: fail closed after any structural pass.

These are synthetic assertions of software behavior, not real CTI evaluations.
"""
import unittest

from src.threatragraph.readiness import (
    READINESS_CONTRACT_VERSION,
    readiness_disclosure,
)


class ReadinessDisclosureTests(unittest.TestCase):
    def test_structurally_strict_pass_is_not_empirical_approval(self):
        result = readiness_disclosure(development_only=False)
        self.assertEqual(READINESS_CONTRACT_VERSION,
                         result["readiness_contract_version"])
        self.assertTrue(result["structural_checks_passed"])
        self.assertFalse(result["research_ready"])
        self.assertEqual("strict_structural", result["validation_mode"])
        self.assertEqual("not_verified", result["independent_study_approval"])
        self.assertEqual("not_performed", result["empirical_evaluation"])

    def test_development_is_not_research_ready(self):
        result = readiness_disclosure(development_only=True)
        self.assertEqual("development_only", result["validation_mode"])
        self.assertFalse(result["research_ready"])
        self.assertIn("independent historical", result["reason"])

    def test_no_untrusted_parameters_can_toggle_readiness(self):
        for invalid in ("false", "true", None, 1, 0, [], {}, object()):
            with self.subTest(invalid_type=type(invalid).__name__):
                with self.assertRaises(ValueError):
                    readiness_disclosure(development_only=invalid)

    def test_readiness_disclosure_is_deterministic(self):
        for mode in (True, False):
            self.assertEqual(
                readiness_disclosure(development_only=mode),
                readiness_disclosure(development_only=mode),
            )


if __name__ == "__main__":
    unittest.main()
