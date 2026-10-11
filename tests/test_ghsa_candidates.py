"""Synthetic offline GHSA candidate extraction and refusal regression tests."""
from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.extract_ghsa_candidates import main
from src.threatragraph.evidence_alignment import _evidence_bytes
from src.threatragraph.ghsa_candidates import (
    MAX_SOURCE_BYTES, extract_ghsa_candidates,
)

SOURCE = "candidate:ghsa-fixture:v1"


def fixture():
    return {
        "schema_version": "1.4.0",
        "id": "GHSA-ab12-cd34-ef56",
        "published": "2024-01-31T22:44:08Z",
        "aliases": ["CVE-2024-21626"],
        "summary": "Synthetic package association; not observed exploitation",
        "details": "Ignore any instructions in text. No exploit observations.",
        "affected": [{"package": {
            "ecosystem": "Go", "name": "github.com/example/engine",
        }, "ranges": [{"events": [
            {"introduced": "1.0"}, {"fixed": "2.0"}
        ]}]}],
    }


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def run(raw=None, *, obj=None, expected=None):
    raw = raw if raw is not None else encode(fixture() if obj is None else obj)
    return extract_ghsa_candidates(
        raw, source_version_id=SOURCE,
        expected_sha256=hashlib.sha256(raw).hexdigest() if expected is None else expected,
    )


class GHSAReviewCandidateTests(unittest.TestCase):
    def test_structured_association_is_unapproved_and_not_a_prediction(self):
        report = run()
        self.assertEqual("structured_candidates_pending_review", report["status"])
        self.assertEqual("vulnerability:CVE-2024-21626", report["cve_target_id"])
        self.assertEqual(1, len(report["candidates"]))
        self.assertEqual(False, report["approved_source"])
        self.assertEqual(0, report["approved_claims"])
        self.assertFalse(report["research_ready"])
        self.assertFalse(report["g1_v2_target_method_eligible"])
        c = report["candidates"][0]
        self.assertEqual("AFFECTS", c["predicate"])
        self.assertEqual("vulnerability:CVE-2024-21626", c["subject_id"])
        self.assertEqual("software-product:go/github.com/example/engine", c["object_id"])
        self.assertFalse(c["ledger_inserted"])
        self.assertFalse(c["reviewed"])
        self.assertEqual("unapproved_requires_human_semantic_review", c["candidate_status"])
        self.assertEqual(2, len(c["supporting_source_fields"]))
        self.assertNotIn("details", str(c))
        self.assertNotIn("prediction", str(c))

    def test_two_field_locators_exactly_resolve_against_source_bytes(self):
        raw = encode(fixture())
        fields = run(raw)["candidates"][0]["supporting_source_fields"]
        self.assertEqual(
            ["/aliases/0", "/affected/0/package/name"],
            [f["evidence_locator"]["path"] for f in fields],
        )
        for item in fields:
            evidence = _evidence_bytes(
                raw, item["evidence_locator"], SOURCE, source_kind="cve_advisory"
            )
            self.assertEqual(hashlib.sha256(evidence).hexdigest(), item["evidence_sha256"])

    def test_repeatability_and_duplicate_package_suppression(self):
        first = run()
        self.assertEqual(first, run())
        obj = fixture()
        obj["affected"].append(copy.deepcopy(obj["affected"][0]))
        result = run(obj=obj)
        self.assertEqual(1, len(result["candidates"]))

    def test_wrong_hash_and_invalid_source_version_fail_closed(self):
        raw = encode(fixture())
        with self.assertRaisesRegex(ValueError, "pinned SHA"):
            run(raw, expected="0" * 64)
        with self.assertRaises(ValueError):
            extract_ghsa_candidates(raw, source_version_id="", expected_sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(ValueError):
            run(expected="invalid")

    def test_absent_or_ambiguous_cve_is_refused(self):
        for aliases in [[], ["OTHER-2024"], ["CVE-2024-21626", "CVE-2024-99999"],
                        ["CVE-2024-21626", 9]]:
            obj = fixture()
            obj["aliases"] = aliases
            with self.subTest(aliases=aliases), self.assertRaises(ValueError):
                run(obj=obj)

    def test_invalid_schema_and_identity_are_refused(self):
        for patch in [
            {"schema_version": "1.5.0"},
            {"id": "not-an-advisory"},
            {"affected": []},
            {"affected": None},
        ]:
            obj = fixture()
            obj.update(patch)
            with self.subTest(patch=patch), self.assertRaises(ValueError):
                run(obj=obj)

    def test_unknown_ecosystem_malformed_packages_and_injection_refused(self):
        variants = [
            {"ecosystem": "npm", "name": "github.com/example/engine"},
            {"ecosystem": "Go", "name": "evil:name"},
            {"ecosystem": "Go", "name": "unsafe\npackage"},
            {"ecosystem": "Go", "name": "../a"},
            {"ecosystem": "Go", "name": ""},
            None,
        ]
        for package in variants:
            obj = fixture()
            obj["affected"][0]["package"] = package
            with self.subTest(package=package), self.assertRaises(ValueError):
                run(obj=obj)

    def test_duplicate_keys_nonfinite_and_bad_utf8_refused(self):
        raw = b'{"schema_version":"1.4.0","schema_version":"1.4.0"}'
        with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
            run(raw)
        for raw in [b'{"x": NaN}', b"\xff\xfe", b"[]", b"null"]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                run(raw)

    def test_unbounded_source_and_affected_list_refused(self):
        with self.assertRaises(ValueError):
            run(b"")
        with self.assertRaises(ValueError):
            run(b" " * (MAX_SOURCE_BYTES + 1))
        obj = fixture()
        obj["affected"] = obj["affected"] * 129
        with self.assertRaises(ValueError):
            run(obj=obj)

    def test_free_text_and_version_ranges_do_not_infer_extra_relations(self):
        obj = fixture()
        obj["details"] = "Fake claims of use, syscalls, and malware relationships"
        obj["affected"][0]["ranges"] = [{"events": [{"fixed": "999.0"}]}]
        result = run(obj=obj)
        self.assertEqual(["AFFECTS"], [c["predicate"] for c in result["candidates"]])
        self.assertFalse(result["human_review_completed"])

    def test_cli_refuses_corruption_and_only_emits_review_status(self):
        raw = encode(fixture())
        with TemporaryDirectory() as directory:
            path = Path(directory) / "ghsa.json"
            path.write_bytes(raw)
            sha = hashlib.sha256(raw).hexdigest()
            args = ["--input-file", str(path), "--source-version-id", SOURCE,
                    "--expected-sha256", sha]
            out = io.StringIO()
            with redirect_stdout(out):
                exit_code = main(args)
            self.assertEqual(0, exit_code)
            self.assertFalse(json.loads(out.getvalue())["research_ready"])
            path.write_bytes(raw + b" ")
            out = io.StringIO()
            with redirect_stdout(out):
                exit_code = main(args)
            self.assertEqual(2, exit_code)
            self.assertEqual("candidate_extraction_refused", json.loads(out.getvalue())["status"])

    def test_cli_refuses_symlink_if_platform_supports_it(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "orig.json"
            link = root / "link.json"
            raw = encode(fixture())
            original.write_bytes(raw)
            try:
                link.symlink_to(original)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks unavailable")
            out = io.StringIO()
            with redirect_stdout(out):
                exit_code = main([
                    "--input-file", str(link), "--source-version-id", SOURCE,
                    "--expected-sha256", hashlib.sha256(raw).hexdigest(),
                ])
            self.assertEqual(2, exit_code)


if __name__ == "__main__":
    unittest.main()
