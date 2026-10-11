"""Offline tests for original pinned GHSA replay; no real-source bytes in Git."""
from contextlib import redirect_stdout
import copy
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts import replay_original_ghsa_candidate as replay


def symbolic_report():
    """Synthetic shape check ONLY; does not pass source-byte authentication."""
    return {
        "original_ghsa_id": replay.ORIGINAL_GHSA,
        "cve_target_id": replay.ORIGINAL_TARGET,
        "candidates": [{
            "subject_id": replay.ORIGINAL_TARGET,
            "predicate": "AFFECTS",
            "object_id": replay.ORIGINAL_PACKAGE,
            "candidate_id": "candidate:" + "a" * 64,
        }],
    }


def symbolic_packet():
    return {
        "source_version_id": replay.SOURCE_VERSION,
        "source_sha256": replay.SOURCE_SHA256,
        "candidate_id": "candidate:" + "a" * 64,
        "field_evidence": [
            {"evidence_locator": {"kind": "json_pointer", "path": "/aliases/0"}},
            {"evidence_locator": {"kind": "json_pointer",
                                  "path": "/affected/0/package/name"}},
        ],
    }


class OriginalGHSAReplayTests(unittest.TestCase):
    def test_source_specific_association_shape_can_be_audited(self):
        replay.check_expected_association(symbolic_report(), symbolic_packet())

    def test_wrong_subject_predicate_object_or_candidate_fails(self):
        for key, value in [
            ("subject_id", "malware:fake"),
            ("predicate", "USES"),
            ("object_id", "software-product:go/github.com/other/pkg"),
            ("candidate_id", "candidate:" + "b" * 64),
        ]:
            report = symbolic_report()
            report["candidates"][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                replay.check_expected_association(report, symbolic_packet())

    def test_wrong_source_identity_and_changed_paths_fail(self):
        for key, value in [
            ("source_version_id", "candidate:wrong"),
            ("source_sha256", "0" * 64),
            ("candidate_id", "candidate:" + "0" * 64),
            ("field_evidence", []),
        ]:
            pkt = symbolic_packet()
            pkt[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                replay.check_expected_association(symbolic_report(), pkt)

    def test_missing_or_surplus_candidate_refused(self):
        for records in [[], symbolic_report()["candidates"] * 2]:
            report = symbolic_report()
            report["candidates"] = records
            with self.subTest(count=len(records)), self.assertRaises(ValueError):
                replay.check_expected_association(report, symbolic_packet())

    def test_prose_only_forged_or_mutated_original_bytes_fail_pin(self):
        obj = {
            "schema_version": "1.4.0",
            "id": replay.ORIGINAL_GHSA,
            "aliases": ["CVE-2024-21626"],
            "affected": [{"package": {
                "ecosystem": "Go", "name": "github.com/opencontainers/runc",
            }}],
            "details": "Invented modern description is not historic source bytes",
        }
        raw = json.dumps(obj).encode("utf-8")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            replay.replay_original(raw)
        changed = copy.deepcopy(obj)
        changed["details"] = "Added after the cutoff"
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            replay.replay_original(json.dumps(changed).encode("utf-8"))

    def test_malformed_and_missing_source_fail_cli(self):
        with TemporaryDirectory() as temp:
            path = Path(temp) / "fake-original-ghsa.json"
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(2, replay.main(["--input-file", str(path)]))
            self.assertFalse(json.loads(out.getvalue())["research_ready"])
            path.write_bytes(b'{"not": "historical"}')
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(2, replay.main(["--input-file", str(path)]))
            self.assertEqual("original_ghsa_replay_refused",
                             json.loads(out.getvalue())["status"])

    def test_symlink_source_refused_if_available(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "raw.json"
            link = root / "link.json"
            target.write_bytes(b"{}")
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink not available")
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(2, replay.main(["--input-file", str(link)]))


if __name__ == "__main__":
    unittest.main()
