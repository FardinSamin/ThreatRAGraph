"""Synthetic adversarial replay of actual pinned Securonix 2022 Cado pointer."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import verify_kissadog_cado_pointer as witness


def _oid(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + bytes((0,)) + raw,
                        usedforsecurity=False).hexdigest()


class Original2022CadoPointerTests(unittest.TestCase):
    def setUp(self):
        self.ref = witness.CANONICAL_OLD_CADO_URL.encode("utf-8")
        self.iocs = (
            "\n## IOCs\n__hash__:\n\n```text\n"
            + "\n".join(chr(ord("1") + i) * 64 for i in range(7))
            + "\n```\n__url__:\n\n```text\n"
            + "http://kiss.a-dog.top/b2f628/m/xm.jpg\n```\n"
        ).encode()

    def _verified(self, ref=None, iocs=None):
        ref = self.ref if ref is None else ref
        iocs = self.iocs if iocs is None else iocs
        with patch.object(witness, "REFERENCE_GIT_BLOB", _oid(ref)), patch.object(
            witness, "IOC_GIT_BLOB", _oid(iocs)
        ):
            return witness.verify_reference(ref, iocs)

    def test_exact_pointer_receipt_rejects_primary_article_or_independence_claim(self):
        out = self._verified()
        self.assertEqual(witness.VERSION, out["schema_version"])
        self.assertEqual(7, out["derived_ioc_count"])
        self.assertEqual(hashlib.sha256(self.ref).hexdigest(), out["reference_sha256"])
        for field in (
            "original_cado_report_body_present", "original_cado_report_public_time_verified",
            "publisher_source_rights_approved", "original_cado_source_version_approved",
            "securonix_independent_honeypot_investigation_verified",
            "g1_two_independent_claim_groups_verified", "research_ready",
        ):
            self.assertFalse(out[field])

    def test_public_git_blob_integrity_mandatory(self):
        with self.assertRaisesRegex(ValueError, "differs"):
            witness.verify_reference(self.ref, self.iocs)
        with patch.object(witness, "REFERENCE_GIT_BLOB", _oid(self.ref)), patch.object(
            witness, "IOC_GIT_BLOB", _oid(self.iocs)
        ):
            with self.assertRaisesRegex(ValueError, "differs"):
                witness.verify_reference(self.ref + b"x", self.iocs)

    def test_modified_reference_fails_even_if_new_blob_hash_is_valid(self):
        altered = self.ref.replace(b"cadosecurity", b"crowdstrike")
        with self.assertRaisesRegex(ValueError, "original Cado"):
            self._verified(ref=altered)

    def test_duplicate_reference_and_extra_injected_data_rejected(self):
        for changed in (
            self.ref + self.ref,
            self.ref + b"\nmalicious appended text",
            b"https://www.cadosecurity.com/blog/other",
        ):
            with self.subTest(size=len(changed)), self.assertRaisesRegex(
                ValueError, "original Cado"
            ):
                self._verified(ref=changed)

    def test_ioc_index_requires_distinct_exact_seven_sha256_hashes(self):
        for bad in (
            self.iocs.replace(b"7" * 64, b"1" * 64),
            self.iocs.replace(b"7" * 64, b"z" * 64),
            self.iocs + b"\n" + b"8" * 64,
        ):
            with self.subTest(length=len(bad)), self.assertRaisesRegex(ValueError, "hashes"):
                self._verified(iocs=bad)

    def test_corrupted_ioc_root_cue_refused(self):
        altered = self.iocs.replace(b"kiss.a-dog.top", b"example.comxxx")
        with self.assertRaisesRegex(ValueError, "IOC cue"):
            self._verified(iocs=altered)

    def test_non_utf8_or_oversize_rejected_even_with_modified_pin(self):
        for bad in (self.ref + b"\xff", b"x" * (witness.MAX_BYTES + 1)):
            with self.subTest(len=len(bad)), self.assertRaises(ValueError):
                self._verified(ref=bad)
        with self.assertRaises(ValueError):
            witness.verify_reference("not raw bytes", self.iocs)

    def test_cli_receipt_and_tamper_refusal(self):
        with TemporaryDirectory() as d:
            ref = Path(d) / "References.txt"
            iocs = Path(d) / "README.md"
            ref.write_bytes(self.ref)
            iocs.write_bytes(self.iocs)
            args = ["--reference-file", str(ref), "--ioc-file", str(iocs)]
            with patch.object(witness, "REFERENCE_GIT_BLOB", _oid(self.ref)), patch.object(
                witness, "IOC_GIT_BLOB", _oid(self.iocs)
            ), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(0, witness.main(args))
            self.assertFalse(json.loads(out.getvalue())["research_ready"])
            ref.write_bytes(self.ref + b"tampered")
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(2, witness.main(args))
            self.assertEqual("historical_kissadog_reference_refused",
                             json.loads(out.getvalue())["status"])

    def test_symlink_to_external_material_refused(self):
        with TemporaryDirectory() as d:
            ref = Path(d) / "actual.txt"
            alias = Path(d) / "link.txt"
            iocs = Path(d) / "README.md"
            ref.write_bytes(self.ref)
            iocs.write_bytes(self.iocs)
            try:
                alias.symlink_to(ref)
            except (NotImplementedError, OSError):
                return
            with redirect_stdout(io.StringIO()):
                self.assertEqual(2, witness.main([
                    "--reference-file", str(alias), "--ioc-file", str(iocs),
                ]))

    def test_public_historical_pointer_ids_are_fixed(self):
        self.assertEqual(40, len(witness.COMMIT))
        self.assertEqual(40, len(witness.REFERENCE_GIT_BLOB))
        self.assertEqual(40, len(witness.IOC_GIT_BLOB))
        self.assertEqual("2022-12-23T11:42:26Z",
                         self._verified()["git_declared_committer_time_unverified_as_public_by"])


if __name__ == "__main__":
    unittest.main()
