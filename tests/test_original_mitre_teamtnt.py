"""Original MITRE v12 TeamTNT pinned candidate: adversarial offline integrity tests."""
import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import verify_original_mitre_teamtnt as witness


def _bytes(obj):
    return json.dumps(obj, sort_keys=True, indent=2).encode("utf-8")


def _blob(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + bytes((0,)) + raw,
                        usedforsecurity=False).hexdigest()


class MitreOriginalStixWitnessTests(unittest.TestCase):
    def setUp(self):
        self.valid = {
            "type": "bundle",
            "id": "bundle--fixture",
            "spec_version": "2.0",
            "objects": [{
                "type": "intrusion-set",
                "id": witness.EXPECTED_OBJECT,
                "name": "TeamTNT",
                "modified": "2022-10-19T21:35:03.147Z",
                "x_mitre_version": "1.2",
                "aliases": ["TeamTNT"],
                "external_references": [{
                    "source_name": witness.REFERENCE_NAME_CONFLICT,
                    "description": witness.REFERENCE_DATE
                    + " Retrieved September 22, 2021.",
                    "url": witness.ORIGINAL_REPORT_URL,
                }],
            }],
        }

    def _verified(self, value=None):
        raw = _bytes(self.valid if value is None else value)
        with patch.object(witness, "BLOB", _blob(raw)):
            return witness.verify_original(raw)

    def test_typed_mitre_record_is_not_a_chimaera_source_approval(self):
        out = self._verified()
        self.assertEqual(witness.SCHEMA, out["schema_version"])
        self.assertEqual("intrusion-set", out["original_entity_type"])
        self.assertEqual("TeamTNT", out["original_entity_name"])
        self.assertTrue(out["chimaera_reference_2020_label_conflicts_with_2021_citation"])
        for field in (
            "original_chimaera_report_bytes_present",
            "campaign_chimaera_source_assertions_verified",
            "actor_to_campaign_relabeling_authorized",
            "source_availability_independently_verified",
            "source_rights_approved",
            "source_version_approved",
            "semantic_review_verified", "g1_evaluation_eligible",
            "research_ready",
        ):
            with self.subTest(field=field):
                self.assertFalse(out[field])
        self.assertEqual(0, sum("report body" in str(v) for v in out.values()))

    def test_actual_git_oid_is_pinned_even_if_stix_fields_look_valid(self):
        raw = _bytes(self.valid)
        with self.assertRaisesRegex(ValueError, "Git blob mismatch"):
            witness.verify_original(raw)

    def test_synthetic_blob_pin_detects_single_byte_change(self):
        raw = _bytes(self.valid)
        with patch.object(witness, "BLOB", _blob(raw)):
            witness.verify_original(raw)
            with self.assertRaisesRegex(ValueError, "Git blob mismatch"):
                witness.verify_original(raw + b" ")

    def test_wrong_actor_type_and_campaign_relabeling_refused(self):
        for k, value in (
            ("type", "campaign"), ("name", "Chimaera"),
            ("id", "campaign:Chimaera"), ("modified", "2024-01-01T00:00:00Z"),
            ("x_mitre_version", "future-version"),
        ):
            obj = copy.deepcopy(self.valid)
            obj["objects"][0][k] = value
            with self.subTest(field=k), self.assertRaises(ValueError):
                self._verified(obj)

    def test_missing_or_duplicate_original_chimaera_url_refused(self):
        for refs in (
            [], [self.valid["objects"][0]["external_references"][0]] * 2,
            [dict(self.valid["objects"][0]["external_references"][0],
                  url="https://example.org/malicious/")],
        ):
            obj = copy.deepcopy(self.valid)
            obj["objects"][0]["external_references"] = refs
            with self.subTest(count=len(refs)), self.assertRaises(ValueError):
                self._verified(obj)

    def test_bibliography_2020_2021_conflict_must_be_explicit(self):
        for k, v in (
            ("source_name", "ATT TeamTNT Chimaera September 2021"),
            ("description", "AT&T Alien Labs. (2020, September 8)."),
        ):
            obj = copy.deepcopy(self.valid)
            obj["objects"][0]["external_references"][0][k] = v
            with self.subTest(field=k), self.assertRaisesRegex(ValueError, "discrepancy"):
                self._verified(obj)

    def test_unauthorized_mitre_alias_or_second_object_refused(self):
        obj = copy.deepcopy(self.valid)
        obj["objects"][0]["aliases"] = ["TeamTNT", "Chimaera"]
        with self.assertRaisesRegex(ValueError, "aliases"):
            self._verified(obj)
        obj = copy.deepcopy(self.valid)
        obj["objects"].append(copy.deepcopy(obj["objects"][0]))
        with self.assertRaisesRegex(ValueError, "exactly one"):
            self._verified(obj)

    def test_wrong_stix_bundle_version_and_type_refused(self):
        for k, v in (("spec_version", "2.1"), ("type", "campaign")):
            obj = copy.deepcopy(self.valid)
            obj[k] = v
            with self.assertRaisesRegex(ValueError, "STIX 2.0"):
                self._verified(obj)

    def test_duplicate_json_fields_refused_even_with_recomputed_git_oid(self):
        raw = b'{"type":"bundle","type":"bundle","spec_version":"2.0","objects":[]}'
        with patch.object(witness, "BLOB", _blob(raw)):
            with self.assertRaisesRegex(ValueError, "Duplicate"):
                witness.verify_original(raw)

    def test_unbounded_or_nonbytes_source_refused(self):
        for raw in (b"", b"x" * (witness.LIMIT + 1), "str"):
            with self.subTest(length=len(raw)), self.assertRaises(ValueError):
                witness.verify_original(raw)

    def test_cli_succeeds_synthetically_without_approving(self):
        raw = _bytes(self.valid)
        with TemporaryDirectory() as d:
            p = Path(d) / "source.json"
            p.write_bytes(raw)
            out = io.StringIO()
            with patch.object(witness, "BLOB", _blob(raw)), redirect_stdout(out):
                self.assertEqual(0, witness.main(["--original-file", str(p)]))
            self.assertFalse(json.loads(out.getvalue())["research_ready"])
            p.write_bytes(raw + b"tampered")
            with patch.object(witness, "BLOB", _blob(raw)), redirect_stdout(io.StringIO()) as out:
                self.assertEqual(2, witness.main(["--original-file", str(p)]))
            self.assertEqual("original_mitre_stix_refused", json.loads(out.getvalue())["status"])

    def test_cli_symlink_refused(self):
        raw = _bytes(self.valid)
        with TemporaryDirectory() as d:
            p = Path(d) / "actual.json"
            alias = Path(d) / "alias.json"
            p.write_bytes(raw)
            try:
                alias.symlink_to(p)
            except (OSError, NotImplementedError):
                return
            with redirect_stdout(io.StringIO()):
                self.assertEqual(2, witness.main(["--original-file", str(alias)]))


if __name__ == "__main__":
    unittest.main()
