"""Synthetic, offline tests of GitHub release/tag linkage and no-approval gate."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.verify_runc_release_witness import (
    CUTOFF, RELEASE_API, REF_API, validate_witness, read_api_json,
)


def records():
    sha = "a" * 40
    commit = "b" * 40
    release = {
        "tag_name": "v1.1.12",
        "html_url": "https://github.com/opencontainers/runc/releases/tag/v1.1.12",
        "draft": False, "prerelease": False,
        "created_at": "2024-01-23T13:13:42Z",
        "published_at": "2024-01-31T20:06:08Z",
        "body": "Current mutable text; not a historical byte witness",
    }
    ref = {
        "ref": "refs/tags/v1.1.12",
        "object": {"type": "tag", "sha": sha,
                   "url": "https://api.github.com/repos/opencontainers/runc/git/tags/" + sha},
    }
    signed = f"object {commit}\ntype commit\ntag v1.1.12\n\nCVE-2024-21626 signed test payload"
    tag = {
        "tag": "v1.1.12",
        "tagger": {"date": "2024-01-23T13:13:42Z"},
        "object": {"type": "commit", "sha": commit,
                   "url": "https://api.github.com/repos/opencontainers/runc/git/commits/" + commit},
        "message": "CVE-2024-21626 fix\n-----BEGIN PGP SIGNATURE-----\nfixture",
        "verification": {
            "verified": True, "reason": "valid",
            "verified_at": "2024-11-07T15:42:44Z",
            "payload": signed,
            "signature": "-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----",
        },
    }
    return release, ref, tag


class SignedReleaseWitnessTests(unittest.TestCase):
    def test_valid_but_unapproved_synthetic_release_linkage(self):
        release, ref, tag = records()
        result = validate_witness(release, ref, tag)
        self.assertEqual("runc-release-witness-v1", result["schema_version"])
        self.assertEqual("api_reports_valid", result["github_pgp_status"])
        self.assertEqual("2024-01-31T20:06:08Z", result["public_release_timestamp_observed"])
        self.assertEqual("2024-01-23T13:13:42Z", result["tagger_timestamp_observed"])
        self.assertEqual(RELEASE_API, result["official_release_api"])
        self.assertEqual(REF_API, result["official_tag_reference_api"])
        for key in ("research_ready", "independent_release_date_verified",
                    "raw_git_pgp_signature_reverified_locally",
                    "exact_historical_public_source_bytes_verified",
                    "reuse_rights_verified",
                    "api_payload_digest_is_original_archived_source_sha256"):
            self.assertFalse(result[key], key)
        self.assertIsNone(result["historical_available_at"])

    def test_different_cutoff_blocks_early_release(self):
        release, ref, tag = records()
        with self.assertRaisesRegex(ValueError, "chronology"):
            validate_witness(release, ref, tag, cutoff="2024-01-31T19:00:00Z")
        with self.assertRaisesRegex(ValueError, "calendar|seconds"):
            validate_witness(release, ref, tag, cutoff="2024-02-30T00:00:00Z")

    def test_draft_or_prerelease_is_not_public_final_release(self):
        for key in ("draft", "prerelease"):
            release, ref, tag = records()
            release[key] = True
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "draft/prerelease"):
                validate_witness(release, ref, tag)

    def test_tag_must_be_annotated_and_ref_must_match_its_object(self):
        for field, altered in (
            ("type", "commit"),
            ("url", "https://example.org/tag"),
            ("sha", "0" * 40),
        ):
            release, ref, tag = records()
            ref["object"][field] = altered
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_witness(release, ref, tag)

    def test_invalid_pgp_verification_refused(self):
        for changes in (
            {"verified": False}, {"verified": "true"},
            {"reason": "unknown_key"}, {"signature": "none"},
            {"verified_at": "2024-01-20T00:00:00Z"},
        ):
            release, ref, tag = records()
            tag["verification"].update(changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                validate_witness(release, ref, tag)

    def test_signed_payload_must_bind_tag_commit(self):
        release, ref, tag = records()
        tag["verification"]["payload"] = (
            f"object {'c' * 40}\ntype commit\ntag v1.1.12\n\nCVE-2024-21626 fake"
        )
        with self.assertRaisesRegex(ValueError, "bind target commit"):
            validate_witness(release, ref, tag)

    def test_future_tag_date_refused_even_when_pgp_flag_set(self):
        release, ref, tag = records()
        tag["tagger"]["date"] = "2024-02-02T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "Tagger timestamp follows"):
            validate_witness(release, ref, tag)

    def test_mutable_release_body_does_not_change_tag_witness(self):
        release, ref, tag = records()
        a = validate_witness(release, ref, tag)
        release["body"] = "future attacker payload or updated advisory"
        self.assertEqual(a, validate_witness(release, ref, tag))

    def test_bogus_target_and_malformed_release_datetime_refused(self):
        release, ref, tag = records()
        tag["object"]["type"] = "blob"
        with self.assertRaises(ValueError):
            validate_witness(release, ref, tag)
        release, ref, tag = records()
        release["published_at"] = "2024-01-31"
        with self.assertRaisesRegex(ValueError, "exact UTC seconds"):
            validate_witness(release, ref, tag)

    def test_safe_local_reader_refuses_large_and_symlinked_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "release.json"
            release, _, _ = records()
            path.write_text(json.dumps(release), encoding="utf-8")
            self.assertEqual(release, read_api_json(path))
            path.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "bounded"):
                read_api_json(path)
            path.write_text(json.dumps(release), encoding="utf-8")
            link = Path(tmp) / "link.json"
            try:
                link.symlink_to(path)
            except (OSError, NotImplementedError):
                return
            with self.assertRaisesRegex(ValueError, "non-symlink"):
                read_api_json(link)

    def test_independent_api_copies_cannot_certify_date_or_rights(self):
        release, ref, tag = records()
        future = copy.deepcopy(tag)
        future["verification"]["verified_at"] = "2026-10-10T23:30:00Z"
        outcome = validate_witness(release, ref, future, cutoff=CUTOFF)
        self.assertFalse(outcome["independent_release_date_verified"])
        self.assertFalse(outcome["reuse_rights_verified"])
        self.assertIsNone(outcome["historical_available_at"])


if __name__ == "__main__":
    unittest.main()
