"""P1a raw signed Git-tag identity tests (offline, no source promotion)."""
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.acquire_runc_git_tag import (
    COMMIT_OID, SOURCE_URL, SOURCE_VERSION, TAG_OID, _git, acquire_tag,
    git_tag_oid, inspect_tag_bytes,
)


def fake_raw(commit="b" * 40):
    return (
        f"object {commit}\n"
        "type commit\n"
        "tag v1.1.12\n"
        "tagger Synthetic Reviewer <test@example.org> 1706015622 +1100\n"
        "\n"
        "v1.1.12 sample non-authentic CVE-2024-21626 advisory\n"
        "-----BEGIN PGP SIGNATURE-----\n"
        "fixture-only-not-a-real-signature\n"
        "-----END PGP SIGNATURE-----\n"
    ).encode("utf-8")


def candidate_manifest():
    return {"sources": [{
        "source_version_id": SOURCE_VERSION,
        "source_id": "src:runc-signed-release-tag",
        "status": "candidate",
        "date_confidence": "unknown",
        "sha256": None, "available_at": None,
        "url": SOURCE_URL,
    }]}


class PinnedGitTagTests(unittest.TestCase):
    def test_correct_git_sha1_object_framing_and_sha256_distinction(self):
        raw = fake_raw()
        h = hashlib.sha1(
            b"tag " + str(len(raw)).encode("ascii") + b"\x00" + raw,
            usedforsecurity=False,
        ).hexdigest()
        self.assertEqual(h, git_tag_oid(raw))
        report = inspect_tag_bytes(raw, tag_oid=h, commit_oid="b" * 40)
        self.assertEqual(h, report["pinned_tag_git_sha1"])
        self.assertEqual(hashlib.sha256(raw).hexdigest(), report["raw_tag_bytes_sha256"])
        self.assertNotEqual(h, report["raw_tag_bytes_sha256"])
        for flag in (
            "research_ready",
            "pgp_signature_locally_cryptographically_verified",
            "independent_publication_time_of_exact_tag_verified",
            "source_rights_and_redistribution_approved",
            "tagger_time_is_public_release_time",
        ):
            self.assertFalse(report[flag])

    def test_real_upstream_pins_are_not_fixture_pins(self):
        raw = fake_raw(COMMIT_OID)
        with self.assertRaisesRegex(ValueError, "differs from pinned"):
            inspect_tag_bytes(raw)
        self.assertEqual(40, len(TAG_OID))
        self.assertEqual(40, len(COMMIT_OID))

    def test_changed_tag_contents_fail_with_same_pinned_oid(self):
        raw = fake_raw()
        oid = git_tag_oid(raw)
        tampered = raw.replace(b"sample", b"forged")
        with self.assertRaisesRegex(ValueError, "differs from pinned"):
            inspect_tag_bytes(tampered, tag_oid=oid, commit_oid="b" * 40)

    def test_wrong_tag_target_refused_even_when_object_hash_matches(self):
        raw = fake_raw()
        with self.assertRaisesRegex(ValueError, "expected upstream commit"):
            inspect_tag_bytes(raw, tag_oid=git_tag_oid(raw), commit_oid="c" * 40)

    def test_unsigned_tag_body_refused_even_if_git_hash_matches(self):
        raw = fake_raw().replace(b"-----BEGIN PGP SIGNATURE-----", b"--none--")
        with self.assertRaisesRegex(ValueError, "PGP signature envelope"):
            inspect_tag_bytes(raw, tag_oid=git_tag_oid(raw), commit_oid="b" * 40)

    def test_cve_marker_is_required(self):
        raw = fake_raw().replace(b"CVE-2024-21626", b"CVE-2020-12345")
        with self.assertRaisesRegex(ValueError, "advisory content"):
            inspect_tag_bytes(raw, tag_oid=git_tag_oid(raw), commit_oid="b" * 40)

    def test_empty_and_oversized_raw_tag_rejected(self):
        for raw in (b"", b"x" * (128 * 1024 + 1)):
            with self.subTest(length=len(raw)), self.assertRaisesRegex(
                ValueError, "Invalid or oversized"
            ):
                git_tag_oid(raw)

    def test_local_git_object_round_trip_without_network_or_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "objects.git"
            subprocess.run(
                ["git", "init", "--bare", str(repo)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            raw = fake_raw()
            written = subprocess.run(
                ["git", "-C", str(repo), "hash-object", "-t", "tag", "-w", "--stdin"],
                input=raw, check=True, capture_output=True,
            ).stdout.strip().decode("ascii")
            self.assertEqual(git_tag_oid(raw), written)
            subprocess.run(
                ["git", "-C", str(repo), "update-ref", "refs/tags/v1.1.12", written],
                check=True, capture_output=True,
            )
            self.assertEqual(raw, _git(repo, "cat-file", "tag", written))
            self.assertEqual(b"tag\n", _git(repo, "cat-file", "-t", written))
            # A test fixture must not be accepted as the real pinned upstream tag.
            with self.assertRaisesRegex(ValueError, "ref moved"):
                acquire_tag(candidate_manifest(), repo, Path(temp) / "private")
            self.assertFalse((Path(temp) / "private").exists())

    def test_mismatched_or_approved_registry_source_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp) / "dummy.git"
            repo.mkdir()
            m = candidate_manifest()
            m["sources"][0]["url"] = "https://untrusted.example/changed"
            with self.assertRaisesRegex(ValueError, "absent or changed"):
                acquire_tag(m, repo, Path(temp) / "artifacts")
            m = candidate_manifest()
            m["sources"].append(m["sources"][0].copy())
            with self.assertRaisesRegex(ValueError, "absent or changed"):
                acquire_tag(m, repo, Path(temp) / "artifacts")

    def test_invalid_git_repository_fails_without_approved_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            bogus = Path(temp) / "not-git"
            bogus.mkdir()
            with self.assertRaisesRegex(ValueError, "not readable"):
                acquire_tag(candidate_manifest(), bogus, Path(temp) / "artifacts")
            self.assertFalse((Path(temp) / "artifacts").exists())

    def test_tag_object_is_public_upstream_metadata_not_future_gold_label(self):
        r = candidate_manifest()["sources"][0]
        self.assertEqual("candidate", r["status"])
        self.assertIsNone(r["available_at"])
        self.assertIsNone(r["sha256"])
        self.assertTrue(r["url"].endswith(TAG_OID))


if __name__ == "__main__":
    unittest.main()
