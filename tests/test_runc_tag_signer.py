"""Synthetic and structural safeguards for independent local PGP verification."""
import hashlib
from pathlib import Path
import tempfile
import unittest

from scripts.verify_runc_tag_signer import (
    KEYRING_BLOB_SHA1, PRIMARY_FINGERPRINT, SIGNING_KEY_ID,
    parse_key_blocks, parse_verified_signer, pinned_keyring_blob_sha1,
    verify_release_key,
)


def status(primary=PRIMARY_FINGERPRINT, suffix=SIGNING_KEY_ID):
    signing = "1" * 24 + suffix
    return (
        "[GNUPG:] NEWSIG\n"
        f"[GNUPG:] GOODSIG {suffix} Aleksa Sarai <cyphar@cyphar.com>\n"
        f"[GNUPG:] VALIDSIG {signing} 2024-01-23 1706015622 0 4 0 22 8 00 {primary}\n"
        "[GNUPG:] TRUST_UNDEFINED 0 pgp\n"
    )


class HistoricalSignerTests(unittest.TestCase):
    def test_synthetic_validsig_requires_historical_primary_and_signer(self):
        result = parse_verified_signer(status())
        self.assertTrue(result["pgp_signature_locally_cryptographically_verified"])
        self.assertEqual(PRIMARY_FINGERPRINT, result["historical_key_primary_fingerprint"])
        self.assertEqual(SIGNING_KEY_ID, result["signing_subkey_id"])

    def test_signing_key_change_refused(self):
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            parse_verified_signer(status(suffix="0101010101010101"))

    def test_primary_fingerprint_change_refused(self):
        with self.assertRaisesRegex(ValueError, "identity mismatch"):
            parse_verified_signer(status(primary="A" * 40))

    def test_bad_signature_status_rejected_even_with_good_markers(self):
        for signal in ("BADSIG", "ERRSIG", "NO_PUBKEY", "REVKEYSIG",
                       "EXPSIG", "EXPKEYSIG"):
            with self.subTest(signal=signal), self.assertRaisesRegex(
                ValueError, "Exactly one valid"):
                parse_verified_signer(status() + f"[GNUPG:] {signal} key\n")

    def test_status_missing_good_or_valid_is_rejected(self):
        s = status()
        with self.assertRaisesRegex(ValueError, "Exactly one valid"):
            parse_verified_signer(s.replace("GOODSIG", "NOTE"))
        with self.assertRaisesRegex(ValueError, "Exactly one valid"):
            parse_verified_signer(s.replace("VALIDSIG", "NOTE"))

    def test_duplicate_signature_reports_are_rejected(self):
        s = status()
        with self.assertRaisesRegex(ValueError, "Exactly one valid"):
            parse_verified_signer(s + s)

    def test_signed_status_cannot_be_truncated(self):
        s = status()
        s = s[:s.index("[GNUPG:] VALIDSIG")] + "[GNUPG:] VALIDSIG 0101\n"
        with self.assertRaisesRegex(ValueError, "VALIDSIG must contain"):
            parse_verified_signer(s)

    def test_good_signer_and_valid_signer_must_match(self):
        s = status().replace(
            f"GOODSIG {SIGNING_KEY_ID}",
            "GOODSIG 0101010101010101",
        )
        with self.assertRaisesRegex(ValueError, "GOODSIG"):
            parse_verified_signer(s)

    def test_armored_keyring_without_content_rejected(self):
        for content in (b"", b"some descriptive text", b"X" * (256 * 1024 + 1)):
            with self.subTest(length=len(content)), self.assertRaises(ValueError):
                parse_key_blocks(content)

    def test_armor_extracted_from_historical_project_keyring_description(self):
        sample = (
            b"pub rsa2048 tester\n"
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
            b"fixture-body\n-----END PGP PUBLIC KEY BLOCK-----\n"
        )
        self.assertTrue(parse_key_blocks(sample).startswith(b"-----BEGIN PGP"))

    def test_git_blob_identity_over_exact_raw_keyring_bytes(self):
        raw = b"historical armored bytes"
        expected = hashlib.sha1(
            b"blob " + str(len(raw)).encode() + b"\x00" + raw,
            usedforsecurity=False,
        ).hexdigest()
        self.assertEqual(expected, pinned_keyring_blob_sha1(raw))
        self.assertNotEqual(expected, KEYRING_BLOB_SHA1)

    def test_no_global_gpg_keyring_or_network_fetch_on_missing_repo(self):
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder) / "not-a-git-repo"
            repo.mkdir()
            with self.assertRaisesRegex(ValueError, "not readable"):
                verify_release_key(repo)

    def test_pinned_keyring_oid_is_exactly_historical_blob(self):
        self.assertEqual(40, len(KEYRING_BLOB_SHA1))
        self.assertEqual(40, len(PRIMARY_FINGERPRINT))
        self.assertEqual(16, len(SIGNING_KEY_ID))


if __name__ == "__main__":
    unittest.main()
