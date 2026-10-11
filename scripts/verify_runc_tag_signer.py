#!/usr/bin/env python3
"""Verify original runc v1.1.12 Git tag against pinned historical runc.keyring.

Requires an already-fetched local Git repository. Uses a fresh temporary
GnuPG home. No network requests or global trust database. Success certifies
local signature validity with the key in the exact 2024 upstream keyring;
it cannot certify independent owner identity, public date or archive rights.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory

from scripts.acquire_runc_git_tag import (
    COMMIT_OID, TAG, TAG_OID, _git, inspect_tag_bytes,
)

# This is the Git blob identity returned by upstream at pinned v1.1.12.
KEYRING_BLOB_SHA1 = "".join((
    "3fb6d283", "636d0aef", "455301c6", "963815fc", "8ceed59a",
))
# Aleksa Sarai primary key published in the historical release keyring.
PRIMARY_FINGERPRINT = "".join((
    "C9C370B2", "46B09F6D", "BCFC744C", "34401015", "D1D2D386",
))
# Signing subkey ID also reported on the official public release page.
SIGNING_KEY_ID = "".join(("2897FAD2", "B7E9446F"))
MAX_KEYRING_BYTES = 256 * 1024
BLOCK_PATTERN = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----.*?-----END PGP PUBLIC KEY BLOCK-----",
    re.DOTALL,
)


def parse_key_blocks(keyring: bytes) -> bytes:
    if not isinstance(keyring, bytes) or not 0 < len(keyring) <= MAX_KEYRING_BYTES:
        raise ValueError("Missing or oversized historical release keyring")
    try:
        decoded = keyring.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Release keyring is not UTF-8") from exc
    found = BLOCK_PATTERN.findall(decoded)
    if not found or any(len(block) > MAX_KEYRING_BYTES // 2 for block in found):
        raise ValueError("No bounded OpenPGP public key blocks in historical keyring")
    return ("\n".join(found) + "\n").encode("utf-8")


def pinned_keyring_blob_sha1(keyring: bytes) -> str:
    if not isinstance(keyring, bytes) or not 0 < len(keyring) <= MAX_KEYRING_BYTES:
        raise ValueError("Invalid historical keyring bytes")
    return hashlib.sha1(
        b"blob " + str(len(keyring)).encode("ascii") + b"\x00" + keyring,
        usedforsecurity=False,
    ).hexdigest()


def parse_verified_signer(status_text: str) -> dict:
    """Require one valid upstream-tag GPG signature with the pinned signer."""
    if not isinstance(status_text, str):
        raise ValueError("Signature verification status missing")
    raw = []
    for line in status_text.splitlines():
        if line.startswith("[GNUPG:] "):
            raw.append(line[len("[GNUPG:] "):].split())
    good = [parts for parts in raw if parts and parts[0] == "GOODSIG"]
    valid = [parts for parts in raw if parts and parts[0] == "VALIDSIG"]
    failures = {"BADSIG", "ERRSIG", "REVKEYSIG", "EXPSIG", "EXPKEYSIG", "NO_PUBKEY"}
    if (len(good) != 1 or len(valid) != 1
            or any(parts and parts[0] in failures for parts in raw)):
        raise ValueError("Exactly one valid and good tag signature required")
    v = valid[0]
    if len(v) < 11:
        raise ValueError("VALIDSIG missing signing and primary fingerprints")
    signer_fpr = v[1].upper()
    primary = v[10].upper()
    if (not signer_fpr.endswith(SIGNING_KEY_ID)
            or primary != PRIMARY_FINGERPRINT):
        raise ValueError("Signing subkey or release-era primary identity mismatch")
    if len(good[0]) < 2 or not good[0][1].upper().endswith(SIGNING_KEY_ID):
        raise ValueError("GOODSIG does not match pinned signing subkey")
    return {
        "historical_key_primary_fingerprint": primary,
        "signing_subkey_id": SIGNING_KEY_ID,
        "signature_status": "GOODSIG_and_VALIDSIG",
        "pgp_signature_locally_cryptographically_verified": True,
    }


def _run(args: list[str], *, env: dict, data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            args, input=data, capture_output=True, check=True, timeout=20, env=env
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ValueError("Isolated GPG import/verify command failed") from exc
    if len(result.stdout) > MAX_KEYRING_BYTES or len(result.stderr) > MAX_KEYRING_BYTES:
        raise ValueError("Unbounded GPG output refused")
    return result.stdout + b"\n" + result.stderr


def verify_release_key(
    repository_path: str | Path, *, expected_blob_sha1: str = KEYRING_BLOB_SHA1
) -> dict:
    repo = Path(repository_path)
    ref = _git(repo, "show-ref", "--hash", "--verify", f"refs/tags/{TAG}")
    if ref.strip().decode("ascii") != TAG_OID:
        raise ValueError("Signed tag ref moved from pinned original")
    raw_tag = _git(repo, "cat-file", "tag", TAG_OID)
    tag_report = inspect_tag_bytes(raw_tag)
    historic = _git(repo, "show", f"{COMMIT_OID}:runc.keyring")
    blob_oid = pinned_keyring_blob_sha1(historic)
    if blob_oid != expected_blob_sha1:
        raise ValueError("Historical keyring does not match pinned release blob")
    armored = parse_key_blocks(historic)
    with TemporaryDirectory() as tmp:
        home = Path(tmp) / "gnupg"
        home.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(home), "GIT_TERMINAL_PROMPT": "0"}
        _run(["gpg", "--batch", "--no-tty", "--import"], env=env, data=armored)
        output = _run(["git", "-C", str(repo), "verify-tag", "--raw", TAG_OID], env=env)
        signer = parse_verified_signer(output.decode("utf-8", errors="replace"))
    return {
        **signer,
        "schema_version": "runc-release-era-signer-v1",
        "tag_name": TAG,
        "tag_raw_sha256": tag_report["raw_tag_bytes_sha256"],
        "tag_raw_byte_count": tag_report["raw_tag_byte_count"],
        "keyring_origin": "runc v1.1.12 pinned commit runc.keyring",
        "keyring_git_blob_sha1": blob_oid,
        "keyring_sha256": hashlib.sha256(historic).hexdigest(),
        "keyring_original_bytes_verified": True,
        "signer_present_in_2024_project_release_keyring": True,
        "independent_out_of_band_real_world_key_owner_identity_verified": False,
        "independent_exact_tag_first_publication_time_verified": False,
        "source_specific_rights_or_human_cutoff_approved": False,
        "research_ready": False,
        "warning": (
            "Locally valid cryptographic PGP signature with release-era project "
            "keyring; signer ownership out-of-band, historical first-public "
            "availability, rights, reviewer and real-case approval are not established."
        ),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-repo", required=True, help="Already-fetched pinned runc Git objects")
    args = parser.parse_args(argv)
    try:
        report = verify_release_key(args.git_repo)
    except (ValueError, OSError, UnicodeError) as exc:
        print(json.dumps({"status": "signer_refused", "reason": str(exc)}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
