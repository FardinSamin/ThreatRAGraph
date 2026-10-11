"""Synthetic tampering tests; no public source bodies or network access."""
import copy
import gzip
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import verify_advisory_public_witness as witness


def event():
    return {"id": "35293494004", "type": "PushEvent", "public": True,
            "created_at": witness.EVENT_TIME,
            "repo": {"name": "github/advisory-database", "id": 458364565},
            "payload": {"head": witness.COMMIT, "ref": "refs/heads/main",
                        "commits": [{"sha": witness.COMMIT}]}}


class AdvisoryPublicWitnessTests(unittest.TestCase):
    def test_wrong_event_repository_commit_and_visibility_refused(self):
        for field, value in [("id", "other"), ("type", "CreateEvent"), ("public", False),
                             ("created_at", "2024-01-30T00:00:00Z"), ("repo", {}),
                             ("payload", []), ("public", "true")]:
            changed = event()
            changed[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                witness.verify_event(changed, "2024-02-01T00:00:00Z")
        for field, value in [("head", "0" * 40), ("ref", "refs/heads/other"),
                             ("commits", []), ("commits", [None])]:
            changed = event()
            changed["payload"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                witness.verify_event(changed, "2024-02-01T00:00:00Z")
        changed = event()
        changed["repo"]["name"] = "attacker/advisory-database"
        with self.assertRaises(ValueError):
            witness.verify_event(changed, "2024-02-01T00:00:00Z")

    def test_cutoff_must_be_after_public_event_and_explicit_utc(self):
        witness.verify_event(event(), "2024-02-01T00:00:00Z")
        for cutoff in [witness.EVENT_TIME, "2024-01-31T22:46:09Z", "2024-02-01",
                       "2024-02-01T00:00:00", "2024-02-31T00:00:00Z", None]:
            with self.subTest(cutoff=cutoff), self.assertRaises(ValueError):
                witness.verify_event(event(), cutoff)

    def test_archive_and_exact_line_hashes_are_both_required(self):
        raw = json.dumps(event()).encode() + b"\n"
        compressed = gzip.compress(raw, mtime=0)
        archive_sha = hashlib.sha256(compressed).hexdigest()
        line_sha = hashlib.sha256(raw).hexdigest()
        with TemporaryDirectory() as directory:
            path = Path(directory) / "hour.json.gz"
            path.write_bytes(compressed)
            self.assertEqual(event(), witness.read_event(path, archive_sha, 1, line_sha))
            for digest, line, expected in [("0" * 64, 1, line_sha),
                                           (archive_sha, 1, "0" * 64),
                                           (archive_sha, 2, line_sha),
                                           (archive_sha, 0, line_sha)]:
                with self.subTest(line=line, digest=digest), self.assertRaises(ValueError):
                    witness.read_event(path, digest, line, expected)
            path.write_bytes(compressed + b"modified")
            with self.assertRaises(ValueError):
                witness.read_event(path, archive_sha, 1, line_sha)

    def test_tree_path_binds_blob_and_refuses_symlinks_or_duplicates(self):
        root_id, blob_id = "a" * 40, "b" * 40
        entry = b"100644 advisory.json\0" + bytes.fromhex(blob_id)
        objects = {("commit", "c" * 40): f"tree {root_id}\n\nfixture\n".encode(),
                   ("tree", root_id): entry, ("blob", blob_id): b"fixture"}
        def read(kind, oid):
            return objects[kind, oid]
        raw, count = witness.verify_file_chain(read, "c" * 40, "advisory.json", blob_id)
        self.assertEqual((b"fixture", 3), (raw, count))
        for tree in [entry.replace(b"100644", b"120000"), entry + entry, entry[:-1],
                     entry.replace(b"advisory.json", b"different.json")]:
            objects["tree", root_id] = tree
            with self.subTest(tree=tree), self.assertRaises(ValueError):
                witness.verify_file_chain(read, "c" * 40, "advisory.json", blob_id)

    def test_missing_parent_and_wrong_blob_are_refused(self):
        root_id, blob_id = "a" * 40, "b" * 40
        def read(kind, oid):
            if kind == "commit":
                return f"tree {root_id}\n\nfixture\n".encode()
            return b"100644 dir\0" + bytes.fromhex(blob_id)
        with self.assertRaises(ValueError):
            witness.verify_file_chain(read, "c" * 40, "dir/file", blob_id)
        with self.assertRaises(ValueError):
            witness.verify_file_chain(read, "c" * 40, "dir", "d" * 40)

    def test_success_remains_unapproved_and_wrong_date_stops_git_reads(self):
        raw = b"x" * 13105
        with patch.object(witness, "read_event", return_value=copy.deepcopy(event())), \
             patch.object(witness, "verify_file_chain", return_value=(raw, 8)) as chain, \
             patch.object(witness, "SOURCE_SHA256", hashlib.sha256(raw).hexdigest()):
            report = witness.verify("unused", "unused")
            for key in ["research_ready", "source_approved", "rights_review_approved",
                        "first_ever_publication_proven", "cryptographic_timestamp_verified",
                        "exact_signed_tag_publication_proven"]:
                self.assertIs(False, report[key])
            chain.reset_mock()
            with self.assertRaises(ValueError):
                witness.verify("unused", "unused", "2024-01-01T00:00:00Z")
            chain.assert_not_called()


if __name__ == "__main__":
    unittest.main()
