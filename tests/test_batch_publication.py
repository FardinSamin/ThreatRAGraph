"""Synthetic-only batch publication/recovery tests; authored, not executed."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.freeze_case_snapshots import snapshot_sha256, write_immutable_view
from scripts.run_offline_case_batch import ARTIFACT_NAMES, _receipt
from scripts.check_batch_completion import main as completion_cli
from src.threatragraph.batch_publication import (
    check_batch_completion, publish_batch,
)

# The existing frozen-run synthetic fixture exercises the REAL deterministic
# B0/G1 builders. No research data or held-out labels are loaded here.
from test_batch_replay import sample_outputs, reseal_case_links


def built_for(case_ids=("case-a", "case-b")):
    cases = [sample_outputs(case) for case in case_ids]
    plan = {
        "dataset_id": "synthetic", "dataset_version": "v1",
        "cases": [{"case_id": cid} for cid in case_ids],
    }
    return {"case_results": cases, "batch_receipt": _receipt(cases, plan)}


class BatchPublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "output"
        self.built = built_for()
        self.digest = snapshot_sha256(self.built["batch_receipt"])
        self.receipt = self.root / (self.digest + ".json")

    def tearDown(self):
        self.tmp.cleanup()

    def test_published_two_case_receipt_replays_from_disk(self):
        result = publish_batch(self.built, self.root)
        self.assertTrue(result["receipt_published"])
        self.assertTrue(result["stored_leaf_replay_verified"])
        self.assertEqual(self.digest, result["batch_receipt"]["sha256"])
        self.assertTrue(self.receipt.is_file())
        self.assertEqual(21, len(list(self.root.glob("*.json"))))
        report = check_batch_completion(self.root, self.digest)
        self.assertEqual("sealed_unscored_batch_verified", report["status"])
        self.assertTrue(report["full_artifact_integrity_verified"])
        self.assertFalse(report["research_ready"])

    def test_missing_output_root_is_uncommitted_not_complete(self):
        report = check_batch_completion(self.root, self.digest)
        self.assertEqual("uncommitted", report["status"])
        self.assertFalse(report["receipt_present"])
        self.assertFalse(report["full_artifact_integrity_verified"])
        self.assertFalse(self.root.exists())

    def test_orphan_case_artifacts_without_receipt_are_not_complete(self):
        self.root.mkdir()
        write_immutable_view(self.built["case_results"][0]["g1_profile"],
                             self.root)
        report = check_batch_completion(self.root, self.digest)
        self.assertEqual("uncommitted", report["status"])
        self.assertFalse(self.receipt.exists())

    def test_corrupt_leaf_after_receipt_rejected_as_incomplete(self):
        publish_batch(self.built, self.root)
        leaf_sha = self.built["batch_receipt"]["cases"][0]["artifacts"]["g1_graph"]
        (self.root / (leaf_sha + ".json")).write_bytes(b'{"truncated":')
        with self.assertRaisesRegex(ValueError, "declared SHA-256"):
            check_batch_completion(self.root, self.digest)

    def test_deleted_leaf_after_receipt_refuses_completion(self):
        publish_batch(self.built, self.root)
        leaf_sha = self.built["batch_receipt"]["cases"][1]["artifacts"]["g1_view"]
        (self.root / (leaf_sha + ".json")).unlink()
        with self.assertRaisesRegex(ValueError, "Missing"):
            check_batch_completion(self.root, self.digest)

    def test_repeated_publish_reuses_exact_existing_leaves_and_receipt(self):
        first = publish_batch(self.built, self.root)
        second = publish_batch(self.built, self.root)
        self.assertTrue(first["batch_receipt"]["created"])
        self.assertFalse(second["batch_receipt"]["created"])
        self.assertTrue(all(
            not entry["created"]
            for row in second["cases"]
            for entry in row["artifacts"].values()
        ))
        self.assertEqual(first["batch_id"], second["batch_id"])

    def test_later_case_write_failure_leaves_no_new_receipt(self):
        from src.threatragraph import batch_publication
        writer = batch_publication.write_immutable_view
        count = [0]

        def fail_late(*args, **kwargs):
            count[0] += 1
            if count[0] == len(ARTIFACT_NAMES) + 2:
                raise OSError("synthetic second-case failure")
            return writer(*args, **kwargs)

        with patch.object(batch_publication, "write_immutable_view",
                          side_effect=fail_late):
            with self.assertRaisesRegex(OSError, "second-case failure"):
                publish_batch(self.built, self.root)
        self.assertFalse(self.receipt.exists())
        self.assertEqual("uncommitted",
                         check_batch_completion(self.root, self.digest)["status"])
        self.assertTrue(any(self.root.glob("*.json")))

    def test_retry_recovers_from_complete_leaves_of_failed_first_attempt(self):
        from src.threatragraph import batch_publication
        writer = batch_publication.write_immutable_view
        count = [0]

        def fail_before_receipt(*args, **kwargs):
            count[0] += 1
            if count[0] == len(self.built["case_results"]) * len(ARTIFACT_NAMES) + 1:
                raise OSError("synthetic final-receipt failure")
            return writer(*args, **kwargs)

        with patch.object(batch_publication, "write_immutable_view",
                          side_effect=fail_before_receipt):
            with self.assertRaisesRegex(OSError, "final-receipt failure"):
                publish_batch(self.built, self.root)
        self.assertFalse(self.receipt.exists())
        retry = publish_batch(self.built, self.root)
        self.assertTrue(retry["batch_receipt"]["created"])
        self.assertTrue(all(not d["created"] for case in retry["cases"]
                            for d in case["artifacts"].values()))
        self.assertEqual("sealed_unscored_batch_verified",
                         check_batch_completion(self.root, self.digest)["status"])

    def test_corrupt_preexisting_leaf_blocks_retry_before_receipt(self):
        record = self.built["case_results"][0]["b0_view"]
        _, file, _ = write_immutable_view(record, self.root)
        file.write_bytes(b"corrupted")
        with self.assertRaises((ValueError, OSError)):
            publish_batch(self.built, self.root)
        self.assertFalse(self.receipt.exists())

    def test_changed_in_memory_artifact_blocks_all_writes(self):
        self.built["case_results"][0]["b0_view"]["cutoff_at"] = "future-tamper"
        with self.assertRaisesRegex(ValueError, "differs from sealed receipt"):
            publish_batch(self.built, self.root)
        self.assertFalse(self.root.exists())

    def test_missing_in_memory_case_artifact_blocks_all_writes(self):
        self.built["case_results"][1].pop("feature_lineage")
        with self.assertRaisesRegex(ValueError, "Missing, extra"):
            publish_batch(self.built, self.root)
        self.assertFalse(self.root.exists())

    def test_prepublication_replay_rejects_rehashed_fabricated_b0(self):
        forged = sample_outputs("case-forged")
        forged["b0_profile"]["facts"][0]["evidence_sha256s"] = ["0" * 64]
        reseal_case_links(forged)
        plan = {
            "dataset_id": "synthetic", "dataset_version": "v1",
            "cases": [{"case_id": "case-forged"}],
        }
        bad = {
            "case_results": [forged],
            "batch_receipt": _receipt([forged], plan),
        }
        digest = snapshot_sha256(bad["batch_receipt"])
        with self.assertRaisesRegex(ValueError, "deterministic source graph"):
            publish_batch(bad, self.root)
        self.assertFalse((self.root / (digest + ".json")).exists())

    def test_bad_or_ambiguous_receipt_hash_refused(self):
        for supplied in ("../future.json", "B" * 64, "", "a" * 65):
            with self.subTest(supplied=supplied):
                with self.assertRaisesRegex(ValueError, "lowercase SHA-256"):
                    check_batch_completion(self.root, supplied)

    def test_symlinked_final_receipt_never_claims_completion(self):
        self.root.mkdir()
        actual = self.root / "unsafe-source.json"
        actual.write_bytes(b"{}")
        try:
            self.receipt.symlink_to(actual)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable")
        with self.assertRaises((ValueError, OSError)):
            check_batch_completion(self.root, self.digest)

    def test_uncommitted_cli_returns_nonzero_without_writing(self):
        from contextlib import redirect_stdout
        from io import StringIO
        output = StringIO()
        with redirect_stdout(output):
            status = completion_cli([
                "--artifact-root", str(self.root),
                "--batch-receipt-sha256", self.digest,
            ])
        self.assertEqual(2, status)
        payload = json.loads(output.getvalue())
        self.assertEqual("uncommitted", payload["status"])
        self.assertFalse(self.root.exists())

    def test_verified_cli_return_zero_but_not_research_ready(self):
        from contextlib import redirect_stdout
        from io import StringIO
        publish_batch(self.built, self.root)
        output = StringIO()
        with redirect_stdout(output):
            status = completion_cli([
                "--artifact-root", str(self.root),
                "--batch-receipt-sha256", self.digest,
            ])
        self.assertEqual(0, status)
        payload = json.loads(output.getvalue())
        self.assertTrue(payload["full_artifact_integrity_verified"])
        self.assertFalse(payload["research_ready"])

    def test_valid_existing_receipt_reused_without_writing_any_leaf(self):
        from src.threatragraph import batch_publication
        first = publish_batch(self.built, self.root)
        with patch.object(batch_publication, "write_immutable_view",
                          side_effect=AssertionError("should not write")):
            recovered = publish_batch(self.built, self.root)
        self.assertTrue(recovered["existing_receipt_reused"])
        self.assertFalse(recovered["batch_receipt"]["created"])
        self.assertEqual(first["batch_receipt"]["sha256"],
                         recovered["batch_receipt"]["sha256"])
        self.assertTrue(recovered["stored_leaf_replay_verified"])

    def test_corrupt_existing_receipt_blocks_retry_before_leaf_write(self):
        from src.threatragraph import batch_publication
        publish_batch(self.built, self.root)
        self.receipt.write_bytes(b'{"corrupt":true}\n')
        with patch.object(batch_publication, "write_immutable_view",
                          side_effect=AssertionError("must not write")):
            with self.assertRaisesRegex(ValueError, "declared SHA-256"):
                publish_batch(self.built, self.root)
        self.assertEqual(b'{"corrupt":true}\n', self.receipt.read_bytes())

    def test_symlinked_existing_receipt_blocks_retry_before_leaf_write(self):
        from src.threatragraph import batch_publication
        self.root.mkdir()
        other = self.root / "unrelated.json"
        other.write_bytes(b"{}")
        try:
            self.receipt.symlink_to(other)
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks unavailable")
        with patch.object(batch_publication, "write_immutable_view",
                          side_effect=AssertionError("must not write")):
            with self.assertRaises((ValueError, OSError)):
                publish_batch(self.built, self.root)
        self.assertTrue(self.receipt.is_symlink())

    def test_valid_receipt_with_deleted_leaf_is_refused_on_retry(self):
        from src.threatragraph import batch_publication
        publish_batch(self.built, self.root)
        sha = self.built["batch_receipt"]["cases"][0]["artifacts"]["b0_graph"]
        (self.root / (sha + ".json")).unlink()
        with patch.object(batch_publication, "write_immutable_view",
                          side_effect=AssertionError("must not write")):
            with self.assertRaisesRegex(ValueError, "Missing"):
                publish_batch(self.built, self.root)

    def test_post_commit_replay_exception_can_recover_via_existing_receipt(self):
        from src.threatragraph import batch_publication
        verifier = batch_publication.replay_batch
        with patch.object(batch_publication, "replay_batch",
                          side_effect=OSError("post-commit interruption")):
            with self.assertRaisesRegex(OSError, "post-commit interruption"):
                publish_batch(self.built, self.root)
        # Publication was completed before the interrupted readback; don't
        # report success until the retry independently replays the receipt.
        self.assertTrue(self.receipt.is_file())
        verified = verifier(self.root, self.digest)
        self.assertTrue(verified["receipt_published"])
        with patch.object(batch_publication, "write_immutable_view",
                          side_effect=AssertionError("must not write")):
            retry = publish_batch(self.built, self.root)
        self.assertTrue(retry["existing_receipt_reused"])

    def test_parallel_identical_publications_have_one_receipt_creator(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier
        from src.threatragraph import batch_publication
        original = batch_publication.verify_unpublished_batch
        barrier = Barrier(2)

        def both_ready(*args):
            barrier.wait(timeout=10)
            return original(*args)

        with patch.object(batch_publication, "verify_unpublished_batch",
                          side_effect=both_ready):
            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = [
                    pool.submit(publish_batch, self.built, self.root)
                    for _ in range(2)
                ]
                results = [f.result(timeout=20) for f in futures]
        self.assertEqual(1, sum(x["batch_receipt"]["created"] for x in results))
        self.assertTrue(all(x["stored_leaf_replay_verified"] for x in results))
        self.assertEqual("sealed_unscored_batch_verified",
                         check_batch_completion(self.root, self.digest)["status"])

    def test_probe_cannot_observe_commit_during_prepublication_replay(self):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Event
        from src.threatragraph import batch_publication
        started, proceed = Event(), Event()
        original = batch_publication.verify_unpublished_batch

        def paused_check(*args):
            started.set()
            if not proceed.wait(10):
                raise RuntimeError("Test replay gate timed out")
            return original(*args)

        with patch.object(batch_publication, "verify_unpublished_batch",
                          side_effect=paused_check):
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(publish_batch, self.built, self.root)
                try:
                    self.assertTrue(started.wait(10))
                    probe = check_batch_completion(self.root, self.digest)
                    self.assertEqual("uncommitted", probe["status"])
                    self.assertFalse(self.receipt.exists())
                finally:
                    proceed.set()
                completed = future.result(timeout=20)
        self.assertTrue(completed["receipt_published"])
        self.assertEqual("sealed_unscored_batch_verified",
                         check_batch_completion(self.root, self.digest)["status"])

    def test_different_batch_receipts_coexist_without_rewriting_existing(self):
        existing = publish_batch(self.built, self.root)
        alternate = built_for(("case-a",))
        outcome = publish_batch(alternate, self.root)
        self.assertNotEqual(existing["batch_receipt"]["sha256"],
                            outcome["batch_receipt"]["sha256"])
        self.assertTrue(self.receipt.exists())
        self.assertTrue((self.root / (
            outcome["batch_receipt"]["sha256"] + ".json")).exists())
        self.assertEqual("sealed_unscored_batch_verified",
                         check_batch_completion(self.root, self.digest)["status"])
        self.assertEqual("sealed_unscored_batch_verified",
                         check_batch_completion(
                             self.root, outcome["batch_receipt"]["sha256"]
                         )["status"])

    def test_oversized_case_artifact_refused_before_any_disk_write(self):
        from src.threatragraph.batch_replay import MAX_ARTIFACT_BYTES
        self.built["case_results"][0]["b0_view"]["oversized"] = (
            "x" * (MAX_ARTIFACT_BYTES + 1)
        )
        with self.assertRaisesRegex(ValueError, "replay reader size limit"):
            publish_batch(self.built, self.root)
        self.assertFalse(self.root.exists())

    def test_oversized_batch_receipt_refused_before_disk_write(self):
        from src.threatragraph.batch_replay import MAX_ARTIFACT_BYTES
        self.built["batch_receipt"]["oversized"] = (
            "x" * (MAX_ARTIFACT_BYTES + 1)
        )
        with self.assertRaisesRegex(ValueError, "receipt exceeds replay reader"):
            publish_batch(self.built, self.root)
        self.assertFalse(self.root.exists())

    def test_extra_uncommitted_staging_file_is_not_completion(self):
        self.root.mkdir()
        (self.root / ".stage-abandoned.partial").write_bytes(b"truncated")
        status = check_batch_completion(self.root, self.digest)
        self.assertEqual("uncommitted", status["status"])
        self.assertFalse(self.receipt.exists())


if __name__ == "__main__":
    unittest.main()
