"""Synthetic only: unscored batch plans, case isolation, reproducible receipts."""
import copy
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.freeze_case_snapshots import snapshot_sha256
from scripts.run_offline_case_batch import (
    ARTIFACT_NAMES, _confined_file, _receipt, main, run_batch, validate_plan,
)
from src.threatragraph.evidence_graph import fingerprint


def fixtures():
    src = {"dataset_id": "synthetic", "dataset_version": "v1"}
    cases = {"dataset_id": "synthetic", "dataset_version": "v1",
             "cases": [{"case_id": "case-a"}, {"case_id": "case-b"}]}
    def spec(cid):
        return {
            "case_id": cid,
            "claims_jsonl": cid + "/claims.jsonl",
            "reviews_jsonl": cid + "/reviews.jsonl",
            "feature_lineage_json": cid + "/lineage.json",
            "metadata_json": cid + "/metadata.json",
            "g1_config_json": "common/g1-config.json",
        }
    plan = {
        "schema_version": "1.0",
        "artifact_kind": "unscored-multicase-batch-v1",
        "dataset_id": "synthetic", "dataset_version": "v1",
        "cases": [spec("case-a"), spec("case-b")],
    }
    return plan, src, cases


def fake_outputs(cid):
    b0_id = "profile:" + fingerprint({"method": "B0", "case_id": cid})
    g1_id = "profile:" + fingerprint({"method": "G1", "case_id": cid})
    run_id = "run:" + fingerprint({"case": cid})
    audit_id = "audit:" + fingerprint({"case": cid})
    pipeline_id = "pipeline:" + fingerprint({"case": cid})
    return {
        "b0_view": {"case_id": cid},
        "g1_view": {"case_id": cid},
        "b0_graph": {"case_id": cid},
        "g1_graph": {"case_id": cid},
        "b0_profile": {"case_id": cid, "profile_id": b0_id},
        "g1_profile": {
            "case_id": cid, "profile_id": g1_id,
            "predictions": [], "abstention": {"abstained": True},
        },
        "paired_audit": {"case_id": cid, "audit_id": audit_id},
        "run_lock": {"case_id": cid, "run_id": run_id, "research_ready": False},
        "pipeline_receipt": {
            "case_id": cid, "pipeline_id": pipeline_id,
            "run_id": run_id, "b0_profile_id": b0_id,
            "g1_profile_id": g1_id, "paired_audit_id": audit_id,
            "research_ready": False, "heldout_labels_opened": False,
            "empirical_evaluation": "not_performed",
        },
    }


class OfflineBatchTests(unittest.TestCase):
    def setUp(self):
        self.plan, self.sources, self.cases = fixtures()
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.input_root = self.root / "input"
        self.input_root.mkdir()
        for row in self.plan["cases"]:
            for name in ("claims_jsonl", "reviews_jsonl",
                         "feature_lineage_json", "metadata_json",
                         "g1_config_json"):
                file = self.input_root / row[name]
                file.parent.mkdir(parents=True, exist_ok=True)
                file.write_text("{}\n", encoding="utf-8")
        self.deps = self.root / "dependency.lock"
        self.deps.write_bytes(b"synthetic test lock")
        self.archive = self.root / "archives"
        self.archive.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def simulate(self):
        with patch(
            "scripts.run_offline_case_batch.run_offline_case",
            side_effect=lambda sources, cases, cid, *args, **kwargs:
                fake_outputs(cid),
        ) as mocked:
            output = run_batch(
                self.plan, self.sources, self.cases, self.input_root,
                self.archive, self.deps, development_only=True,
            )
        return output, mocked

    def test_canonical_plan_accepted(self):
        self.assertEqual(2, len(validate_plan(
            self.plan, self.sources, self.cases
        )))

    def test_unknown_gold_fields_refused(self):
        self.plan["heldout_reference_path"] = "labels.json"
        with self.assertRaisesRegex(ValueError, "no-label"):
            validate_plan(self.plan, self.sources, self.cases)

    def test_case_cannot_supply_gold_instead_of_declared_inputs(self):
        self.plan["cases"][0]["gold_labels"] = ["later-answer"]
        with self.assertRaisesRegex(ValueError, "label input"):
            validate_plan(self.plan, self.sources, self.cases)

    def test_duplicate_case_id_refused(self):
        self.plan["cases"][1] = copy.deepcopy(self.plan["cases"][0])
        with self.assertRaisesRegex(ValueError, "Cross-case|unique"):
            validate_plan(self.plan, self.sources, self.cases)

    def test_out_of_order_cases_refused(self):
        self.plan["cases"].reverse()
        with self.assertRaisesRegex(ValueError, "sorted"):
            validate_plan(self.plan, self.sources, self.cases)

    def test_foreign_case_refused(self):
        self.plan["cases"][0]["case_id"] = "not-in-corpus"
        with self.assertRaisesRegex(ValueError, "unknown"):
            validate_plan(self.plan, self.sources, self.cases)

    def test_dataset_identity_mismatch_refused(self):
        self.plan["dataset_version"] = "newer-version"
        with self.assertRaisesRegex(ValueError, "identity"):
            validate_plan(self.plan, self.sources, self.cases)

    def test_invalid_path_traversal_and_absolute_paths_refused(self):
        for value in ("../reference.json", "/tmp/secret.json",
                      "C:\\secret.json", "nested/../gold.json",
                      "bad\x00path.json"):
            with self.subTest(value=value):
                invalid = copy.deepcopy(self.plan)
                invalid["cases"][0]["claims_jsonl"] = value
                with self.assertRaisesRegex(ValueError, "path|Paths"):
                    validate_plan(invalid, self.sources, self.cases)

    def test_cross_case_private_input_reuse_refused(self):
        self.plan["cases"][1]["reviews_jsonl"] = (
            self.plan["cases"][0]["reviews_jsonl"]
        )
        with self.assertRaisesRegex(ValueError, "Cross-case"):
            validate_plan(self.plan, self.sources, self.cases)

    def test_symlink_intermediate_directory_refused(self):
        with tempfile.TemporaryDirectory() as outside:
            root = self.input_root / "link"
            try:
                root.symlink_to(Path(outside), target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink cannot be created on this OS")
            with self.assertRaisesRegex(ValueError, "Symlinked"):
                _confined_file(self.input_root, "link/external.json")

    def test_later_case_missing_file_refused_before_any_run(self):
        target = self.input_root / self.plan["cases"][1]["feature_lineage_json"]
        target.unlink()
        with patch("scripts.run_offline_case_batch.run_offline_case") as mocked:
            with self.assertRaises((OSError, ValueError)):
                run_batch(self.plan, self.sources, self.cases,
                          self.input_root, self.archive, self.deps)
            mocked.assert_not_called()

    def test_two_case_receipt_is_deterministic_and_unscored(self):
        first, mocked = self.simulate()
        second, _ = self.simulate()
        self.assertEqual(2, mocked.call_count)
        self.assertEqual(first, second)
        batch = first["batch_receipt"]
        self.assertEqual(2, batch["case_count"])
        self.assertEqual(["case-a", "case-b"],
                         [r["case_id"] for r in batch["cases"]])
        self.assertFalse(batch["later_reference_labels_accessed"])
        self.assertFalse(batch["research_ready"])
        self.assertEqual("not_performed", batch["empirical_evaluation"])
        self.assertEqual("batch:" + fingerprint({
            k: v for k, v in batch.items() if k != "batch_id"
        }), batch["batch_id"])
        self.assertEqual(set(ARTIFACT_NAMES),
                         set(batch["cases"][0]["artifacts"]))

    def test_tampered_case_run_id_is_refused(self):
        objects = [fake_outputs("case-a"), fake_outputs("case-b")]
        objects[1]["pipeline_receipt"]["run_id"] = "run:tampered"
        with self.assertRaisesRegex(ValueError, "Inconsistent"):
            _receipt(objects, self.plan)

    def test_duplicate_run_id_is_refused(self):
        objects = [fake_outputs("case-a"), fake_outputs("case-b")]
        objects[1]["run_lock"]["run_id"] = objects[0]["run_lock"]["run_id"]
        objects[1]["pipeline_receipt"]["run_id"] = objects[0]["run_lock"]["run_id"]
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            _receipt(objects, self.plan)

    def test_approved_result_cannot_enter_candidate_batch(self):
        objects = [fake_outputs("case-a"), fake_outputs("case-b")]
        objects[0]["pipeline_receipt"]["research_ready"] = True
        with self.assertRaisesRegex(ValueError, "Inconsistent"):
            _receipt(objects, self.plan)

    def test_failed_later_run_has_no_output_writes(self):
        def side_effect(*args, **kwargs):
            if args[2] == "case-b":
                raise ValueError("Second case source invalid")
            return fake_outputs(args[2])
        outdir = self.root / "output"
        with patch("scripts.run_offline_case_batch.run_offline_case",
                   side_effect=side_effect):
            with self.assertRaisesRegex(ValueError, "source invalid"):
                run_batch(self.plan, self.sources, self.cases,
                          self.input_root, self.archive, self.deps)
        self.assertFalse(outdir.exists())

    def test_preview_does_not_create_output_files(self):
        for name, content in (("plan", self.plan),
                              ("sources", self.sources),
                              ("cases", self.cases)):
            (self.root / (name + ".json")).write_text(
                json.dumps(content), encoding="utf-8"
            )
        argv = [
            "--plan", str(self.root / "plan.json"),
            "--sources", str(self.root / "sources.json"),
            "--cases", str(self.root / "cases.json"),
            "--input-root", str(self.input_root),
            "--archive-root", str(self.archive),
            "--dependency-lock", str(self.deps),
            "--development-only",
        ]
        output = StringIO()
        with patch(
            "scripts.run_offline_case_batch.run_offline_case",
            side_effect=lambda sources, cases, cid, *args, **kwargs:
                fake_outputs(cid),
        ), redirect_stdout(output):
            self.assertEqual(0, main(argv))
        response = json.loads(output.getvalue())
        self.assertEqual("unscored_batch_preview", response["status"])
        self.assertFalse(response["later_reference_labels_accessed"])
        self.assertEqual(2, response["case_count"])
        self.assertFalse((self.root / "artifacts").exists())
        self.assertEqual(snapshot_sha256(self.simulate()[0]["batch_receipt"]),
                         response["batch_receipt"]["sha256"])


if __name__ == "__main__":
    unittest.main()
