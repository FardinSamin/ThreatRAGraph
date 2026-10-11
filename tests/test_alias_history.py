"""Synthetic candidate historical alias policy; no approved alias graph."""
import copy
import hashlib
import json
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import tempfile
import unittest

from scripts.audit_alias_history import _read, main
from src.threatragraph.alias_history import (
    create_history, inspect_alias, validate_history,
)
from src.threatragraph.evidence_graph import fingerprint


def digest(data):
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def fixture():
    view = {
        "schema_version": "1.0", "artifact_kind": "historical_source_input",
        "dataset_id": "synthetic", "dataset_version": "v1",
        "case_id": "case-a", "target_entity_id": "malware:target",
        "cutoff_at": "2023-01-01T00:00:00Z",
        "scope_warning": "Synthetic source dates, no genuine provenance",
        "method": "B0_sparse_report_only",
        "sources": [{
            "role": "early", "source_version_id": "early-report",
            "sha256": digest("source"), "available_at": "2022-12-01T00:00:00Z",
            "independence_group": "publisher-one",
        }],
    }
    entry = {
        "alias_id": "malware:oldname",
        "canonical_candidate_id": "malware:known",
        "source_version_id": "early-report",
        "source_sha256": digest("source"),
        "first_known_at": "2022-12-01T00:00:00Z",
        "evidence_sha256": digest("evidence"),
        "reviewer_id_declared": "synthetic-reviewer",
        "decision": "candidate_supported",
    }
    return view, [entry]


def reseal(hist):
    result = copy.deepcopy(hist)
    result.pop("history_id", None)
    result["history_id"] = "alias-history:" + fingerprint(result)
    return result


class HistoricalAliasCandidateTests(unittest.TestCase):
    def test_single_historically_eligible_candidate_never_rewrites(self):
        view, rows = fixture()
        history = create_history(view, rows)
        result = inspect_alias(view, history, "malware:oldname")
        self.assertEqual("single_candidate_still_unapproved", result["status"])
        self.assertEqual(["malware:known"], result["candidate_canonical_ids"])
        self.assertFalse(result["automatic_entity_rewrite_allowed"])
        self.assertFalse(result["g1_feature_lineage_enrichment_allowed"])
        self.assertFalse(result["research_ready"])

    def test_unknown_alias_never_guessed_from_name(self):
        view, rows = fixture()
        result = inspect_alias(view, create_history(view, rows),
                               "malware:looks-similar")
        self.assertEqual("no_candidate", result["status"])
        self.assertEqual([], result["candidate_canonical_ids"])

    def test_candidate_collisions_are_exposed_not_silently_resolved(self):
        view, rows = fixture()
        another = dict(rows[0],
                       canonical_candidate_id="malware:other",
                       evidence_sha256=digest("other"))
        history = create_history(view, [rows[0], another])
        result = inspect_alias(view, history, "malware:oldname")
        self.assertEqual("ambiguous_candidates_require_adjudication",
                         result["status"])
        self.assertEqual(["malware:known", "malware:other"],
                         result["candidate_canonical_ids"])

    def test_conflicting_supported_and_rejected_same_target_requires_review(self):
        view, rows = fixture()
        opposed = dict(rows[0], evidence_sha256=digest("contradicting excerpt"),
                       decision="candidate_rejected")
        history = create_history(view, [rows[0], opposed])
        report = inspect_alias(view, history, "malware:oldname")
        self.assertEqual("conflicting_evidence_requires_adjudication",
                         report["status"])
        self.assertEqual(["malware:known"], report["candidate_canonical_ids"])
        self.assertEqual(["malware:known"], report["disputed_or_uncertain_ids"])
        self.assertFalse(report["automatic_entity_rewrite_allowed"])

    def test_cross_type_actor_malware_conflation_refused(self):
        view, rows = fixture()
        rows[0]["canonical_candidate_id"] = "threat-actor:known"
        with self.assertRaisesRegex(ValueError, "Cross-type"):
            create_history(view, rows)

    def test_postcutoff_alias_evidence_is_refused(self):
        view, rows = fixture()
        rows[0]["first_known_at"] = "2024-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "Future or retrospectively"):
            create_history(view, rows)

    def test_alias_history_cannot_depend_on_later_source(self):
        view, rows = fixture()
        view["sources"][0]["available_at"] = "2024-01-01T00:00:00Z"
        rows[0]["first_known_at"] = "2024-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "post-cutoff"):
            create_history(view, rows)

    def test_unregistered_source_cannot_support_mapping(self):
        view, rows = fixture()
        rows[0]["source_version_id"] = "future-leaked-source"
        with self.assertRaisesRegex(ValueError, "declared source"):
            create_history(view, rows)

    def test_source_digest_mismatch_refused(self):
        view, rows = fixture()
        rows[0]["source_sha256"] = "b" * 64
        with self.assertRaisesRegex(ValueError, "source byte digest"):
            create_history(view, rows)

    def test_duplicate_identical_alias_decision_refused(self):
        view, rows = fixture()
        with self.assertRaisesRegex(ValueError, "Duplicated"):
            create_history(view, rows + [copy.deepcopy(rows[0])])

    def test_unsorted_alias_rows_refused(self):
        view, rows = fixture()
        other = dict(rows[0], alias_id="malware:aaname",
                     evidence_sha256=digest("other"))
        with self.assertRaisesRegex(ValueError, "deterministically ordered"):
            create_history(view, [rows[0], other])

    def test_chained_alias_candidate_refused(self):
        view, rows = fixture()
        second = dict(rows[0], alias_id="malware:known",
                      canonical_candidate_id="malware:final",
                      evidence_sha256=digest("other"))
        with self.assertRaisesRegex(ValueError, "Chained or cyclic"):
            create_history(view, [second, rows[0]])

    def test_rejected_alias_remains_uncertain_not_approved(self):
        view, rows = fixture()
        rows[0]["decision"] = "candidate_rejected"
        history = create_history(view, rows)
        result = inspect_alias(view, history, "malware:oldname")
        self.assertEqual("no_candidate", result["status"])
        self.assertEqual(["malware:known"], result["disputed_or_uncertain_ids"])

    def test_tampered_rehashed_history_cannot_bypass_source_cutoff(self):
        view, rows = fixture()
        history = create_history(view, rows)
        history["entries"][0]["first_known_at"] = "2026-01-01T00:00:00Z"
        history = reseal(history)
        with self.assertRaisesRegex(ValueError, "Future or retrospectively"):
            validate_history(view, history)

    def test_unrecognized_history_fields_cannot_smuggle_gold(self):
        view, rows = fixture()
        history = create_history(view, rows)
        history["heldout_labels"] = ["future-answer"]
        with self.assertRaisesRegex(ValueError, "Exact source-bound"):
            validate_history(view, history)

    def test_inspection_result_is_deterministic(self):
        view, rows = fixture()
        history = create_history(view, rows)
        self.assertEqual(inspect_alias(view, history, "malware:oldname"),
                         inspect_alias(view, history, "malware:oldname"))

    def test_cli_can_inspect_synthetic_history_without_file_writes(self):
        view, rows = fixture()
        hist = create_history(view, rows)
        with tempfile.TemporaryDirectory() as tmp:
            vp = Path(tmp) / "view.json"
            hp = Path(tmp) / "history.json"
            vp.write_text(json.dumps(view), encoding="utf-8")
            hp.write_text(json.dumps(hist), encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = main(["--view", str(vp), "--history", str(hp),
                               "--entity-id", "malware:oldname"])
            self.assertEqual(0, status)
            self.assertFalse(json.loads(output.getvalue())["research_ready"])

    def test_cli_refuses_nested_nonfinite_alias_history_json(self):
        view, rows = fixture()
        history = create_history(view, rows)
        with tempfile.TemporaryDirectory() as tmp:
            a = Path(tmp) / "view.json"
            b = Path(tmp) / "history.json"
            a.write_text(json.dumps(view), encoding="utf-8")
            b.write_text(json.dumps(history).replace(
                '"entries": [', '"extra": {"x":NaN}, "entries": [', 1
            ), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Nonfinite"):
                _read(b)

    def test_cli_refuses_symlinked_parent_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real"
            real.mkdir()
            (real / "history.json").write_text("{}", encoding="utf-8")
            alias = root / "linked"
            try:
                alias.symlink_to(real, target_is_directory=True)
            except (OSError, NotImplementedError):
                self.skipTest("Symlinks not available")
            with self.assertRaisesRegex(ValueError, "Symlink"):
                _read(alias / "history.json")

    def test_cli_rejects_identical_source_history_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "same.json"
            path.write_text("{}", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                code = main(["--view", str(path), "--history", str(path),
                             "--entity-id", "malware:fixture"])
            self.assertEqual(2, code)
            self.assertEqual(
                "ValueError", json.loads(output.getvalue())["reason_category"]
            )

    def test_cli_refuses_symlinked_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "original.json"
            alias = Path(tmp) / "linked.json"
            path.write_text("{}", encoding="utf-8")
            try:
                alias.symlink_to(path)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink unavailable on this OS")
            with self.assertRaisesRegex(ValueError, "Symlink"):
                _read(alias)


if __name__ == "__main__":
    unittest.main()
