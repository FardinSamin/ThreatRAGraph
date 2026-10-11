"""Synthetic offline pairing and run-lock tests. No historical approval."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.freeze_case_snapshots import snapshot_sha256, write_immutable_view
from scripts.freeze_paired_run import _load
from src.threatragraph.evidence_graph import fingerprint
from src.threatragraph.feature_lineage import (
    ARTIFACT_KIND, CONTRACT_VERSION, EXTRACTION, IDENTITY_POLICY,
    graph_claim_set_sha256,
)
from src.threatragraph.paired_run_freeze import build_paired_run


def digest(text):
    return hashlib.sha256(text.encode()).hexdigest()


def source(name, role, group):
    return {
        "role": role, "source_version_id": name, "sha256": digest(name),
        "available_at": "2022-01-01T00:00:00Z",
        "independence_group": group,
    }


def edge(n, src, subject, predicate, obj):
    return {
        "claim_id": "claim:" + digest(n),
        "source_version_id": src,
        "subject_id": subject, "predicate": predicate, "object_id": obj,
        "assertion_kind": "report_assertion", "polarity": "positive",
        "evidence_locator": {
            "kind": "text_span", "segment_id": "seg:" + src,
            "start": 0, "end": 8,
        },
        "evidence_sha256": digest(n + "excerpt"),
        "extractor_version": "fixture-1",
        "evidence_status": "aligned",
        "semantic_review_status": "supported_by_excerpt",
    }


def view(method, sources):
    return {
        "schema_version": "1.0", "artifact_kind": "historical_source_input",
        "dataset_id": "synthetic", "dataset_version": "v1",
        "case_id": "test-case", "target_entity_id": "malware:new",
        "cutoff_at": "2023-01-01T00:00:00Z",
        "scope_warning": "Synthetic only: not real source history",
        "method": method, "sources": sources,
    }


def graph(v, edges):
    return {
        "schema_version": "1.0", "artifact_kind": "historical_sourced_graph",
        "case_id": v["case_id"], "method": v["method"],
        "cutoff_at": v["cutoff_at"], "source_view_sha256": fingerprint(v),
        "nodes": sorted({x for e in edges
                         for x in (e["subject_id"], e["object_id"])}),
        "edges": edges, "caveat": "Synthetic fixture",
    }


def fixture():
    early = source("early", "early", "early-group")
    back1 = source("back-one", "background", "history-a")
    back2 = source("back-two", "background", "history-b")
    bv = view("B0_sparse_report_only", [early])
    gv = view("G1_early_plus_historical_background",
              [copy.deepcopy(early), back1, back2])
    e = edge("a", "early", "malware:new", "USES", "attack-technique:T1059")
    shared = edge("b", "back-one", "malware:old", "USES",
                  "attack-technique:T1059")
    proposed = edge("c", "back-two", "malware:old", "HAS_BEHAVIOR",
                    "attack-behavior:exec-sequence")
    bg, gg = graph(bv, [e]), graph(gv, [e, shared, proposed])
    sources = {s["source_version_id"]: s for s in gv["sources"]}
    lineage = {
        "schema_version": CONTRACT_VERSION,
        "artifact_kind": ARTIFACT_KIND,
        "case_id": gv["case_id"], "cutoff_at": gv["cutoff_at"],
        "g1_source_view_sha256": fingerprint(gv),
        "g1_graph_sha256": graph_claim_set_sha256(gg),
        "identity_policy": IDENTITY_POLICY,
        "claim_lineage": [
            {
                "claim_id": row["claim_id"],
                "source_version_id": row["source_version_id"],
                "source_sha256": sources[row["source_version_id"]]["sha256"],
                "source_available_at": sources[row["source_version_id"]]["available_at"],
                "claim_evidence_sha256": row["evidence_sha256"],
                "subject_id": row["subject_id"], "predicate": row["predicate"],
                "object_id": row["object_id"],
                "feature_known_at": sources[row["source_version_id"]]["available_at"],
                "derivation": EXTRACTION,
            }
            for row in sorted(gg["edges"], key=lambda r: r["claim_id"])
        ],
        "limitations": "Fabricated source and review metadata; synthetic test",
    }
    provenance = {
        "git_commit_sha": "a" * 40,
        "dependency_lock_sha256": "b" * 64,
        "source_manifest_sha256": "c" * 64,
        "case_manifest_sha256": "d" * 64,
        "review_set_sha256": "e" * 64,
        "ontology_version": "v1",
        "extractor_version": "test-fixture-v1",
        "ruleset_version": "no-enrichment-v1",
        "random_seed": None,
    }
    config = {
        "top_k": 5, "min_overlap": 1,
        "min_background_groups": 2, "max_peers_per_feature": 10,
    }
    return bv, bg, gv, gg, lineage, provenance, config


def run(values=None):
    bv, bg, gv, gg, lineage, provenance, config = (
        copy.deepcopy(values if values is not None else fixture())
    )
    return build_paired_run(
        bv, bg, gv, gg, lineage,
        metadata=provenance, g1_config=config,
    )


class PairedRunFreezeTests(unittest.TestCase):
    def test_synthetic_run_produces_profiles_and_lock_without_gold(self):
        result = run()
        self.assertEqual("B0", result["b0_profile"]["method"])
        self.assertEqual("G1", result["g1_profile"]["method"])
        self.assertEqual(1, len(result["g1_profile"]["predictions"]))
        self.assertTrue(result["paired_audit"]["early_output_parity_verified"])
        lock = result["run_lock"]
        self.assertFalse(lock["gold_labels_read"])
        self.assertTrue(lock["predictions_sealed_before_gold_access"])
        self.assertFalse(lock["historical_dates_and_rights_independently_verified"])
        self.assertFalse(lock["research_ready"])
        self.assertEqual(result, run())

    def test_run_id_is_derived_from_exact_lock_bytes(self):
        item = run()["run_lock"]
        ident = item["run_id"]
        self.assertEqual(ident, "run:" + fingerprint({
            k: v for k, v in item.items() if k != "run_id"
        }))

    def test_modified_metadata_changes_lock_but_not_predictions(self):
        data = fixture()
        a = run(data)
        data[5]["git_commit_sha"] = "f" * 40
        b = run(data)
        self.assertNotEqual(a["run_lock"]["run_id"], b["run_lock"]["run_id"])
        self.assertEqual(a["g1_profile"]["profile_id"], b["g1_profile"]["profile_id"])

    def test_version_control_characters_are_refused(self):
        data = fixture()
        data[5]["extractor_version"] = "v1\\nsource-injection"
        with self.assertRaisesRegex(ValueError, "bounded research version"):
            run(data)

    def test_unknown_metadata_or_gold_key_refused(self):
        data = fixture()
        data[5]["gold_labels"] = ["post-cutoff answer"]
        with self.assertRaisesRegex(ValueError, "exact reproducibility"):
            run(data)

    def test_future_source_cannot_enter_g1(self):
        data = fixture()
        data[2]["sources"][1]["available_at"] = "2025-01-01T00:00:00Z"
        with self.assertRaises(ValueError):
            run(data)

    def test_mismatched_early_claim_rejected(self):
        data = fixture()
        data[3]["edges"][0]["object_id"] = "attack-technique:T1105"
        with self.assertRaises(ValueError):
            run(data)

    def test_bad_code_revision_refused(self):
        data = fixture()
        data[5]["git_commit_sha"] = "HEAD"
        with self.assertRaisesRegex(ValueError, "Git commit"):
            run(data)

    def test_bad_hashes_refused(self):
        data = fixture()
        data[5]["review_set_sha256"] = "invalid"
        with self.assertRaisesRegex(ValueError, "Pinned SHA-256"):
            run(data)

    def test_unknown_configuration_refused(self):
        data = fixture()
        data[6]["top_k_future_labels"] = 5
        with self.assertRaisesRegex(ValueError, "exactly four"):
            run(data)

    def test_nonpositive_top_k_refused_by_g1(self):
        data = fixture()
        data[6]["top_k"] = 0
        with self.assertRaisesRegex(ValueError, "Invalid bounded G1"):
            run(data)

    def test_non_null_seed_for_deterministic_engine_refused(self):
        data = fixture()
        data[5]["random_seed"] = 12345
        with self.assertRaisesRegex(ValueError, "must be null"):
            run(data)

    def test_preview_and_immutable_write_use_identical_artifact_hash(self):
        profile = run()["run_lock"]
        digest = snapshot_sha256(profile)
        with tempfile.TemporaryDirectory() as root:
            actual, path, created = write_immutable_view(profile, root)
            self.assertTrue(created)
            self.assertEqual(digest, actual)
            self.assertEqual(path.name, digest + ".json")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")),
                             profile)
            other, repeated, created_again = write_immutable_view(profile, root)
            self.assertEqual(digest, other)
            self.assertEqual(path, repeated)
            self.assertFalse(created_again)

    def test_duplicate_json_keys_cannot_silently_change_metadata(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "meta.json"
            path.write_text('{"git_commit_sha":"a","git_commit_sha":"b"}',
                            encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Duplicate JSON"):
                _load(str(path))

    def test_symlinked_cli_input_refused(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "metadata.json"
            target.write_text("{}", encoding="utf-8")
            alias = Path(root) / "alias.json"
            try:
                alias.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("Symlink creation unavailable on this OS")
            with self.assertRaisesRegex(ValueError, "Unsafe"):
                _load(str(alias))

    def test_metadata_declared_not_authenticated(self):
        lock = run()["run_lock"]
        self.assertFalse(lock["source_manifest_bytes_verified_by_this_module"])
        self.assertFalse(lock["reviewer_identities_independently_verified"])
        self.assertEqual("not_performed", lock["empirical_evaluation"])


if __name__ == "__main__":
    unittest.main()
