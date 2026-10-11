"""Only synthetic public GitHub event fixtures; never a claimed historical witness."""
from contextlib import redirect_stdout
import copy
import gzip
import hashlib
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from scripts.verify_kissadog_cado_public_push import (
    CUTOFF, COMMIT, REPO, REPO_ID, SCHEMA, event_matches,
    main, verify_archive,
)


def _event(when="2022-12-23T11:42:26Z"):
    return {
        "id": "12345678901",
        "type": "PushEvent", "public": True,
        "created_at": when,
        "repo": {"id": REPO_ID, "name": REPO},
        "payload": {
            "ref": "refs/heads/main", "head": COMMIT,
            "commits": [{"sha": COMMIT}],
        },
    }


def _jsonl(*events):
    return gzip.compress(
        b"".join(json.dumps(e, sort_keys=True).encode() + b"\n" for e in events),
        mtime=0,
    )


class HistoricalKissadogPublicPushTests(unittest.TestCase):
    def _with_archive(self, raw, function):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "2022-12-23-11.json.gz"
            path.write_bytes(raw)
            return function(path)

    def test_exact_public_push_event_historical_pointer_not_cado_article(self):
        def run(path):
            out = verify_archive(path, pinned_archive_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(SCHEMA, out["schema_version"])
            self.assertEqual("2022-12-23T11:42:26Z", out["public_event_created_at"])
            self.assertTrue(out["independent_public_push_event_found"])
            self.assertTrue(out["archive_sha256_frozen_in_source"])
            self.assertEqual(1, out["parsed_event_count"])
            for key in (
                "historical_pointer_git_tree_chain_verified_in_this_replay",
                "historical_cado_article_body_verifiable_from_event",
                "original_cado_report_public_by_verified", "copyright_and_use_rights_approved",
                "independent_semantic_campaign_claim_verified", "source_version_approved",
                "g1_evaluation_eligible", "research_ready",
            ):
                self.assertFalse(out[key])
        self._with_archive(_jsonl(_event()), run)

    def test_exclusion_wrong_event_repo_public_flag_and_branch(self):
        mutations = [
            ("type", "IssueCommentEvent"),
            ("public", False),
            ("id", 123),
            ("created_at", "2023-03-02T11:42:26Z"),
            ("created_at", "2022-12-23T10:42:26Z"),
            ("created_at", "2022-12-23T11:99:26Z"),
        ]
        for key, wrong in mutations:
            obj = _event()
            obj[key] = wrong
            with self.subTest(field=key):
                self.assertFalse(event_matches(obj))
        for mutation in (
            {"id": 1}, {"name": "evil/repo"},
        ):
            obj = _event()
            obj["repo"].update(mutation)
            self.assertFalse(event_matches(obj))
        for mutation in (
            {"ref": "refs/heads/not-main"},
            {"head": "a" * 40}, {"commits": []}, {"commits": [{"sha": "0" * 40}]},
        ):
            obj = _event()
            obj["payload"].update(mutation)
            self.assertFalse(event_matches(obj))

    def test_plain_text_json_and_gzip_truncation_fail_closed(self):
        for bad in (
            json.dumps(_event()).encode(),
            _jsonl(_event())[:-2],
            _jsonl(_event()) + b"corruption",
        ):
            with self.subTest(n=len(bad)), self.assertRaises(ValueError):
                self._with_archive(bad, lambda p: verify_archive(p))

    def test_wrong_hour_and_invalid_utc_calendar_event_does_not_count(self):
        for time in (
            "2022-12-23T10:59:59Z",
            "2022-12-23T12:00:00Z",
            "2023-03-01T11:00:00Z",
            "2022-12-23T11:60:00Z",
            "2022-12-23T11:30:00+00:00",
        ):
            with self.subTest(t=time), self.assertFalse(event_matches(_event(time))):
                pass

    def test_no_target_event_in_full_hour_is_not_a_positive_receipt(self):
        wrong = _event()
        wrong["id"] = "900"
        wrong["repo"]["name"] = "other/repo"
        with self.assertRaisesRegex(ValueError, "No exact target"):
            self._with_archive(_jsonl(wrong), lambda p: verify_archive(p))

    def test_wrong_original_archive_sha256_rejected(self):
        raw = _jsonl(_event())
        with self.assertRaisesRegex(ValueError, "digest differs"):
            self._with_archive(raw, lambda p: verify_archive(p, pinned_archive_sha256="0" * 64))
        with self.assertRaisesRegex(ValueError, "full lowercase"):
            self._with_archive(raw, lambda p: verify_archive(p, pinned_archive_sha256="not sha256"))

    def test_duplicated_event_in_archive_refused(self):
        with self.assertRaisesRegex(ValueError, "Ambiguous duplicate"):
            self._with_archive(_jsonl(_event(), _event()), lambda p: verify_archive(p))

    def test_near_match_does_not_block_unique_correct_event(self):
        other = _event()
        other["payload"]["ref"] = "refs/tags/not-branch"
        def run(path):
            result = verify_archive(path)
            self.assertEqual(2, result["parsed_event_count"])
            self.assertFalse(result["archive_sha256_frozen_in_source"])
        self._with_archive(_jsonl(other, _event()), run)

    def test_nonregular_and_symlink_archive_rejected(self):
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            orig = folder / "actual.gz"
            alias = folder / "link.gz"
            orig.write_bytes(_jsonl(_event()))
            try:
                alias.symlink_to(orig)
            except (OSError, NotImplementedError):
                return
            with self.assertRaisesRegex(ValueError, "regular"):
                verify_archive(alias)

    def test_cli_hash_only_candidate_output_and_rejection(self):
        with TemporaryDirectory() as directory:
            path = Path(directory) / "events.gz"
            path.write_bytes(_jsonl(_event()))
            with redirect_stdout(io.StringIO()) as out:
                self.assertEqual(0, main(["--archive", str(path)]))
            obj = json.loads(out.getvalue())
            self.assertFalse(obj["research_ready"])
            self.assertNotIn("commits", obj)
            with redirect_stdout(io.StringIO()) as bad:
                self.assertEqual(2, main(["--archive", str(path),
                                          "--pinned-archive-sha256", "0" * 64]))
            self.assertEqual("historical_pointer_push_witness_refused",
                             json.loads(bad.getvalue())["status"])

    def test_archive_event_sha256_hashes_original_line(self):
        e = _event()
        raw_line = json.dumps(e, sort_keys=True).encode() + b"\n"
        self._with_archive(_jsonl(e), lambda p: self.assertEqual(
            hashlib.sha256(raw_line).hexdigest(),
            verify_archive(p)["event_line_sha256"]
        ))


if __name__ == "__main__":
    unittest.main()
