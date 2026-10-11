"""Synthetic local-file input hardening tests; not executed in this draft."""
import json
import os
from pathlib import Path
import tempfile
import unittest

from src.threatragraph.local_file_inputs import (
    assert_distinct_input_files, read_local_json, read_local_text,
)


class LocalFileInputsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.file = self.root / "input.json"
        self.file.write_text('{"case_id":"fixture"}\n', encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_valid_bytes_and_plain_json_round_trip(self):
        self.assertEqual({"case_id": "fixture"}, read_local_json(self.file))
        self.assertEqual('{"case_id":"fixture"}\n', read_local_text(self.file))

    def test_preserves_crlf_instead_of_translating(self):
        self.file.write_bytes(b'{"x":"abc"}\r\n')
        self.assertTrue(read_local_text(self.file).endswith("\r\n"))

    def test_nested_duplicate_json_keys_refused(self):
        self.file.write_text('{"outer":{"x":1,"x":2}}', encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            read_local_json(self.file)

    def test_nested_nonfinite_json_values_refused(self):
        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(literal=literal):
                self.file.write_text('{"data":' + literal + '}',
                                     encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "Nonfinite"):
                    read_local_json(self.file)

    def test_json_array_not_accepted_as_object(self):
        self.file.write_text("[1,2,3]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "root"):
            read_local_json(self.file)

    def test_rejects_invalid_utf8_file(self):
        self.file.write_bytes(b"\xff\xfe")
        with self.assertRaises(UnicodeDecodeError):
            read_local_text(self.file)

    def test_rejects_empty_or_oversized_bytes(self):
        self.file.write_bytes(b"")
        with self.assertRaisesRegex(ValueError, "Empty"):
            read_local_text(self.file)
        self.file.write_bytes(b"x" * 12)
        with self.assertRaisesRegex(ValueError, "oversized"):
            read_local_text(self.file, max_bytes=10)

    def test_rejects_nonregular_directory_input(self):
        with self.assertRaises((ValueError, OSError)):
            read_local_text(self.root)

    def test_rejects_leaf_symlink(self):
        link = self.root / "leaf.json"
        try:
            link.symlink_to(self.file)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink not available on this platform")
        with self.assertRaisesRegex(ValueError, "Symlink"):
            read_local_text(link)

    def test_rejects_parent_directory_symlink(self):
        actual = self.root / "real"
        actual.mkdir()
        (actual / "case.json").write_text('{"x":1}', encoding="utf-8")
        alias = self.root / "alias"
        try:
            alias.symlink_to(actual, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Symlink not available on this platform")
        with self.assertRaisesRegex(ValueError, "Symlink"):
            read_local_json(alias / "case.json")

    def test_rejects_posix_fifo_without_blocking(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("POSIX FIFOs unavailable")
        fifo = self.root / "stream.json"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular"):
            read_local_text(fifo)

    def test_rejects_same_file_via_hardlink(self):
        duplicate = self.root / "same.json"
        try:
            os.link(self.file, duplicate)
        except OSError:
            self.skipTest("Hardlinks unavailable")
        with self.assertRaisesRegex(ValueError, "Duplicate or hardlinked"):
            assert_distinct_input_files([self.file, duplicate])

    def test_distinct_files_stay_distinct(self):
        other = self.root / "other.json"
        other.write_text('{"y":2}', encoding="utf-8")
        self.assertEqual(2, assert_distinct_input_files([self.file, other]))

    def test_path_requires_existing_regular_file(self):
        with self.assertRaises((ValueError, OSError)):
            read_local_json(self.root / "missing.json")

    def test_invalid_bound_must_fail(self):
        with self.assertRaisesRegex(ValueError, "bound"):
            read_local_text(self.file, max_bytes=0)


if __name__ == "__main__":
    unittest.main()
