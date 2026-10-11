"""Bounded read-only local input validation for offline research sidecar CLIs.

POSIX paths are traversed with no-follow directory descriptors and a no-follow
leaf file descriptor. On platforms without dir_fd/no-follow support, reject
observed symlink/junction components but note unavoidable replacement races.
This is local filesystem input hygiene, not sandboxing or source attestation.
"""
from __future__ import annotations

import errno
import json
import os
from pathlib import Path
import stat

MAX_JSON_BYTES = 8 * 1024 * 1024


def _unique_pairs(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("Duplicate local JSON input key")
        obj[key] = value
    return obj


def _no_nonfinite(value):
    raise ValueError("Nonfinite JSON input constant forbidden")


def _open_regular(path):
    """Return a descriptor with no-follow protection wherever supported."""
    target = Path(path).expanduser().absolute()
    pieces = target.parts
    if not pieces:
        raise ValueError("Missing local file path")
    # POSIX: O_NOFOLLOW at every path component + dir_fd prevents a parent
    # directory from being replaced with a symlink between check and open.
    if (os.name == "posix" and hasattr(os, "O_NOFOLLOW")
            and hasattr(os, "O_DIRECTORY")
            and os.open in os.supports_dir_fd):
        root = os.open(pieces[0], os.O_RDONLY | os.O_DIRECTORY)
        try:
            try:
                for part in pieces[1:-1]:
                    next_fd = os.open(
                        part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=root,
                    )
                    os.close(root)
                    root = next_fd
                fd = os.open(
                    pieces[-1],
                    os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=root,
                )
            except OSError as error:
                if error.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ValueError(
                        "Symlinked or non-symlink local file component refused"
                    ) from error
                raise
        finally:
            os.close(root)
    else:
        # Windows-compatible fallback: refuse detected symlinks and
        # junctions, including those on parent directories. It does not
        # eliminate a concurrent malicious reparse-point replacement.
        check = target
        for item in (check, *check.parents):
            junction = getattr(item, "is_junction", None)
            if item.is_symlink() or (junction is not None and junction()):
                raise ValueError("Symlinked/junction local file path refused")
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
                     | getattr(os, "O_NOFOLLOW", 0))
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("Local input must be a regular file")
    return fd


def read_local_text(path, *, max_bytes=MAX_JSON_BYTES):
    """Read a stable, bounded local UTF-8 file, without newline translation."""
    if type(max_bytes) is not int or not 0 < max_bytes <= MAX_JSON_BYTES:
        raise ValueError("Invalid local input bound")
    fd = _open_regular(path)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not 0 < before.st_size <= max_bytes:
            raise ValueError("Empty or oversized local input file")
        raw = stream.read(max_bytes + 1)
        after = os.fstat(stream.fileno())
        if (not 0 < len(raw) <= max_bytes
                or len(raw) != before.st_size
                or before.st_size != after.st_size
                or before.st_mtime_ns != after.st_mtime_ns
                or before.st_ctime_ns != after.st_ctime_ns
                or before.st_ino != after.st_ino):
            raise ValueError("Local input changed during bounded read")
    return raw.decode("utf-8", errors="strict")


def read_local_json(path, *, max_bytes=MAX_JSON_BYTES):
    record = json.loads(
        read_local_text(path, max_bytes=max_bytes),
        object_pairs_hook=_unique_pairs,
        parse_constant=_no_nonfinite,
    )
    if type(record) is not dict:
        raise ValueError("Local JSON root must be an object")
    return record


def assert_distinct_input_files(paths):
    """Reject same resolved paths and hard-linked local input arguments."""
    identities = set()
    for path in paths:
        target = Path(path).expanduser().absolute()
        # Inspect a descriptor rather than following symlinks in a preflight
        # stat. Actual reads reopen with identical no-follow requirements.
        fd = _open_regular(target)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            identity = (info.st_dev, info.st_ino)
        if identity in identities:
            raise ValueError("Duplicate or hardlinked sidecar input files")
        identities.add(identity)
    return len(identities)
