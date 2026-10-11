"""Atomic per-file, content-addressed offline artifact publishing.

Stage/fsync privately, then create the final SHA-256 filename via an atomic
no-replace hard link. Never expose a partly written *final* artifact.
On POSIX, output path traversal uses directory descriptors + O_NOFOLLOW.
On Windows the fallback checks symlink/junction ancestors but is not a
security boundary against malicious concurrent directory replacements.
Multi-file batches are NOT transactions; orphan staging files from abrupt
process termination require separate operator cleanup.
"""
from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path
import secrets
import stat
import time

MAX_OUTPUT_BYTES = 64 * 1024 * 1024
EXTENSIONS = frozenset({".json", ".csv"})


def _directory_root(destination):
    root = Path(destination).expanduser().absolute()
    if ".." in root.parts:
        raise ValueError("Output directory cannot contain parent traversal")
    return root


def _posix_dir_fd(root):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(root.anchor, flags)
    try:
        for part in root.parts[1:]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except OSError as error:
        os.close(fd)
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ValueError("Linked or non-directory output path refused") from error
        raise
    except BaseException:
        os.close(fd)
        raise


def _fallback_root(root):
    for ancestor in (root, *root.parents):
        junction = getattr(ancestor, "is_junction", None)
        if ancestor.is_symlink() or (junction is not None and junction()):
            raise ValueError("Linked output directory ancestor refused")
    root.mkdir(parents=True, exist_ok=True)
    for ancestor in (root, *root.parents):
        junction = getattr(ancestor, "is_junction", None)
        if ancestor.is_symlink() or (junction is not None and junction()):
            raise ValueError("Linked output directory ancestor refused")
    if not root.is_dir():
        raise ValueError("Output root must be a directory")


def _verify_existing(root, name, data, *, dir_fd):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    try:
        if dir_fd is None:
            file = root / name
            junction = getattr(file, "is_junction", None)
            if file.is_symlink() or (junction is not None and junction()):
                raise ValueError("Symlinked destination artifact refused")
            fd = os.open(file, flags)
        else:
            fd = os.open(name, flags, dir_fd=dir_fd)
    except FileNotFoundError:
        return False
    except OSError as error:
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise ValueError("Linked digest-named output artifact refused") from error
        raise
    try:
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            # Another writer may have published the destination with an
            # atomic hard link but not yet removed its private stage name.
            # Wait briefly for that link to disappear; never accept a
            # persistently hardlinked mutable destination.
            for _ in range(10):
                if info.st_nlink <= 1:
                    break
                time.sleep(0.005)
                info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_size != len(data)):
                raise ValueError("Destination is not an exact standalone artifact")
            recorded = stream.read(len(data) + 1)
            latest = os.fstat(stream.fileno())
            if (recorded != data or latest.st_size != info.st_size
                    or latest.st_mtime_ns != info.st_mtime_ns):
                raise ValueError("Existing digest-named artifact bytes differ")
    except BaseException:
        raise
    return True


def _commit_staged(root, name, data, *, dir_fd):
    temporary = ".stage-" + secrets.token_hex(16) + ".partial"
    tmp_path = root / temporary
    final_path = root / name
    if dir_fd is None:
        fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_BINARY", 0), 0o600)
    else:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | os.O_NOFOLLOW, 0o600, dir_fd=dir_fd)
    created = False
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            if dir_fd is None:
                os.link(tmp_path, final_path)
            else:
                os.link(
                    temporary, name, src_dir_fd=dir_fd,
                    dst_dir_fd=dir_fd, follow_symlinks=False,
                )
            created = True
        except FileExistsError:
            if not _verify_existing(root, name, data, dir_fd=dir_fd):
                raise ValueError("Conflicting content-addressed artifact")
    finally:
        try:
            if dir_fd is None:
                tmp_path.unlink(missing_ok=True)
            else:
                os.unlink(temporary, dir_fd=dir_fd)
        except FileNotFoundError:
            pass
    if dir_fd is not None:
        os.fsync(dir_fd)
    return created


def write_immutable_bytes(data, output_root, extension):
    """Return digest, final Path, newly_created; never rewrite an existing file."""
    if type(data) is not bytes or not 0 < len(data) <= MAX_OUTPUT_BYTES:
        raise ValueError("Nonempty bounded artifact bytes required")
    if extension not in EXTENSIONS:
        raise ValueError("Unsupported immutable artifact suffix")
    root = _directory_root(output_root)
    digest = hashlib.sha256(data).hexdigest()
    name = digest + extension
    fd = None
    posix = (os.name == "posix" and hasattr(os, "O_NOFOLLOW")
             and hasattr(os, "O_DIRECTORY")
             and os.open in os.supports_dir_fd
             and os.mkdir in os.supports_dir_fd
             and os.link in os.supports_dir_fd
             and os.unlink in os.supports_dir_fd)
    if posix:
        fd = _posix_dir_fd(root)
    else:
        _fallback_root(root)
    try:
        if _verify_existing(root, name, data, dir_fd=fd):
            return digest, root / name, False
        created = _commit_staged(root, name, data, dir_fd=fd)
        return digest, root / name, created
    finally:
        if fd is not None:
            os.close(fd)
