#!/usr/bin/env python3
"""Read-only heuristic preflight of a local source folder before GitHub import.

Prints relative paths and risk *categories*, never secret contents or remote URLs.
No network calls. Not a replacement for comprehensive secret/history review.
"""

import argparse
import collections
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SKIP_DIRS = {
    ".git", ".venv", "venv", "env", "node_modules", "__pycache__",
    ".pytest_cache", ".mypy_cache", ".ruff_cache", "build", "dist",
}
SENSITIVE_DIRS = {".aws", ".ssh", "secrets", "private"}
SENSITIVE_NAMES = {
    "credentials", "credentials.json", "service_account.json",
    "id_rsa", "id_ed25519", ".npmrc", ".pypirc",
}
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx")
PATTERNS = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"
    )),
    ("private_key_block", re.compile(
        r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----"
    )),
    ("credential_assignment", re.compile(
        r"(?im)^\s*(?:AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|OTX_API_KEY|"
        r"GITHUB_TOKEN|CLIENT_SECRET|DATABASE_URL|DB_PASSWORD)\s*[:=]\s*\S{8,}"
    )),
)


def filename_flags(name):
    """Filename-only suspicious indicators."""
    lower = name.lower()
    flags = []
    if lower == ".env" or (lower.startswith(".env.") and lower != ".env.example"):
        flags.append("environment_secret_filename")
    if lower in SENSITIVE_NAMES or lower.endswith(SENSITIVE_SUFFIXES):
        flags.append("credential_or_private_key_filename")
    return flags


def git_metadata(root):
    """Avoid printing remote URLs (which can embed tokens)."""
    def run(*args):
        try:
            result = subprocess.run(
                ["git", "-C", str(root), *args],
                capture_output=True, text=True, timeout=8, check=False,
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None

    top = run("rev-parse", "--show-toplevel")
    if not top or Path(top).resolve() != root.resolve():
        return {"is_git_root": False}
    status = run("status", "--porcelain")
    count = run("rev-list", "--count", "HEAD")
    return {
        "is_git_root": True,
        "branch": run("branch", "--show-current"),
        "dirty_worktree": bool(status) if status is not None else None,
        "local_commit_count": int(count) if count and count.isdigit() else None,
    }


def inspect_tree(root, max_files=20000, max_file_bytes=1024 * 1024):
    """Return metadata and flags. Never copy, mutate, or upload input content."""
    root = Path(root).expanduser().resolve()
    if not root.is_dir():
        raise ValueError("Path is not an existing directory")

    findings = []
    summary = {
        "root": str(root),
        "read_only": True,
        "files_seen": 0,
        "text_files_scanned": 0,
        "skipped_large_or_binary": 0,
        "by_extension": {},
        "findings": findings,
        "warnings": [],
        "git": git_metadata(root),
    }
    extensions = collections.Counter()
    stopped = False

    for base, dirs, names in os.walk(root, followlinks=False):
        dirs.sort()
        names.sort()
        for d in list(dirs):
            path = Path(base) / d
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                findings.append({"path": rel, "reasons": ["directory_symlink_review"]})
                dirs.remove(d)
            elif d.lower() in SENSITIVE_DIRS:
                findings.append({"path": rel + "/", "reasons": ["sensitive_directory"]})
                dirs.remove(d)
            elif d in SKIP_DIRS:
                dirs.remove(d)

        for name in names:
            if summary["files_seen"] >= max_files:
                summary["warnings"].append("file_limit_reached_not_all_files_checked")
                stopped = True
                break

            path = Path(base) / name
            rel = path.relative_to(root).as_posix()
            summary["files_seen"] += 1
            extensions[path.suffix.lower() or "<none>"] += 1
            flags = filename_flags(name)

            if path.is_symlink():
                flags.append("file_symlink_review")
            elif path.is_file():
                try:
                    if path.stat().st_size > max_file_bytes:
                        summary["skipped_large_or_binary"] += 1
                        flags.append("large_file_not_content_scanned")
                    else:
                        raw = path.read_bytes()
                        if b"\x00" in raw:
                            summary["skipped_large_or_binary"] += 1
                        else:
                            text_body = raw.decode("utf-8", errors="replace")
                            summary["text_files_scanned"] += 1
                            for label, pattern in PATTERNS:
                                if pattern.search(text_body):
                                    flags.append(label)
                except OSError:
                    flags.append("unreadable_file")
            else:
                flags.append("unreadable_or_special_file")

            if flags:
                findings.append({"path": rel, "reasons": sorted(set(flags))})
        if stopped:
            break

    summary["by_extension"] = dict(sorted(extensions.items()))
    summary["needs_manual_review"] = bool(findings or summary["warnings"])
    summary["notes"] = [
        "Heuristic only: false positives and false negatives are possible.",
        "Skipped content and ALL historical Git commits require separate review.",
        "No file contents, token values, or Git remote URLs are printed or sent.",
        "Never commit private keys, token files, or restricted CTI source documents.",
    ]
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default=".", help="Local project path")
    parser.add_argument("--max-files", type=int, default=20000)
    parser.add_argument("--max-file-bytes", type=int, default=1024 * 1024)
    args = parser.parse_args(argv)
    if args.max_files < 1 or args.max_file_bytes < 1:
        parser.error("limits must be positive")

    try:
        report = inspect_tree(args.path, args.max_files, args.max_file_bytes)
    except (ValueError, OSError) as exc:
        print(json.dumps({"status": "error", "message": str(exc)}))
        return 1
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 2 if report["needs_manual_review"] else 0


if __name__ == "__main__":
    sys.exit(main())
