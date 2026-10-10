#!/usr/bin/env python3
"""Run a real scanner against Git-tracked content; refuse new detectable secrets.

Uses detect-secrets; no own homegrown regex claiming full coverage. No baseline
allowlist is used. Fail closed on unavailable scanner, malformed JSON or any
finding, without printing matched token values in stdout/stderr.
"""
from __future__ import annotations

import json
import subprocess
import sys


def summarize_findings(report: str) -> tuple[int, int]:
    try:
        payload = json.loads(report)
    except (ValueError, TypeError) as exc:
        raise ValueError("Secret scanner did not produce valid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), dict):
        raise ValueError("Secret scanner result contract invalid")
    total_files, total_findings = 0, 0
    for path, findings in payload["results"].items():
        if not isinstance(path, str) or not isinstance(findings, list):
            raise ValueError("Secret scanner finding structure is invalid")
        if findings:
            total_files += 1
            total_findings += len(findings)
    return total_files, total_findings


def finding_locations(report: str) -> list[tuple[str, str]]:
    """Return only tracked path and detector category; never secret material."""
    payload = json.loads(report)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), dict):
        raise ValueError("Invalid secret scanner report")
    locations: list[tuple[str, str]] = []
    for path, findings in payload["results"].items():
        if not isinstance(path, str) or not isinstance(findings, list):
            raise ValueError("Invalid scanner findings")
        for item in findings:
            if not isinstance(item, dict):
                raise ValueError("Invalid scanner finding")
            detector = item.get("type", "unspecified")
            if not isinstance(detector, str):
                raise ValueError("Invalid scanner detector")
            locations.append((path, detector))
    return locations


def main() -> int:
    try:
        process = subprocess.run(
            ["detect-secrets", "scan"],
            capture_output=True, text=True, check=False, timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired):
        print("Secret scan failed or timed out; refusing merge", file=sys.stderr)
        return 2
    if process.returncode:
        print("Secret scanner returned an error; refusing merge", file=sys.stderr)
        return 2
    try:
        files, findings = summarize_findings(process.stdout)
    except ValueError as exc:
        print(f"Secret scan refused: {exc}", file=sys.stderr)
        return 2
    if findings:
        # No secret excerpts printed. Look at local audit output for investigation.
        print(f"Secret scan flagged {findings} potential secret(s) in {files} file(s)", file=sys.stderr)
        for path, detector in finding_locations(process.stdout):
            print(f"Review tracked file: {path} (detector: {detector})", file=sys.stderr)
        return 1
    print("Tracked-content secret scan: no findings")
    return 0


if __name__ == "__main__":
    sys.exit(main())
