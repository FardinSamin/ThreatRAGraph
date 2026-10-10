"""Fail-closed SQLite schema compatibility for persistent sourced CTI ledgers.

Before opening an existing ledger for writes, validate exact column order,
types and constraints from PRAGMA metadata. CREATE TABLE IF NOT EXISTS alone
does not migrate a legacy table. Never silently upgrade evidence to 'aligned'.
Existing unknown versions must be explicitly reviewed and rebuilt.
"""
from __future__ import annotations

import sqlite3

LEDGER_VERSION = 1

EXPECTED = {
    "source_versions": [
        ("source_version_id", "TEXT", 0, 1),
        ("source_id", "TEXT", 1, 0),
        ("sha256", "TEXT", 1, 0),
        ("available_at", "TEXT", 1, 0),
        ("date_evidence", "TEXT", 1, 0),
    ],
    "sourced_claims": [
        ("claim_id", "TEXT", 0, 1),
        ("source_version_id", "TEXT", 1, 0),
        ("subject_id", "TEXT", 1, 0),
        ("predicate", "TEXT", 1, 0),
        ("object_id", "TEXT", 1, 0),
        ("assertion_kind", "TEXT", 1, 0),
        ("polarity", "TEXT", 1, 0),
        ("evidence_locator", "TEXT", 1, 0),
        ("evidence_sha256", "TEXT", 1, 0),
        ("extractor_version", "TEXT", 1, 0),
        ("evidence_status", "TEXT", 1, 0),
    ],
    "semantic_reviews": [
        ("review_id", "TEXT", 0, 1),
        ("claim_id", "TEXT", 1, 0),
        ("source_version_id", "TEXT", 1, 0),
        ("evidence_sha256", "TEXT", 1, 0),
        ("decision", "TEXT", 1, 0),
        ("reviewer_id", "TEXT", 1, 0),
        ("reviewed_at", "TEXT", 1, 0),
        ("rationale", "TEXT", 1, 0),
        ("review_schema_version", "TEXT", 1, 0),
    ],
}


def check_schema(conn: sqlite3.Connection, tables: tuple[str, ...]) -> None:
    """Validate all pre-existing requested tables; never modify before refusal."""
    if not isinstance(conn, sqlite3.Connection):
        raise ValueError("SQLite connection required")
    version = conn.execute("PRAGMA user_version").fetchone()[0]
    if version not in (0, LEDGER_VERSION):
        raise ValueError("Unsupported SQLite schema version; manual migration required")
    states = {}
    for table in tables:
        if table not in EXPECTED:
            raise ValueError("Unsupported SQLite schema table")
        item = conn.execute(
            "SELECT type FROM sqlite_master WHERE name=?", (table,)
        ).fetchone()
        if item is None:
            states[table] = "absent"
            continue
        if item[0] != "table":
            raise ValueError("Expected SQLite table, found different object")
        actual = [
            (row[1], row[2].upper(), row[3], row[5])
            for row in conn.execute(f"PRAGMA table_info({table})")
        ]
        if actual != EXPECTED[table]:
            raise ValueError(
                f"Incompatible {table} SQLite schema; rebuild from immutable sources "
                "or use a separately reviewed, explicit migration"
            )
        states[table] = "existing"
    # A half-built persistent database is not safely equivalent to a fresh DB.
    if len(tables) > 1 and set(states.values()) == {"absent", "existing"}:
        raise ValueError("Partial ledger schema; explicit repair required")
    # The semantic-review extension may legitimately be added to a valid
    # core v1 ledger on first use; its absence is not a core table migration.
    if (version == LEDGER_VERSION and
            tables != ("semantic_reviews",) and
            any(v == "absent" for v in states.values())):
        raise ValueError("Missing core table from versioned ledger")


def stamp_schema(conn: sqlite3.Connection) -> None:
    """Only called after all expected core ledger tables were successfully created."""
    conn.execute(f"PRAGMA user_version = {LEDGER_VERSION}")
