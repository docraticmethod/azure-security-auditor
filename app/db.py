"""SQLite persistence for scans and findings.

Only the API layer imports this module — the dashboard reaches data through the
API, never the DB directly (strict API-first).
"""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from app.rules import Finding

def db_path() -> Path:
    """Resolve the DB path at call time so AUDITOR_DB can be set after import."""
    return Path(os.getenv("AUDITOR_DB", "auditor.db"))


_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT    NOT NULL,
    created_at  TEXT    NOT NULL,
    total       INTEGER NOT NULL DEFAULT 0,
    critical    INTEGER NOT NULL DEFAULT 0,
    high        INTEGER NOT NULL DEFAULT 0,
    medium      INTEGER NOT NULL DEFAULT 0,
    low         INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    rule_id     TEXT    NOT NULL,
    title       TEXT    NOT NULL,
    severity    TEXT    NOT NULL,
    resource    TEXT    NOT NULL,
    file        TEXT    NOT NULL,
    detail      TEXT    NOT NULL,
    remediation TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
"""


@contextmanager
def _connect():
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    """Create tables if absent. Idempotent — safe to call on every write path."""
    with _connect() as conn:
        conn.executescript(_SCHEMA)


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def save_scan(target: str, findings: list[Finding]) -> int:
    """Persist a scan and its findings; return the new scan id."""
    init_db()
    counts = _severity_counts(findings)
    created_at = datetime.now(timezone.utc).isoformat()
    with _connect() as conn:
        cur = conn.execute(
            """INSERT INTO scans (target, created_at, total, critical, high, medium, low)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                target,
                created_at,
                len(findings),
                counts["CRITICAL"],
                counts["HIGH"],
                counts["MEDIUM"],
                counts["LOW"],
            ),
        )
        scan_id = cur.lastrowid
        conn.executemany(
            """INSERT INTO findings
               (scan_id, rule_id, title, severity, resource, file, detail, remediation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    scan_id,
                    f.rule_id,
                    f.title,
                    f.severity.value,
                    f.resource,
                    f.file,
                    f.detail,
                    f.remediation,
                )
                for f in findings
            ],
        )
    return scan_id


def list_scans(limit: int = 50) -> list[dict]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: int) -> dict | None:
    with _connect() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    return dict(row) if row else None


def get_findings(scan_id: int | None = None, severity: str | None = None) -> list[dict]:
    query = "SELECT * FROM findings"
    clauses, params = [], []
    if scan_id is not None:
        clauses.append("scan_id = ?")
        params.append(scan_id)
    if severity is not None:
        clauses.append("severity = ?")
        params.append(severity.upper())
    if clauses:
        query += " WHERE " + " AND ".join(clauses)
    query += " ORDER BY id DESC"
    with _connect() as conn:
        rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]
