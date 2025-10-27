from __future__ import annotations

import json
import logging
import sqlite3
from pathlib import Path
from typing import Dict, Iterable

from ..utils.time import format_ts

logger = logging.getLogger(__name__)


SCHEMA = {
    "alerts": """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content_hash TEXT NOT NULL,
            simhash TEXT,
            source_name TEXT NOT NULL,
            detected_at TEXT NOT NULL,
            first_seen TEXT,
            last_seen TEXT,
            payload JSON,
            UNIQUE(content_hash, source_name)
        );
    """,
    "seen": """
        CREATE TABLE IF NOT EXISTS seen (
            source_name TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            PRIMARY KEY (source_name, fingerprint)
        );
    """,
    "runs": """
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT,
            started_at TEXT,
            finished_at TEXT,
            status TEXT,
            metrics JSON
        );
    """,
    "errors": """
        CREATE TABLE IF NOT EXISTS errors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_name TEXT,
            url TEXT,
            error TEXT,
            stack TEXT,
            retry_at TEXT
        );
    """,
}

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts(source_name);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON alerts(detected_at);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_content_hash ON alerts(content_hash);",
]


class SQLiteWriter:
    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.execute("PRAGMA journal_mode=WAL;")
        self.conn.execute("PRAGMA synchronous=NORMAL;")
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        for ddl in SCHEMA.values():
            self.conn.execute(ddl)
        for idx in INDEXES:
            self.conn.execute(idx)
        self.conn.commit()

    def write_alert(self, alert: Dict) -> None:
        payload = json.dumps(alert)
        self.conn.execute(
            """
            INSERT INTO alerts (content_hash, simhash, source_name, detected_at, first_seen, last_seen, payload)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(content_hash, source_name) DO UPDATE SET last_seen=excluded.last_seen
            """,
            (
                alert["content_hash"],
                alert.get("simhash"),
                alert["source_name"],
                alert["detected_at"],
                alert.get("first_seen"),
                alert.get("last_seen"),
                payload,
            ),
        )
        self.conn.commit()

    def update_seen(self, source: str, fingerprint: str) -> None:
        self.conn.execute(
            """
            INSERT INTO seen (source_name, fingerprint, last_seen)
            VALUES (?, ?, ?)
            ON CONFLICT(source_name, fingerprint) DO UPDATE SET last_seen=excluded.last_seen
            """,
            (source, fingerprint, format_ts()),
        )
        self.conn.commit()

    def record_run(self, source: str, status: str, metrics: Dict) -> None:
        self.conn.execute(
            """
            INSERT INTO runs (source_name, started_at, finished_at, status, metrics)
            VALUES (?, ?, ?, ?, ?)
            """,
            (source, metrics.get("started_at"), metrics.get("finished_at"), status, json.dumps(metrics)),
        )
        self.conn.commit()

    def fetch_last_run_metrics(self, source: str) -> Dict:
        cursor = self.conn.execute(
            "SELECT metrics FROM runs WHERE source_name = ? ORDER BY id DESC LIMIT 1",
            (source,),
        )
        row = cursor.fetchone()
        if not row or not row[0]:
            return {}
        try:
            return json.loads(row[0])
        except json.JSONDecodeError:
            return {}

    def record_error(self, source: str, url: str, error: str, stack: str, retry_at: str | None = None) -> None:
        self.conn.execute(
            """
            INSERT INTO errors (source_name, url, error, stack, retry_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (source, url, error, stack, retry_at),
        )
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()


__all__ = ["SQLiteWriter", "SCHEMA", "INDEXES"]
