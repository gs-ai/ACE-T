from __future__ import annotations

import hashlib
import sqlite3
import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from db.db_utils import connect


def _ensure_alerts_table(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content_hash VARCHAR NOT NULL,
            simhash VARCHAR,
            source_name VARCHAR NOT NULL,
            detected_at VARCHAR NOT NULL,
            first_seen VARCHAR,
            last_seen VARCHAR,
            payload JSON
        )
        """
    )
    try:
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_content_hash ON alerts(content_hash)"
        )
    except sqlite3.IntegrityError:
        conn.execute(
            """
            DELETE FROM alerts
            WHERE id NOT IN (
                SELECT MAX(id) FROM alerts GROUP BY content_hash
            )
            """
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_content_hash ON alerts(content_hash)"
        )
    conn.commit()


def _isoformat(value: Optional[float | int | str]) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc).isoformat()
    text = str(value).strip()
    if not text:
        return datetime.now(timezone.utc).isoformat()
    return text


def _hash_payload(payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def write_alerts(
    alerts: Iterable[Dict[str, Any]],
    db_path: Optional[Path] = None,
) -> int:
    conn = connect(db_path)
    _ensure_alerts_table(conn)
    try:
        days = int(os.getenv("ACE_T_RETENTION_DAYS") or "30")
    except Exception:
        days = 30
    conn.execute("DELETE FROM alerts WHERE detected_at < datetime('now', ?)", (f"-{days} days",))
    rows: List[tuple] = []
    for alert in alerts:
        payload = alert.get("payload") or {}
        content_hash = alert.get("content_hash") or _hash_payload(payload)
        detected_at = _isoformat(alert.get("detected_at"))
        rows.append(
            (
                content_hash,
                alert.get("simhash"),
                alert.get("source_name", "unknown"),
                detected_at,
                alert.get("first_seen"),
                alert.get("last_seen"),
                json.dumps(payload, default=str),
            )
        )
    if not rows:
        return 0
    conn.executemany(
        """
        INSERT OR IGNORE INTO alerts
        (content_hash, simhash, source_name, detected_at, first_seen, last_seen, payload)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    conn.close()
    return len(rows)
