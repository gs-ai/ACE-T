from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from db.db_utils import connect


def _ensure_iocs_table(conn) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ioc_hash TEXT NOT NULL UNIQUE,
            indicator TEXT NOT NULL,
            ioc_type TEXT NOT NULL,
            source_feed TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            confidence INTEGER DEFAULT 50,
            severity TEXT NOT NULL,
            ioc_metadata JSON,
            tags JSON
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_indicator_type ON iocs(indicator, ioc_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_severity_feed ON iocs(severity, source_feed)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_last_seen ON iocs(last_seen)")
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


def write_iocs(iocs: Iterable[Dict[str, Any]], db_path: Optional[Path] = None) -> int:
    conn = connect(db_path)
    _ensure_iocs_table(conn)
    try:
        days = int(os.getenv("ACE_T_RETENTION_DAYS") or "30")
    except Exception:
        days = 30
    conn.execute("DELETE FROM iocs WHERE last_seen < datetime('now', ?)", (f"-{days} days",))
    rows = []
    for ioc in iocs:
        ioc_hash = ioc.get("ioc_hash")
        if not ioc_hash:
            continue
        indicator = str(ioc.get("indicator") or "").strip()
        ioc_type = str(ioc.get("ioc_type") or "").strip()
        source_feed = str(ioc.get("source_feed") or "").strip()
        if not indicator or not ioc_type or not source_feed:
            continue
        first_seen = _isoformat(ioc.get("first_seen"))
        last_seen = _isoformat(ioc.get("last_seen") or ioc.get("first_seen"))
        confidence = int(float(ioc.get("confidence", 50)))
        severity = str(ioc.get("severity") or "medium").lower()
        metadata = json.dumps(ioc.get("metadata") or {}, default=str)
        tags = json.dumps(ioc.get("tags") or [], default=str)
        rows.append(
            (
                ioc_hash,
                indicator,
                ioc_type,
                source_feed,
                first_seen,
                last_seen,
                confidence,
                severity,
                metadata,
                tags,
            )
        )
    if not rows:
        conn.close()
        return 0
    conn.executemany(
        """
        INSERT OR IGNORE INTO iocs
        (ioc_hash, indicator, ioc_type, source_feed, first_seen, last_seen, confidence, severity, ioc_metadata, tags)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        rows,
    )
    conn.commit()
    conn.close()
    return len(rows)
