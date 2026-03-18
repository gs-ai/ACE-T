from __future__ import annotations
import sqlite3
from typing import Any, Dict, Optional, Iterable, Tuple
import json
import time

class Store:
    """
    SQLite-backed event store and working memory.

    Uses your existing db/osint.db by default. Creates tables if missing.
    """
    def __init__(self, sqlite_path: str):
        self.sqlite_path = sqlite_path
        self._init()

    def _conn(self):
        return sqlite3.connect(self.sqlite_path)

    def _init(self):
        with self._conn() as c:
            c.execute("""
            CREATE TABLE IF NOT EXISTS agent_events (
                event_id TEXT PRIMARY KEY,
                ts_utc REAL NOT NULL,
                type TEXT NOT NULL,
                source TEXT NOT NULL,
                parent_id TEXT,
                tags TEXT,
                payload_json TEXT NOT NULL
            );
            """)
            c.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_events_ts ON agent_events(ts_utc);
            """)
            c.execute("""
            CREATE INDEX IF NOT EXISTS idx_agent_events_type ON agent_events(type);
            """)

            c.execute("""
            CREATE TABLE IF NOT EXISTS agent_kv (
                k TEXT PRIMARY KEY,
                v_json TEXT NOT NULL,
                ts_utc REAL NOT NULL
            );
            """)

            c.execute("""
            CREATE TABLE IF NOT EXISTS agent_seen (
                key TEXT PRIMARY KEY,
                ts_utc REAL NOT NULL
            );
            """)

    def put_event(self, ev: Dict[str, Any]) -> bool:
        """
        Insert event; returns False if duplicate (by event_id).
        """
        try:
            with self._conn() as c:
                c.execute("""
                    INSERT INTO agent_events(event_id, ts_utc, type, source, parent_id, tags, payload_json)
                    VALUES(?,?,?,?,?,?,?)
                """, (
                    ev["event_id"], ev["ts_utc"], ev["type"], ev["source"], ev.get("parent_id"),
                    json.dumps(ev.get("tags", []), ensure_ascii=False),
                    json.dumps(ev["payload"], ensure_ascii=False)
                ))
            return True
        except sqlite3.IntegrityError:
            return False

    def seen(self, key: str) -> bool:
        with self._conn() as c:
            row = c.execute("SELECT 1 FROM agent_seen WHERE key=? LIMIT 1", (key,)).fetchone()
            return row is not None

    def mark_seen(self, key: str) -> None:
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO agent_seen(key, ts_utc) VALUES(?,?)", (key, time.time()))

    def kv_get(self, k: str) -> Optional[Dict[str, Any]]:
        with self._conn() as c:
            row = c.execute("SELECT v_json FROM agent_kv WHERE k=? LIMIT 1", (k,)).fetchone()
            if not row:
                return None
            return json.loads(row[0])

    def kv_set(self, k: str, v: Dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO agent_kv(k, v_json, ts_utc) VALUES(?,?,?)",
                      (k, json.dumps(v, ensure_ascii=False), time.time()))
