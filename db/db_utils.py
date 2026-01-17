from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Iterable, Optional

DEFAULT_DB_PATH = Path(__file__).resolve().parent / "osint.db"
DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parent / "schema.sql"

def connect(db_path: Optional[Path] = None) -> sqlite3.Connection:
    db_path = db_path or DEFAULT_DB_PATH
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn

def init_db(conn: sqlite3.Connection, schema_path: Optional[Path] = None) -> None:
    schema_path = schema_path or DEFAULT_SCHEMA_PATH
    schema_sql = schema_path.read_text(encoding="utf-8")
    conn.executescript(schema_sql)
    conn.commit()

def insert_artifact(conn: sqlite3.Connection, kind: str, payload: str, source_path: str = "") -> int:
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO artifacts(kind, source_path, created_at, payload) VALUES(?, ?, datetime('now'), ?)",
        (kind, source_path, payload),
    )
    conn.commit()
    return int(cur.lastrowid)

def query(conn: sqlite3.Connection, sql: str, params: Iterable = ()) -> list[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute(sql, tuple(params))
    return cur.fetchall()
