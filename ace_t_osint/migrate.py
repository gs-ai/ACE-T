from __future__ import annotations

import sqlite3
from pathlib import Path

from .writers.sqlite_writer import SCHEMA, INDEXES


def migrate(db_path: str = "data/osint.db") -> None:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        for ddl in SCHEMA.values():
            conn.execute(ddl)
        for idx in INDEXES:
            conn.execute(idx)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    migrate()
