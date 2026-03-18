-- schema.sql
-- Auto-generated placeholder.

CREATE TABLE IF NOT EXISTS artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT NOT NULL,
  source_path TEXT,
  created_at TEXT NOT NULL,
  payload TEXT
);
