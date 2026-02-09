PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS telegram_pending_inputs (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  target_id TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
