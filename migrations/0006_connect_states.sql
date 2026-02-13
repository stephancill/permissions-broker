PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS connect_states (
  state TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_connect_states_user_provider_expires
  ON connect_states(user_id, provider, expires_at);
