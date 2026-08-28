PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS email_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  approval_expires_at TEXT NOT NULL,
  last_activity_at TEXT,
  consent_hint TEXT
);

CREATE INDEX IF NOT EXISTS idx_email_sessions_user_status
  ON email_sessions(user_id, status, approval_expires_at);

CREATE INDEX IF NOT EXISTS idx_email_sessions_api_key
  ON email_sessions(api_key_id, status);
