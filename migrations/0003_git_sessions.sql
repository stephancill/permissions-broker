PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS git_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  operation TEXT NOT NULL,
  repo_owner TEXT NOT NULL,
  repo_name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  approval_expires_at TEXT NOT NULL,
  last_activity_at TEXT,
  session_secret_hash TEXT NOT NULL,
  allow_default_branch_push INTEGER NOT NULL,
  deny_deletes INTEGER NOT NULL,
  deny_tag_updates INTEGER NOT NULL,
  default_branch_ref TEXT,
  error_code TEXT,
  error_message TEXT
);

CREATE INDEX IF NOT EXISTS idx_git_sessions_user_status
  ON git_sessions(user_id, status, approval_expires_at);

CREATE INDEX IF NOT EXISTS idx_git_sessions_api_key
  ON git_sessions(api_key_id, status);
