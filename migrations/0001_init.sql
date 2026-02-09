PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS schema_migrations (
  id TEXT PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  telegram_user_id INTEGER NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  label TEXT NOT NULL,
  key_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revoked_at TEXT,
  last_used_at TEXT,
  UNIQUE(user_id, label)
);

CREATE TABLE IF NOT EXISTS linked_accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  provider_user_id TEXT NOT NULL,
  scopes TEXT NOT NULL,
  refresh_token_ciphertext BLOB NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_linked_accounts_user_provider_status
  ON linked_accounts(user_id, provider, status);

CREATE TABLE IF NOT EXISTS oauth_states (
  state TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  pkce_verifier TEXT
);

CREATE TABLE IF NOT EXISTS proxy_requests (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  api_key_label_snapshot TEXT NOT NULL,
  upstream_url TEXT NOT NULL,
  request_hash TEXT NOT NULL,
  consent_hint TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  approval_expires_at TEXT NOT NULL,
  idempotency_key TEXT,
  upstream_http_status INTEGER,
  upstream_content_type TEXT,
  upstream_bytes INTEGER,
  result_state TEXT NOT NULL,
  error_code TEXT,
  error_message TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uidx_proxy_requests_idempotency
  ON proxy_requests(api_key_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_proxy_requests_status_expires
  ON proxy_requests(status, approval_expires_at);

CREATE INDEX IF NOT EXISTS idx_proxy_requests_user_created
  ON proxy_requests(user_id, created_at);

CREATE TABLE IF NOT EXISTS approvals (
  request_id TEXT PRIMARY KEY REFERENCES proxy_requests(id) ON DELETE CASCADE,
  telegram_chat_id INTEGER NOT NULL,
  telegram_message_id INTEGER NOT NULL,
  decision TEXT NOT NULL,
  decided_at TEXT NOT NULL,
  decided_by_telegram_user_id INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  user_id TEXT,
  request_id TEXT,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  event_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_events_user_created
  ON audit_events(user_id, created_at);

CREATE TABLE IF NOT EXISTS telegram_state (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  last_update_id INTEGER NOT NULL
);

INSERT OR IGNORE INTO telegram_state (id, last_update_id) VALUES (1, 0);
