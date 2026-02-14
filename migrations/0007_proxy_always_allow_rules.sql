PRAGMA foreign_keys = ON;

-- Permanently allow requests for a specific upstream endpoint (method + host + path) for a user.
-- These rules are created via Telegram approval UI ("Always allow").

-- Track the caller's IP for proxy requests so the Telegram approval UI can create
-- an always-allow rule scoped to a specific key/IP pair.
ALTER TABLE proxy_requests ADD COLUMN requester_ip TEXT;

CREATE TABLE IF NOT EXISTS proxy_always_allow_rules (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  requester_ip TEXT NOT NULL,
  method TEXT NOT NULL,
  upstream_host TEXT NOT NULL,
  upstream_path TEXT NOT NULL,
  created_at TEXT NOT NULL,
  revoked_at TEXT
);

-- One rule per endpoint per user + api key + requester IP.
-- (If revoked_at is set, re-enabling should UPDATE the same row.)
CREATE UNIQUE INDEX IF NOT EXISTS uidx_proxy_always_allow_rules_scope_endpoint
  ON proxy_always_allow_rules(user_id, api_key_id, requester_ip, method, upstream_host, upstream_path);

CREATE INDEX IF NOT EXISTS idx_proxy_always_allow_rules_user
  ON proxy_always_allow_rules(user_id, created_at);
