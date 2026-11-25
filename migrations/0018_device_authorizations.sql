PRAGMA foreign_keys = ON;

-- OAuth 2.0 Device Authorization Grant (RFC 8628): a CLI asks for a code, the
-- user confirms it in the app, and the CLI's next poll receives a new API key
-- (docs/DEVICE_AUTHORIZATION.md). The key is minted at that poll, so its
-- plaintext is never stored.
CREATE TABLE IF NOT EXISTS device_authorizations (
  id TEXT PRIMARY KEY,
  device_code_hash TEXT NOT NULL UNIQUE,
  user_code TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  -- Suggested by the client; the user confirms or edits it before approving.
  label_hint TEXT,
  -- PENDING -> APPROVED -> CONSUMED, or PENDING -> DENIED.
  status TEXT NOT NULL,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  label TEXT,
  approved_session_id TEXT,
  api_key_id TEXT,
  interval_seconds INTEGER NOT NULL,
  last_polled_at TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_device_authorizations_expires
  ON device_authorizations(expires_at);
