PRAGMA foreign_keys = ON;

-- OAuth 2.1 authorization server for MCP connectors (Claude, ChatGPT, ...);
-- see docs/MCP_CONNECTOR.md. Clients register themselves (RFC 7591) and are
-- public (PKCE only, no secret). The access token they receive is a regular
-- API key, minted at the token exchange so its plaintext is never stored.
CREATE TABLE IF NOT EXISTS oauth_clients (
  id TEXT PRIMARY KEY,
  client_name TEXT,
  redirect_uris_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  -- Set when a code is first issued; unused registrations are swept.
  last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  approved_session_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  resource TEXT,
  -- API key label chosen on the consent page.
  label TEXT NOT NULL,
  -- PENDING -> USED (single use).
  status TEXT NOT NULL,
  api_key_id TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_oauth_authorization_codes_expires
  ON oauth_authorization_codes(expires_at);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_unused
  ON oauth_clients(created_at) WHERE last_used_at IS NULL;
