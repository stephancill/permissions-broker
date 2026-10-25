PRAGMA foreign_keys = ON;

-- Passkey-gated credential encryption. See docs/PASSKEY_CREDENTIAL_ENCRYPTION.md.

-- One passkey per user (re-enrolling replaces it).
CREATE TABLE IF NOT EXISTS user_passkeys (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key BLOB NOT NULL,
  sign_count INTEGER NOT NULL,
  transports TEXT,
  prf_salt TEXT NOT NULL,
  created_at TEXT NOT NULL
);

-- Per-user ECDH P-256 keypair. The private key is only stored wrapped under the
-- passkey-derived KEK; the server never sees it in plaintext.
CREATE TABLE IF NOT EXISTS user_keys (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  public_key BLOB NOT NULL,
  wrapped_private_key BLOB NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

-- enc_version 0: legacy APP_SECRET ciphertext (migrated on passkey enrollment).
-- enc_version 1: ECIES to the user's public key; credential_epk holds the
-- ephemeral public key. metadata_json holds non-secret display metadata.
ALTER TABLE linked_accounts ADD COLUMN enc_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE linked_accounts ADD COLUMN credential_epk BLOB;
ALTER TABLE linked_accounts ADD COLUMN metadata_json TEXT;

-- A grant is an approval-released DEK for one linked credential, encrypted with
-- APP_SECRET, scoped to one approval target and wiped on use/expiry.
CREATE TABLE IF NOT EXISTS credential_grants (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  linked_account_id TEXT NOT NULL REFERENCES linked_accounts(id) ON DELETE CASCADE,
  target_kind TEXT NOT NULL,
  target_id TEXT NOT NULL,
  dek_ciphertext BLOB NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_credential_grants_target
  ON credential_grants(target_kind, target_id);

CREATE INDEX IF NOT EXISTS idx_credential_grants_account
  ON credential_grants(linked_account_id);

CREATE INDEX IF NOT EXISTS idx_credential_grants_expires
  ON credential_grants(expires_at);

-- Proxy requests auto-approved by an approval window reuse the window's grant.
ALTER TABLE proxy_requests ADD COLUMN grant_id TEXT;

-- Single-use WebAuthn challenges for enrollment and approvals.
CREATE TABLE IF NOT EXISTS webauthn_challenges (
  nonce TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL,
  target_kind TEXT,
  target_id TEXT,
  options_json TEXT,
  challenge TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_webauthn_challenges_expires
  ON webauthn_challenges(expires_at);

-- Time-boxed approvals replace permanent always-allow rules.
CREATE TABLE IF NOT EXISTS approval_windows (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  api_key_id TEXT NOT NULL REFERENCES api_keys(id) ON DELETE CASCADE,
  requester_ip TEXT NOT NULL,
  method TEXT NOT NULL,
  upstream_host TEXT NOT NULL,
  upstream_path TEXT NOT NULL,
  grant_id TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_approval_windows_scope
  ON approval_windows(user_id, api_key_id, requester_ip, method, upstream_host, upstream_path, expires_at);

DROP TABLE IF EXISTS proxy_always_allow_rules;

-- Re-register Telegram bot commands so /passkey shows up.
UPDATE telegram_state SET bot_commands_registered_at = NULL WHERE id = 1;
