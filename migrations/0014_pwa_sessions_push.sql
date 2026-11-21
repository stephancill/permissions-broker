PRAGMA foreign_keys = ON;

-- Replace the Telegram bot with a passkey-authenticated PWA + Web Push.
--
-- users.telegram_user_id is NOT NULL UNIQUE and every table cascades off
-- users, so the table cannot be rebuilt safely on D1 (dropping it fires the
-- ON DELETE CASCADE actions even with defer_foreign_keys). The column stays as
-- a legacy identifier: existing rows keep their Telegram id and new users get
-- a random negative placeholder. Nothing reads it any more.

-- Browser sessions created by a passkey sign-in. Only the token hash is stored.
CREATE TABLE IF NOT EXISTS web_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_web_sessions_expires ON web_sessions(expires_at);

-- Single-use WebAuthn challenges issued before the user is known (sign-in and
-- sign-up). user_id is the prospective id for sign-up, NULL for sign-in.
CREATE TABLE IF NOT EXISTS auth_challenges (
  nonce TEXT PRIMARY KEY,
  purpose TEXT NOT NULL,
  user_id TEXT,
  challenge TEXT NOT NULL,
  options_json TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_auth_challenges_expires ON auth_challenges(expires_at);

-- Web Push subscriptions (one per installed PWA / browser).
CREATE TABLE IF NOT EXISTS push_subscriptions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  endpoint TEXT NOT NULL UNIQUE,
  p256dh TEXT NOT NULL,
  auth TEXT NOT NULL,
  user_agent TEXT,
  created_at TEXT NOT NULL,
  last_success_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id);

-- Telegram-only state.
DROP TABLE IF EXISTS telegram_pending_inputs;
DROP TABLE IF EXISTS telegram_state;
-- Telegram decision log (keyed by chat/message ids); audit_events covers it.
DROP TABLE IF EXISTS approvals;

ALTER TABLE proxy_requests DROP COLUMN telegram_chat_id;
ALTER TABLE proxy_requests DROP COLUMN telegram_message_id;
ALTER TABLE proxy_requests DROP COLUMN telegram_message_html;

ALTER TABLE git_sessions DROP COLUMN telegram_chat_id;
ALTER TABLE git_sessions DROP COLUMN telegram_message_id;
ALTER TABLE git_sessions DROP COLUMN telegram_message_html;

ALTER TABLE email_sessions DROP COLUMN telegram_chat_id;
ALTER TABLE email_sessions DROP COLUMN telegram_message_id;
ALTER TABLE email_sessions DROP COLUMN telegram_message_html;
