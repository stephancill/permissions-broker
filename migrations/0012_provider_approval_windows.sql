PRAGMA foreign_keys = ON;

-- Provider-wide approval windows: auto-approve every request to a provider
-- (same user + API key + requester IP) until the window expires. Endpoint
-- columns hold '*' for provider-scoped windows.
ALTER TABLE approval_windows ADD COLUMN scope TEXT NOT NULL DEFAULT 'endpoint';
ALTER TABLE approval_windows ADD COLUMN provider_id TEXT;

CREATE INDEX IF NOT EXISTS idx_approval_windows_provider_scope
  ON approval_windows(user_id, api_key_id, requester_ip, provider_id, expires_at);
