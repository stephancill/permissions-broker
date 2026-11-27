PRAGMA foreign_keys = ON;

-- Keys are deleted instead of revoked (labels become reusable). Revoked keys
-- go away, together with the requests and sessions that reference them
-- (ON DELETE CASCADE); audit_events keep the record. revoked_at stays as an
-- unused column: rebuilding api_keys on D1 would cascade the same way.
DELETE FROM api_keys WHERE revoked_at IS NOT NULL;

-- 'persistent' keys live until deleted; 'session' keys (device sign-in with
-- key_type=session) stop working at expires_at and are swept afterwards.
ALTER TABLE api_keys ADD COLUMN key_type TEXT NOT NULL DEFAULT 'persistent';
ALTER TABLE api_keys ADD COLUMN expires_at TEXT;

-- Audit trail shown on the API keys page: where the key was issued to and
-- last used from. Location is the edge's IP geolocation (Cloudflare), when
-- available.
ALTER TABLE api_keys ADD COLUMN created_ip TEXT;
ALTER TABLE api_keys ADD COLUMN created_user_agent TEXT;
ALTER TABLE api_keys ADD COLUMN created_location TEXT;
ALTER TABLE api_keys ADD COLUMN last_used_ip TEXT;
ALTER TABLE api_keys ADD COLUMN last_used_user_agent TEXT;
ALTER TABLE api_keys ADD COLUMN last_used_location TEXT;

CREATE INDEX IF NOT EXISTS idx_api_keys_expires
  ON api_keys(expires_at) WHERE expires_at IS NOT NULL;

ALTER TABLE device_authorizations
  ADD COLUMN key_type TEXT NOT NULL DEFAULT 'persistent';
