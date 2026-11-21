PRAGMA foreign_keys = ON;

-- Apple release sessions: CI (GitHub Actions, authenticated by OIDC) signs and
-- uploads iOS builds through the broker, which holds the App Store Connect key
-- and the distribution private key (docs/APPLE_RELEASE_SESSIONS.md).

-- Which workflow may release which bundle ids. Created by the user in the app
-- and activated with a passkey assertion (status PENDING_APPROVAL -> ACTIVE).
CREATE TABLE IF NOT EXISTS release_policies (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  repository TEXT NOT NULL,
  workflow_path TEXT NOT NULL,
  ref TEXT NOT NULL,
  bundle_ids_json TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  approval_expires_at TEXT NOT NULL
);

-- One active policy per workflow identity (pending duplicates are allowed and
-- expire).
CREATE UNIQUE INDEX IF NOT EXISTS idx_release_policies_active
  ON release_policies(repository, workflow_path, ref) WHERE status = 'ACTIVE';
CREATE INDEX IF NOT EXISTS idx_release_policies_user ON release_policies(user_id);

CREATE TABLE IF NOT EXISTS release_sessions (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  policy_id TEXT NOT NULL REFERENCES release_policies(id) ON DELETE CASCADE,
  -- GitHub OIDC claims of the run that asked.
  repository TEXT NOT NULL,
  workflow_ref TEXT NOT NULL,
  ref TEXT NOT NULL,
  sha TEXT NOT NULL,
  run_id TEXT NOT NULL,
  run_attempt TEXT NOT NULL,
  actor TEXT NOT NULL,
  -- What the run asked to release.
  bundle_ids_json TEXT NOT NULL,
  version TEXT NOT NULL,
  build_number TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  approval_expires_at TEXT NOT NULL,
  -- Hard cap once approved; NULL while pending.
  expires_at TEXT,
  last_activity_at TEXT,
  -- The secret is shown to the run once (secret_delivered_at), then only its
  -- hash is used.
  session_secret_hash TEXT NOT NULL,
  session_secret_ciphertext BLOB,
  secret_delivered_at TEXT,
  -- App Store Connect resources this session may touch, filled in as it learns
  -- them (JSON arrays of ids).
  app_ids_json TEXT,
  bundle_resource_ids_json TEXT NOT NULL DEFAULT '[]',
  build_ids_json TEXT NOT NULL DEFAULT '[]',
  build_upload_ids_json TEXT NOT NULL DEFAULT '[]',
  build_upload_file_ids_json TEXT NOT NULL DEFAULT '[]',
  signed_bundle_ids_json TEXT NOT NULL DEFAULT '[]',
  -- The broker-made App Store Connect JWT (APP_SECRET-encrypted), reused until
  -- it nearly expires so not every request unlocks the credential.
  asc_jwt_ciphertext BLOB,
  asc_jwt_expires_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_release_sessions_user ON release_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_release_sessions_status ON release_sessions(status);
