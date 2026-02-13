PRAGMA foreign_keys = ON;

ALTER TABLE git_sessions ADD COLUMN session_secret_ciphertext BLOB;

-- NOTE: existing sessions (if any) will not have a secret available for /remote.
