PRAGMA foreign_keys = ON;

-- The WebAuthn RP ID each passkey was registered under, so the broker can move
-- to a new domain: passkeys from the old domain keep working via Related Origin
-- Requests (WEBAUTHN_LEGACY_RP_ID) until they are moved. NULL means the row
-- predates this column: the legacy RP ID when one is configured, otherwise the
-- current one (see passkeyRpId in src/passkey/webauthn.ts).
ALTER TABLE user_passkeys ADD COLUMN rp_id TEXT;
