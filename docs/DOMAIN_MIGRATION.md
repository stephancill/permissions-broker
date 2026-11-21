# Moving the broker to a new domain

Passkeys are bound to their WebAuthn RP ID (the domain they were created on),
and the passkey's PRF output is what decrypts every linked credential. Moving
domains therefore keeps old passkeys working through **Related Origin Requests**
until each user moves theirs. Nothing is re-encrypted on the server.

Used for `permissions-broker.stupidtech.net` → `vault.stupidtech.net` (completed 2026-11-21: every passkey moved, `WEBAUTHN_LEGACY_RP_ID` unset, old route removed).

## How it works

- `APP_BASE_URL` is the new origin; new passkeys use its host as RP ID.
- `WEBAUTHN_LEGACY_RP_ID` is the old host. While it is set:
  - The old host serves `/.well-known/webauthn` with
    `{"origins": ["<new origin>"]}`, so browsers on the new origin may use
    passkeys whose RP ID is the old host (Safari 18 / iOS 18, Chrome 128+).
  - The old host keeps serving `/v1/*` (agents, OAuth callbacks) and `/healthz`;
    every other path gets a 308 redirect to the new origin.
- `user_passkeys.rp_id` (migration 0016) records each passkey's RP ID. Rows from
  before it are NULL and resolve to `WEBAUTHN_LEGACY_RP_ID` (or the current RP
  ID when none is set). Assertions are verified against the passkey's own RP ID,
  and the client calls `navigator.credentials.get` with it.
- Sign-in shows an extra "Sign in with your <old host> passkey" button while any
  passkey still uses the legacy RP ID (usernameless sign-in needs the RP ID up
  front).
- The inbox and Settings show "Move it to <new host>" until the user's passkey
  is moved. **Move passkey** (`/passkey/enroll`, mode `rewrap`) unlocks the user
  key with the old passkey (related origin), creates a passkey for the new RP ID
  and wraps the same key under it. Linked accounts, API keys and the public key
  are unchanged.

## Runbook

1. Deploy the code with the new host as a Worker custom domain (`wrangler.toml`
   routes) and apply migration 0016 to D1.
2. Set the Worker secrets together:
   `APP_BASE_URL=https://<new>` and `WEBAUTHN_LEGACY_RP_ID=<old host>`.
3. OAuth apps: add `https://<new>/v1/accounts/callback/<provider>` for Google
   and Spotify. GitHub OAuth apps have a single callback URL: switch it to the
   new host. Existing refresh tokens keep working.
4. On each device: add the app from the new domain to the home screen, sign in
   with the old-domain passkey, tap **Move it to …**, re-enable notifications,
   and remove the old devices under Settings.
5. Point agents at the new base URL (skill scripts default to it). The old host
   keeps serving the API meanwhile.
6. Once every passkey is moved (`SELECT COUNT(*) FROM user_passkeys WHERE rp_id IS
   NULL OR rp_id = '<old host>'` is 0) and agents no longer call the old host,
   unset `WEBAUTHN_LEGACY_RP_ID` and drop the old route. Until then, keep it:
   removing it locks out anyone who hasn't moved their passkey.

Rollback before any passkey is moved: set `APP_BASE_URL` back to the old origin
and unset `WEBAUTHN_LEGACY_RP_ID`.
