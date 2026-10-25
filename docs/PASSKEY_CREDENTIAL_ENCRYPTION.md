# Passkey-Gated Credential Encryption

Status: implemented (migration `0011_passkey_credentials.sql`).

## Goal

Stop the broker from being able to decrypt stored provider credentials on its own.
Today every linked credential (OAuth refresh tokens, Cloudflare API tokens, IMAP
passwords) is encrypted with a single `APP_SECRET` held by the Worker, so a
compromise of the Worker's secrets plus D1 exposes every user's long-lived
credentials.

After this change, credentials are encrypted to a per-user key that can only be
unlocked by the user's passkey (WebAuthn PRF extension). Each approval releases a
one-time key for exactly the credential that request needs. Execution, token
refresh, git streaming and IMAP code paths are unchanged; only the source of the
decryption key changes.

Non-goals: per-provider credential leasing, a native mobile app, executing upstream
requests on the user's device.

## Threat model

| Scenario | Exposure |
|---|---|
| D1 dump | Nothing |
| D1 dump + `APP_SECRET` | Credentials with an unexpired approval key at that moment |
| Worker compromised at runtime | Credentials approved or used during the compromise |
| Malicious deploy of the approval page JS | Private key while it is unwrapped in the page, i.e. all credentials. Accepted trade-off for a self-operated broker |

## Platform findings (2026-10-25)

Tested with a throwaway page on iOS 18.7, passkey stored in Apple Passwords:

| Browser | Register | Authenticate | PRF |
|---|---|---|---|
| Safari | ok | ok | ok, identical output at create and get |
| Telegram in-app browser (iOS) | `NotAllowedError` | `NotAllowedError` | n/a |

Telegram's in-app browser is an embedded webview without passkey access, even
though `getClientCapabilities()` reports `extension:prf: true` there. Approval
pages must therefore run in Safari (or another full browser); see "Approval page".

## Key hierarchy

```
passkey (platform authenticator, user verification required)
  └─ PRF(eval.first = prf_salt) ──HKDF-SHA256──► KEK (AES-256-GCM)       client only
       └─ wraps ──► user private key (ECDH P-256, PKCS#8)                server stores ciphertext
                      ▲
user public key (raw P-256) ┘                                            server stores plaintext
  └─ ECIES ──► per-credential ciphertext                                 server stores
```

### Key derivation and wrapping (client)

- `KEK = HKDF-SHA256(ikm = PRF output, salt = empty, info = "pb-kek-v1:" + user_id)`.
- `wrapped_private_key = iv ‖ AES-256-GCM(KEK, PKCS#8 private key, aad = "pb-userkey-v1:" + user_id)`.
- `prf_salt` is 32 random bytes per enrollment, stored in `user_passkeys`.

### ECIES envelope (credentials)

Byte-compatible implementations in the Worker (`src/crypto/ecies.ts`) and the
browser (`src/passkey/clientCrypto.ts`), WebCrypto only:

1. Generate ephemeral P-256 keypair `(esk, epk)`.
2. `shared = ECDH(esk, user_public_key)`.
3. `dek = HKDF-SHA256(ikm = shared, salt = epk_raw, info = "pb-cred-v1:" + linked_account_id, 32 bytes)`.
4. `ciphertext = AES-256-GCM(dek, iv = random 12 bytes, plaintext = credential, aad = linked_account_id)`.
5. Store `enc_version = 1`, `credential_epk = epk_raw`, `refresh_token_ciphertext = iv ‖ ciphertext`.

Binding `linked_account_id` into `info` and `aad` prevents swapping ciphertexts
between accounts.

### Decryption on approval

Client: PRF → KEK → unwrap private key → `ECDH(private_key, epk)` → HKDF → `dek`.
The client sends only `dek` to the server, never the KEK or the private key.

### Rotation after use

Every unlock re-encrypts the credential with a fresh ephemeral key to the user's
public key and overwrites the row. The server knows the new DEK (it is the
encrypting side), so it also re-encrypts every live grant for that credential with
the new DEK in the same step. A DEK that leaked (logs, memory dumps) is useless
against later database snapshots, and concurrent approvals for the same credential
keep working.

The same path stores replacement credentials a provider issues during execution
(rotated OAuth refresh tokens): `getAuthorizationHeaderValue` returns
`{ authorization, updatedCredential? }`.

D1 has no interactive transactions, so a reader can briefly see a new ciphertext
with an old grant DEK; `unlockCredential` retries the read a few times.

## Flows

### Enrollment (`/passkey` in Telegram → `/passkey/enroll`)

1. Telegram `/passkey` replies with a URL button to a single-use enrollment link
   (`connect_states` row, provider `passkey`, 10 minutes).
2. `POST /passkey/enroll/options` returns WebAuthn registration options, a fresh
   `prf_salt` and, when re-enrolling, the current passkey id, salt, public key and
   wrapped private key.
3. The page calls `navigator.credentials.create` (`residentKey: "required"`,
   `userVerification: "required"`, `extensions.prf.eval.first = prf_salt`). If no
   PRF output comes back at create time it runs one `get` to obtain it, and fails
   loudly if PRF is unavailable.
4. The client generates the P-256 keypair (or, for re-wrap, first unlocks the
   current private key with the current passkey), wraps it under the new KEK and
   posts `POST /passkey/enroll/verify`.
5. The server verifies the registration, stores `user_passkeys` + `user_keys`, and
   migrates legacy credentials (below).

One passkey per user; re-enrolling replaces it:

- `rewrap`: the old passkey unlocks the private key, which is re-wrapped under the
  new passkey; the public key must not change and credentials are untouched.
- `replace_lost`: a new keypair; every passkey-encrypted credential is revoked and
  must be reconnected.

### Connecting accounts

UX is unchanged, but `/connect` and the connect forms require an enrolled passkey
(fail loudly otherwise). The server receives the credential (OAuth callback,
Cloudflare/IMAP forms), validates it, and `saveLinkedCredential` ECIES-encrypts it
to the user's public key. Non-secret display metadata (IMAP email/host/port,
Cloudflare account list) is stored in `metadata_json`, so `GET /v1/accounts` never
decrypts credentials.

### Approval (`/approve/:kind/:id?t=<link token>`)

`kind` is `proxy`, `git` or `email`.

1. Telegram messages carry a **Review & approve** URL button and a **Deny** callback
   button. Telegram buttons can no longer approve (old messages' Approve buttons
   answer with a hint). Git push default-branch permission and approval windows
   are chosen on the page.
2. `t` is `HMAC(APP_SECRET, "approve:<kind>:<id>")`; the page embeds the wrapped
   private key, so it is only reachable from the Telegram link.
3. In Telegram's in-app browser (`window.TelegramWebviewProxy`) the page shows
   "Open in Safari" with a copy-link button instead of the approve UI.
4. `POST /approve/:kind/:id/challenge` validates the chosen options and returns a
   challenge `SHA-256(JSON{kind, id, request_hash, options, nonce})`, stored single
   use in `webauthn_challenges`.
5. `navigator.credentials.get` with that challenge, `userVerification: "required"`
   and the PRF extension: one Face ID produces both the signed approval and the PRF
   output.
6. The client derives the DEK for the linked account the target needs (if one is
   linked) and posts `{ assertion, dek }` to `POST /approve/:kind/:id`.
7. The server consumes the challenge, recomputes it from the current target (fails
   if the request changed), verifies the assertion (signature, counter, challenge,
   origin, rpId, UV), creates the grant (which test-decrypts the credential), and
   moves the target to `APPROVED`. The full assertion is stored in `audit_events`
   (`actor_type = 'passkey'`) as a signed, verifiable approval.

Pages that handle key material use a strict CSP (nonce'd inline scripts only, no
third-party origins, same-origin fetches) and ship no external JavaScript.

### Execution

- Proxy: `proxy_requests.grant_id` → `unlockCredential`; the request's own grant is
  deleted right after the unlock (execute is single use).
- Git: the session's grant is looked up by target; push sessions delete it once
  `USED`. Without a linked GitHub account, clone still proxies unauthenticated.
- Email: the session's grant is looked up by target on every operation.

Missing or expired grants fail loudly (`credential_unavailable`, HTTP 409, with
`code` `NO_GRANT` / `GRANT_EXPIRED` / `DECRYPT_FAILED`).

### Grants (`credential_grants`)

- `dek_ciphertext` is the DEK encrypted with the `APP_SECRET` AES-GCM helper.
- `target_kind`/`target_id` scope it to one proxy request, git session, email
  session or approval window.
- Lifetime: proxy requests until `approval_expires_at` (5 minutes from creation, raised
  from 2 to leave time for the Safari + Face ID round trip); git/email sessions until the session ends (swept) with a 60 minute hard
  cap; windows until the window closes.
- The cron/loop sweeper deletes expired grants and grants whose target is terminal.

### Approval windows (replace always-allow)

Permanent always-allow rules cannot work, because the server cannot decrypt without
an approval. On the approval page a proxy request can instead be approved for 15 or
60 minutes. This creates an `approval_windows` row scoped like the old rules (user,
API key, requester IP, method, host, path) plus a grant targeted at the window.
Matching requests in the window are auto-approved and reuse that grant; rotation
keeps it valid. `proxy_always_allow_rules` is dropped.

## Schema (`0011_passkey_credentials.sql`)

- `user_passkeys` (one row per user), `user_keys`.
- `linked_accounts`: `enc_version` (0 legacy, 1 passkey), `credential_epk`,
  `metadata_json`.
- `credential_grants`, `webauthn_challenges`, `approval_windows`.
- `proxy_requests.grant_id`.
- Drops `proxy_always_allow_rules`.

## Migration (breaking change)

No backwards compatibility. On enrollment the server decrypts the user's legacy
`APP_SECRET` ciphertexts, re-encrypts them to the new public key, fills
`metadata_json`, and sets `enc_version = 1` (unreadable legacy rows are revoked).
Until a user enrolls they cannot approve or connect accounts. Existing always-allow
rules are deleted.

`APP_BASE_URL` must be the https origin users open approval links on: it determines
the WebAuthn RP ID and expected origin. Changing the domain invalidates passkeys.

## Dependencies

- `@simplewebauthn/server` for registration and assertion verification. The browser
  side is hand-rolled (`src/passkey/clientCrypto.ts`) so approval pages load no
  third-party scripts.
- Everything else is WebCrypto (ECDH P-256, HKDF-SHA256, AES-256-GCM).

## Code map

- `src/crypto/ecies.ts`: server ECIES; `src/passkey/clientCrypto.ts`: browser side.
- `src/credentials/store.ts`: storage, grants, unlock + rotation, legacy migration.
- `src/passkey/webauthn.ts`: challenges, link tokens, assertion verification.
- `src/web/passkey.ts`, `src/web/approve.ts`, `src/web/pages.ts`: pages and routes.
- `src/proxy/approvalWindows.ts`: approval windows.
- Tests: `tests/passkey_crypto.test.ts` (browser ↔ server crypto),
  `tests/passkey_flow.test.ts` (end to end with a software authenticator in
  `tests/helpers/virtualAuthenticator.ts`).
