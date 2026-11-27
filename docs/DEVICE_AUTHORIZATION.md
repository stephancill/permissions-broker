# Device sign-in (OAuth 2.0 Device Authorization Grant)

Agents and CLIs get their API key through the device authorization grant
([RFC 8628](https://datatracker.ietf.org/doc/html/rfc8628)) instead of the user
copying a key out of the app.

## Flow

1. The CLI calls `POST /v1/device/authorize` (no auth) with an optional
   `client_id`, a suggested key `label` and `key_type` (`persistent`, the
   default, or `session`). The broker returns a secret
   `device_code`, a short `user_code` (`XXXX-XXXX`, base-20 consonants),
   `verification_uri` (`<APP_BASE_URL>/device`), `verification_uri_complete`,
   `expires_in` (600) and `interval` (5).
2. The CLI shows the URL and code. `/device` redirects to `/app/device`, which
   needs the web session (passkey sign-in).
3. The page shows the code, the client id, when it was requested and whether
   it issues a session key, and an editable label (the suggestion gets a
   numeric suffix if a key already uses it). **Approve** records the user, label and approving session;
   **Deny** ends the flow.
4. The CLI polls `POST /v1/device/token` with
   `grant_type=urn:ietf:params:oauth:grant-type:device_code`. Errors follow
   RFC 8628 §3.5: `authorization_pending`, `slow_down` (polled inside the
   interval; the interval grows by 5s), `access_denied`, `expired_token`, and
   `invalid_grant` for unknown or used codes.
5. The first poll after approval claims the row (`APPROVED -> CONSUMED`,
   conditional update) and only then mints the API key, so the key's plaintext
   is never stored and concurrent polls get at most one key. The response is
   `{access_token, token_type: "Bearer", api_key_label, key_type}` plus
   `expires_at`/`expires_in` for session keys. The poll's IP, user agent and
   edge geolocation are stored on the key as where it was issued to.

## Session keys

Agents sign in with `key_type=session` (the skill's default). A session key
works for 6 hours (`SESSION_KEY_TTL_SECONDS`); after that `requireApiKey`
answers `401 {"error": "api_key_expired"}` and the sweeper deletes the key
(which also removes its requests and sessions, as deleting any key does).
Session keys can be renamed or deleted but not rotated. Expiry starts when the
key is issued, so each new agent session costs one approval.

## Design notes

- Only the SHA-256 of the device code is stored.
- Approval checks that the label is free; if a key with that label appears
  between approval and the poll, the poll returns `access_denied`.
- Approval needs the web session only (like creating a key on the API keys
  page), not a fresh passkey assertion. The page tells the user to approve only
  codes they started, the usual device-flow phishing guard.
- Audit events: `device_authorization_approved`, `device_authorization_denied`,
  and `api_key_created` with `via: "device_authorization"`.
- The sweeper deletes rows an hour after they expire.
- Schema: `migrations/0018_device_authorizations.sql`.

## Client (skill scripts)

`skills/stupid-vault/scripts/vault_auth.py login` runs the flow and writes
`{base_url, api_key, label}` to `~/.config/stupid-vault/credentials.json`
(`$XDG_CONFIG_HOME` respected; directory 0700, file 0600, atomic write).
`vault_proxy.py` and `vault_git.py` read the broker URL and key from that file;
`--credentials <path>` overrides the location for every script. They don't
read environment variables, and the broker URL comes from the credential
(`login --base-url` for a self-hosted broker).

Script flags carry no prefix (the old `--pb-*` names were dropped in the
rebrand). They are chosen not to collide with curl options (`vault_proxy.py`) or
git clone/fetch/pull/push options (`vault_git.py` strips its flags from anywhere
in the arguments).

`login` requests a session key unless `--persistent` is given, stores its
`expires_at`, and replaces an expired credential without `--force`; the
other scripts refuse an expired credential with a hint to log in again.
`vault_auth.py status` checks the stored key against `/v1/whoami`; `logout`
deletes the file (delete the key in the app); `base-url` and `header` feed raw
`curl` calls without exposing the key in the agent's output.
