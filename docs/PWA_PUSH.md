# PWA + Web Push (replaces the Telegram bot)

The user surface is an installable progressive web app at `/app`, branded
**stupid vault** (lowercase; manifest name, home-screen title, sign-in heading,
passkey RP name). The service, API and agent skill keep the
`permissions-broker` name. It is served from `vault.stupidtech.net`; the domain
is the passkey RP ID, so moving it needs `docs/DOMAIN_MIGRATION.md`. It replaces the
Telegram bot that used to handle sign-up, API keys, account linking and approval
prompts.

## Why

- Approvals already needed a passkey page in Safari; Telegram's in-app browser
  cannot use passkeys, so every approval bounced between apps.
- The passkey already anchors the security model (it unlocks credentials), so it
  can be the account identity too. One less third party in the trust path.
- iOS (16.4+) delivers Web Push to web apps added to the home screen.

## User flow

1. Open `$APP_BASE_URL/app` in Safari on the iPhone → Share → **Add to Home Screen**.
   Home-screen web apps have their own cookie jar, so sign in from the installed app.
2. **Create account** (only offered on an empty broker or with `ALLOW_SIGNUP=true`)
   creates the passkey + wrapped user key in one step, or **Sign in with passkey**.
3. **Enable notifications** (must be a tap; iOS only exposes `PushManager` in
   standalone mode).
4. Create an API key, link accounts.
5. An agent request sends a push → tap opens `/approve/:kind/:id` in the app →
   Approve with passkey or Deny.

## Accounts and sessions

- Sign-in is a usernameless WebAuthn assertion (no `allowCredentials`); the
  credential id resolves the user (`user_passkeys.credential_id`). Existing users
  keep their account: their passkey's RP ID is unchanged.
- Pre-auth challenges (sign-in, sign-up) live in `auth_challenges` (single use,
  5 minutes) because `webauthn_challenges.user_id` references `users`.
- A successful sign-in/sign-up creates a `web_sessions` row (token hash only) and
  an `HttpOnly; SameSite=Lax` (+ `Secure` on https) cookie `pb_session`. Sessions
  last 30 days and slide forward at most once an hour.
- Cookie-authenticated writes require `Origin` = `APP_BASE_URL` origin, or (when
  the browser sends no/`null` Origin) `Sec-Fetch-Site: same-origin`. App pages use
  `Referrer-Policy: same-origin` so form POSTs carry the real Origin.
- The session gates the app and the approval pages (which embed the wrapped
  private key). It replaces the HMAC link tokens Telegram messages carried.
  Approving still needs a fresh passkey assertion + PRF; denying needs only the
  session.
- Sign-up policy: open while `users` is empty (first-run bootstrap) or with
  `ALLOW_SIGNUP=true`; checked again at verify.

## Web Push

- `src/push/webpush.ts`: RFC 8291 encryption with the RFC 8188 `aes128gcm`
  coding (single record) and RFC 8292 VAPID (ES256 JWT, `aud` = push service
  origin, 12 h expiry), all on WebCrypto so it runs on Workers and Bun.
  `tests/webpush.test.ts` checks the RFC 8291 Appendix A vector byte for byte.
- `src/push/notify.ts`: subscriptions (`push_subscriptions`, unique per
  endpoint) and best-effort fan-out. 404/410 responses delete the subscription.
  Failures are logged (host + status only) and never fail the agent request; the
  request is always visible in the app inbox.
- Endpoints are restricted to the browser push services (`web.push.apple.com`,
  `fcm.googleapis.com`, `updates.push.services.mozilla.com`, `*.notify.windows.com`,
  https, default port) so the broker never POSTs to arbitrary URLs.
- Payload: `{title, body, url, tag}`. `tag` is `<kind>:<id>`; it also becomes the
  `Topic` header (non-url-safe chars replaced) so an undelivered push is replaced.
  The approval page closes the device notification with that tag after a decision.
- TTL: the remaining approval time for proxy requests, 5 minutes for git, the
  session TTL for email. Approval prompts use `Urgency: high`; approval-window
  auto-approvals are sent as `low` informational pushes.
- VAPID keys: `bun scripts/vapid_keys.ts`. Rotating them invalidates every
  subscription; devices re-enable from Settings.

## PWA plumbing

- `/manifest.webmanifest` and `/sw.js` are Hono routes (`src/web/app.ts`) so they
  are served identically on Bun, Workers and in tests.
- The service worker has no fetch handler: it shows every push (iOS revokes
  permission for silent pushes) and on tap focuses/navigates an open window or
  opens one. Only same-origin URLs are opened.
- Icons live in `public/` (Workers `[assets]` binding; `serveStatic` in
  `src/server.ts` for Bun).
- Page CSP: nonce scripts/styles, `connect-src 'self'`, `manifest-src 'self'`,
  `worker-src 'self'`, `img-src 'self'`, `form-action 'self'`.

## Schema (migration 0014)

- New: `web_sessions`, `auth_challenges`, `push_subscriptions`.
- Dropped: `telegram_state`, `telegram_pending_inputs`, `approvals` (Telegram
  decision log; `audit_events` records decisions), and the `telegram_*` prompt
  columns on `proxy_requests`, `git_sessions`, `email_sessions`.
- Kept: `users.telegram_user_id` (NOT NULL UNIQUE). Rebuilding `users` on
  D1/SQLite fires `ON DELETE CASCADE` for every child table even with
  `defer_foreign_keys`, and a UNIQUE column can't be dropped. New users get a
  random negative placeholder; nothing reads the column.

## Removed

- `src/telegram/` (bot, poller, webhook, command registration, message edits),
  the `grammy` dependency, `TELEGRAM_BOT_TOKEN`, `/telegram/webhook`.
- Telegram "connected"/"passkey saved" confirmation messages: the result pages
  show the outcome instead.

## Limitations

- A user who never enrolled a passkey under Telegram has no way to sign in. With
  closed sign-up they need `ALLOW_SIGNUP=true` to create a new account.
- Losing the passkey means losing the account (no Telegram identity to recover
  through). Passkeys synced via iCloud Keychain make this unlikely.
- Web Push on iOS requires the home-screen app and iOS 16.4+.
