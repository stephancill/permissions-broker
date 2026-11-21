# permissions-broker

Passkey-controlled permissions gate + proxy API for third-party providers, with an installable PWA for approvals called **stupid vault**.

- Agent/app calls a single proxy API using a user-issued API key.
- Every request pauses and sends a push notification to the user's PWA (add it to the iPhone home screen); tapping it opens the request, which the user approves with their passkey (Face ID / Touch ID) or denies.
- On approval, the agent can execute the upstream API request and the broker returns the upstream response.
- Linked credentials are encrypted to a key only the user's passkey can unlock; the server cannot decrypt them without an approval. See `docs/PASSKEY_CREDENTIAL_ENCRYPTION.md`.

## Current providers:

- Google (Drive/Docs/Sheets)
- GitHub
- Spotify
- Cloudflare
- Generic IMAP email (read-only, via `/v1/email`)
- Apple release signing: GitHub Actions runs sign and upload TestFlight builds through `/v1/release`, authenticated with GitHub OIDC, while the keys stay in the broker (`docs/APPLE_RELEASE_SESSIONS.md`)

## Agent skill

- Skill definition (for agent integrations): `skills/permissions-broker/SKILL.md`

When self-hosting, update the skill definition to point to your own broker instance.

## Self-hosting

### Bun/Railway-style hosting

1. Deploy to any host that can run Bun (VPS, Railway, Render, Fly.io, etc.)

2. Generate Web Push (VAPID) keys: `bun scripts/vapid_keys.ts`

3. Configure environment:
   - VAPID_PUBLIC_KEY / VAPID_PRIVATE_KEY: from step 2 (rotating them invalidates every device's push subscription)
   - VAPID_SUBJECT: `mailto:` or `https:` contact for push services (Apple requires it)
   - ALLOW_SIGNUP: `true` to let anyone create an account; otherwise sign-up is only open while the broker has no users
   - APP_BASE_URL: Publicly reachable https URL (e.g. https://your-host.com). It is also the passkey (WebAuthn) relying party: to change the domain later, follow `docs/DOMAIN_MIGRATION.md` (`WEBAUTHN_LEGACY_RP_ID`).
   - APP_SECRET: Generate a random secret (openssl rand -base64 32)
   - Provider OAuth credentials (optional, for providers you want to support):
     - Google: Google Cloud Console -> OAuth 2.0
     - GitHub: GitHub Developer Settings -> OAuth Apps
     - Spotify: Spotify Developer Dashboard
     - Cloudflare: Manage Account > OAuth clients (authorization code + refresh token, `client_secret_post`, redirect `$APP_BASE_URL/v1/accounts/callback/cloudflare`, scopes from `src/providers/cloudflare/oauth.ts`)

4. Set up your database (SQLite recommended for simplicity, or PostgreSQL):
   - SQLite (default): DB_PATH=./data/permissions-broker.sqlite3
   - PostgreSQL: DB_PATH=postgres://user:pass@localhost:5432/permissionsbroker

5. Run migrations and start:
   bun run migrate
   bun run start

6. Open `$APP_BASE_URL/app` in Safari on your iPhone, tap Share → Add to Home Screen, open the app from the home screen, create your account (passkey) and enable notifications.

### Cloudflare Workers + D1

The broker can also run on Cloudflare Workers with D1. This path uses cron triggers instead of in-process sweepers, and serves the PWA icons from `public/` via the assets binding.

Note: `/v1/git/*` is mounted on the Worker, but large clone/push operations should be validated against Cloudflare Worker body/time limits before relying on it for heavy repositories.

Migration runbook: `docs/RAILWAY_TO_CLOUDFLARE_WORKERS.md`

Key points:

- Preserve `APP_SECRET` exactly when importing existing data; legacy linked-account credentials (not yet migrated by a passkey enrollment) depend on it.
- Import the Railway SQLite database into D1 before cutover.
- Keep `APP_BASE_URL` on the same production domain when possible.
- Set `VAPID_PUBLIC_KEY`, `VAPID_PRIVATE_KEY` (secret) and `VAPID_SUBJECT` on the Worker.

Production: `https://vault.stupidtech.net` (previously `permissions-broker.stupidtech.net`, which still serves the API and redirects pages; see `docs/DOMAIN_MIGRATION.md`).

Deploys: the `permissions-broker` Worker is connected to this repo with Cloudflare Workers Builds. Every push to `main` runs `bun run typecheck && bun test` from the repo root, then `bunx wrangler deploy`. D1 migrations are not applied by the build: run `bunx wrangler d1 migrations apply permissions-broker --remote` before pushing a change that needs them.

## Local dev

1. Install deps

- `bun install`

2. Configure env

- Copy `.env.example` to `.env.local` and fill in:
  - `VAPID_PUBLIC_KEY` + `VAPID_PRIVATE_KEY` + `VAPID_SUBJECT` (`bun scripts/vapid_keys.ts`)
  - `APP_BASE_URL` (must be reachable by Google OAuth; use ngrok/cloudflared for local dev. Passkeys work on `http://localhost`; push on iOS needs the real https domain)
  - `APP_SECRET` (random secret used to encrypt short-lived approval keys and git session secrets, and legacy credentials until users enroll a passkey)
  - `GOOGLE_OAUTH_CLIENT_ID` + `GOOGLE_OAUTH_CLIENT_SECRET`
  - `GITHUB_OAUTH_CLIENT_ID` + `GITHUB_OAUTH_CLIENT_SECRET`
  - `SPOTIFY_OAUTH_CLIENT_ID` + `SPOTIFY_OAUTH_CLIENT_SECRET`
  - `CLOUDFLARE_OAUTH_CLIENT_ID` + `CLOUDFLARE_OAUTH_CLIENT_SECRET` (see `docs/CLOUDFLARE_OAUTH.md`)

3. Run migrations (optional; server runs them on startup)

- `bun --env-file .env.local run migrate`

4. Start the server

- `bun --env-file .env.local run dev`

Health check

- `GET http://localhost:3000/healthz`

## The app

Everything the user does happens in the stupid vault PWA at `/app` (installable; see `docs/PWA_PUSH.md`):

- **Sign in** with the passkey (usernameless). The first visit on an empty broker offers **Create account**, which creates the passkey that encrypts linked accounts.
- **Requests**: pending requests (tap to review) and recent decisions. Approve with the passkey or Deny.
- **API keys**: create (shown once), rename, rotate, revoke.
- **Accounts**: connect/disconnect Google, GitHub, Spotify and Cloudflare (OAuth) and IMAP email (read-only form).
- **Settings**: enable notifications on this device, list/remove devices, send a test push, replace the passkey, sign out.

Approvals: proxy requests can be approved once or for 15/60 minutes per endpoint (an approval window, scoped to API key + requester IP + method + host + path). An **Advanced** section (collapsed by default, with a warning) can instead open a 15/60 minute window for every request to the provider from that API key + requester IP.

## Public API

Auth:

- `Authorization: Bearer <USER_API_KEY>`

Endpoints:

- `POST /v1/proxy/request` (create a request; sends a push unless an approval window covers it)
- `GET /v1/proxy/requests/:id` (poll status only)
- `POST /v1/proxy/requests/:id/execute` (execute approved request and return upstream response)
- `POST /v1/email/sessions` (create a read-only email session; passkey approval required)
- `GET /v1/email/sessions/:id` (poll session status)
- `GET /v1/email/sessions/:id/folders` (list mailboxes)
- `POST /v1/email/sessions/:id/search` (search messages; curated filters)
- `POST /v1/email/sessions/:id/read` (read a message by UID; read-only)
- `GET /v1/accounts/` (list linked/connected provider accounts for the authenticated user)
- `GET /v1/whoami` (debug: verify API key auth)

Email access details: `docs/EMAIL_IMAP.md`

Upstream constraints

- https only
- allowed hosts are provider-defined
- methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`
- response size cap: 1 MiB
- request body cap: 256 KiB
- request bodies are stored as bytes and interpreted based on `content-type`
  - JSON: send an object/array (or JSON string) with `content-type: application/json`
  - Text: send a string with `content-type: text/*`
  - Binary: send a base64 string and set `content-type` appropriately
- result TTL is short-lived and responses are consumed on first retrieval
