# permissions-broker

Telegram-controlled permissions gate + proxy API for third-party providers.

- Agent/app calls a single proxy API using a user-issued API key.
- Every request pauses and prompts the user in Telegram to Approve/Deny.
- On approval, the agent can execute the upstream API request and the broker returns the upstream response.

## Current providers:

- Google (Drive/Docs/Sheets)
- GitHub
- iCloud (CalDAV)
- Spotify

## Agent skill

- Skill definition (for agent integrations): `skills/permissions-broker/SKILL.md`

When self-hosting, update the skill definition to point to your own broker instance.

## Self-hosting

1. Deploy to any host that can run Bun (VPS, Railway, Render, Fly.io, etc.)

2. Create a Telegram bot via @BotFather (https://t.me/BotFather):
   - Send /newbot and follow prompts
   - Copy the bot token

3. Configure environment:
   - TELEGRAM_BOT_TOKEN: Your bot token from step 2
   - APP_BASE_URL: Publicly reachable URL (e.g. https://your-host.com)
   - APP_SECRET: Generate a random secret (openssl rand -base64 32)
   - Provider OAuth credentials (optional, for providers you want to support):
     - Google: Google Cloud Console -> OAuth 2.0
     - GitHub: GitHub Developer Settings -> OAuth Apps
     - Spotify: Spotify Developer Dashboard

4. Set up your database (SQLite recommended for simplicity, or PostgreSQL):
   - SQLite (default): DB_PATH=./data/permissions-broker.sqlite3
   - PostgreSQL: DB_PATH=postgres://user:pass@localhost:5432/permissionsbroker

5. Run migrations and start:
   bun run migrate
   bun run start

6. Open your bot in Telegram and run /start to link your account

## Local dev

1. Install deps

- `bun install`

2. Configure env

- Copy `.env.example` to `.env.local` and fill in:
  - `TELEGRAM_BOT_TOKEN`
  - `APP_BASE_URL` (must be reachable by Google OAuth; use ngrok/cloudflared for local dev)
  - `APP_SECRET` (random secret used to encrypt refresh tokens)
  - `GOOGLE_OAUTH_CLIENT_ID` + `GOOGLE_OAUTH_CLIENT_SECRET`
  - `GITHUB_OAUTH_CLIENT_ID` + `GITHUB_OAUTH_CLIENT_SECRET`
  - `SPOTIFY_OAUTH_CLIENT_ID` + `SPOTIFY_OAUTH_CLIENT_SECRET`

3. Run migrations (optional; server runs them on startup)

- `bun --env-file .env.local run migrate`

4. Start the server

- `bun --env-file .env.local run dev`

Health check

- `GET http://localhost:3000/healthz`

## Telegram quick test

In Telegram (to your bot):

- `/start`
- `/key <label>` (or `/key` to be prompted for a label)
- `/connect` (shows connection status + buttons)
- `/connect google` (generates Google OAuth link)
- `/connect github` (generates GitHub OAuth link)
- `/connect spotify` (generates Spotify OAuth link)
- `/keys` (rename/revoke/rotate keys)

## Public API

Auth:

- `Authorization: Bearer <USER_API_KEY>`

Endpoints:

- `POST /v1/proxy/request` (create a request; always prompts in Telegram)
- `GET /v1/proxy/requests/:id` (poll status only)
- `POST /v1/proxy/requests/:id/execute` (execute approved request and return upstream response)
- `GET /v1/accounts/` (list linked/connected provider accounts for the authenticated user)
- `GET /v1/whoami` (debug: verify API key auth)

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
