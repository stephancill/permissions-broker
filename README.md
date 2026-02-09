# permissions-broker

Telegram-controlled permissions gate + proxy API for Google APIs.

- Agent/app calls a single proxy API using a user-issued API key.
- Every request pauses and prompts the user in Telegram to Approve/Deny.
- On approval, the broker executes the upstream Google API GET request and returns the upstream response exactly once (polling).

Docs

- MVP spec: `docs/TECH_SPEC_MVP.md`
- Implementation plan: `docs/IMPLEMENTATION_PLAN.md`

Agent skill

- Skill definition (for agent integrations): `skills/permissions-broker/SKILL.md`

## Local dev

1. Install deps

- `bun install`

2. Configure env

- Copy `.env.example` to `.env.local` and fill in:
  - `TELEGRAM_BOT_TOKEN`
  - `APP_BASE_URL` (must be reachable by Google OAuth; use ngrok/cloudflared for local dev)
  - `APP_SECRET` (random secret used to encrypt refresh tokens)
  - `GOOGLE_OAUTH_CLIENT_ID`
  - `GOOGLE_OAUTH_CLIENT_SECRET`

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
- `/connect` (generates Google OAuth link)
- `/keys` (rename/revoke/rotate keys)

## Public API (MVP)

Auth:

- `Authorization: Bearer <USER_API_KEY>`

Endpoints:

- `POST /v1/proxy/request` (create a request; always prompts in Telegram)
- `GET /v1/proxy/requests/:id` (poll status and retrieve upstream response exactly once)
- `GET /v1/whoami` (debug: verify API key auth)

Upstream constraints (MVP)

- GET only
- https only
- allowed hosts: `docs.googleapis.com`, `www.googleapis.com`
- response size cap: 1 MiB
- result TTL is short-lived and responses are consumed on first retrieval
