# Railway to Cloudflare Workers Migration

This repo can run the permissions broker on Cloudflare Workers with D1.
`/v1/git/*` is mounted on the Worker, but large clone/push operations should be validated against Cloudflare Worker body/time limits before relying on it for heavy repositories.

## Runtime Changes

- Worker entrypoint: `src/worker.ts`
- Shared app factory: `src/app.ts`
- D1 binding: `DB`
- Telegram delivery on Workers: `POST /telegram/webhook`
- Expiration sweeping on Workers: cron trigger every minute
- Local Bun runtime remains available through `src/server.ts`

## Data Preservation Requirements

- Keep `APP_SECRET` exactly unchanged. Existing linked provider credentials are encrypted with this secret.
- Snapshot the Railway SQLite database during a write freeze.
- Import every table into D1, including BLOB ciphertext columns.
- Keep the production domain/base URL unchanged if possible.

## Initial Cloudflare Setup

1. Create D1 database:

```bash
wrangler d1 create permissions-broker
```

2. Replace `database_id` in `wrangler.toml` with the created D1 database id.

3. Apply schema migrations:

```bash
wrangler d1 migrations apply permissions-broker --remote
```

4. Configure secrets:

```bash
wrangler secret put TELEGRAM_BOT_TOKEN
wrangler secret put APP_SECRET
wrangler secret put GOOGLE_OAUTH_CLIENT_ID
wrangler secret put GOOGLE_OAUTH_CLIENT_SECRET
wrangler secret put GITHUB_OAUTH_CLIENT_ID
wrangler secret put GITHUB_OAUTH_CLIENT_SECRET
wrangler secret put SPOTIFY_OAUTH_CLIENT_ID
wrangler secret put SPOTIFY_OAUTH_CLIENT_SECRET
```

Set `APP_BASE_URL` as a secret or Worker variable matching the production domain.

## SQLite to D1 Import

1. Stop Railway writes or put the app in maintenance mode.

2. Copy the SQLite database file from Railway persistent storage.

3. Create a SQL dump locally:

```bash
sqlite3 permissions-broker.sqlite3 .dump > permissions-broker.sql
```

4. Import into D1:

```bash
wrangler d1 execute permissions-broker --remote --file permissions-broker.sql
```

5. Verify row counts for all tables before cutover.

## Telegram Cutover

Workers use webhooks instead of long polling.

After deploying the Worker, set the webhook:

```bash
curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/setWebhook?url=$APP_BASE_URL/telegram/webhook"
```

If rolling back to Railway long polling, delete the webhook before restarting Railway:

```bash
curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/deleteWebhook?drop_pending_updates=false"
```

## Deploy And Smoke Test

1. Deploy:

```bash
wrangler deploy
```

2. Verify health:

```bash
curl -sf "$APP_BASE_URL/healthz"
```

3. Verify existing API keys:

```bash
curl -H "Authorization: Bearer <existing_pb_key>" "$APP_BASE_URL/v1/whoami"
```

4. Verify linked accounts:

```bash
curl -H "Authorization: Bearer <existing_pb_key>" "$APP_BASE_URL/v1/accounts/"
```

5. Create a proxy request and approve it in Telegram.

6. Execute the approved request.

## Rollback

- Keep the Railway SQLite snapshot untouched.
- Keep Railway env vars available.
- Delete the Telegram webhook and restart Railway long polling.
- Point the production domain back to Railway.
- Reconcile any D1 writes made after cutover before attempting another migration.
