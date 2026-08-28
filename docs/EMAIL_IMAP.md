# Read-only Email Access (Generic IMAP)

The broker can act as an **IMAP client** on a user's behalf: the user connects a generic
IMAP account (host/port/username/password) once, and agents can then issue **read-only**
email operations over the broker's HTTP API. Every access is gated behind an explicit
Telegram approval for a short-lived session.

Because IMAP is a raw TCP/TLS protocol, the broker never hands raw IMAP access to agents.
Instead, it translates a small set of curated HTTP operations into IMAP, and only ever
executes read-only commands (open via IMAP `EXAMINE`), so read-only is enforced by
construction.

## Connect flow

A user links an email account from Telegram:

1. `/connect imap` in Telegram → the bot creates a `connect_state` and replies with a link
   to the broker-hosted form (`/v1/accounts/connect/imap?state=...`).
2. The user enters their **email address** and **password / app-specific password**.
3. The broker **auto-detects the IMAP server** from the email domain:
   - Thunderbird ISPDB autoconfig (`https://autoconfig.thunderbird.net/v1.1/<domain>`),
   - falling back to `imap.<domain>`, `mail.<domain>`, `<domain>` on 993 (TLS) and
     143 (STARTTLS),
   - each candidate is verified by actually connecting and authenticating before it is
     used. A manual host/port override is also supported.
4. The verified credential `{ email, password, host, port, secure }` is stored
   **encrypted at rest** (`APP_SECRET`) in `linked_accounts` with `provider='imap'`,
   `scopes='read'`.

## Session model

Email access is session-based (mirrors `/v1/git`):

- `POST /v1/email/sessions` — creates a `PENDING_APPROVAL` session (10 min TTL) and
  prompts the user in Telegram with **Approve / Deny** buttons.
- The session is scoped to the exact API key that created it (like `/v1/proxy` and
  `/v1/git`).
- After approval the session becomes `APPROVED` (then `ACTIVE` on first use). Reads are
  allowed while `APPROVED`/`ACTIVE`; `PENDING_APPROVAL` → 202, `DENIED` → 403,
  `EXPIRED` → 408.
- A session is an **authorization window, not a live socket**: each operation connects
  fresh with the stored credentials, executes one read-only IMAP sequence, then
  disconnects. No long-lived sockets.

## Curated read-only operations

All endpoints require `Authorization: Bearer <pb_...>`. Every mailbox open uses
`getMailboxLock(path, { readOnly: true })` → IMAP `EXAMINE`, so the server itself rejects
any state change.

### List folders

`GET /v1/email/sessions/:id/folders`

Returns the mailbox list:
```json
{ "folders": [ { "path": "INBOX", "delimiter": "/", "attributes": ["\\HasChildren"], "specialUse": "\\Inbox" } ] }
```

### Search

`POST /v1/email/sessions/:id/search`

```json
{
  "mailbox": "INBOX",
  "query": { "subject": "invoice", "from": "billing@example.com",
             "since": "2026-08-01", "unseen": true },
  "results_limit": 50
}
```

Supported curated filters: `subject`, `from`, `to`, `since` (inclusive date, `YYYY-MM-DD`),
`before` (exclusive date), `unseen`, `keyword`, `body_text`. `results_limit` defaults to
50, max 200.

Returns a list of matches `{ uid, date, subject, from }`.

### Read

`POST /v1/email/sessions/:id/read`

```json
{ "mailbox": "INBOX", "uid": 123, "parts": { "envelope": true, "text": true } }
```

`parts` may include `envelope` (always on for read), `text` (plain text body),
`html` (HTML body), and `raw` (full raw RFC822 source, base64-encoded). Fetched message
source is capped at **1 MiB**.

Returns message metadata, flags, and the requested parts.

## Read-only enforcement

- `src/email/client.ts` is the only module that opens IMAP connections, backed by a
  hand-rolled protocol client (`src/email/protocol.ts`) that implements only read
  operations (LIST / EXAMINE / SEARCH / read FETCHs).
- `src/email/ops.ts` exposes exactly three operations: `listFolders`, `searchEmails`,
  `readEmail`.
- All mailbox selections use IMAP `EXAMINE` (read-only), so the server itself rejects any
  mutation. Even a bug cannot mutate mail.

## Testing

### Offline end-to-end (no account needed)

A bundled harness boots a throwaway plaintext IMAP server (seeded with two sample
messages) and runs the full read path through the real HTTP handlers, simulating the
Telegram approval:

```bash
bun scripts/email_e2e.ts
```

You should see `create session`, `approve`, `folders`, `search`, and `read` all return
HTTP 200, with the searched subjects and the decoded message text. The mini IMAP server
lives in `scripts/imap_test_server.ts` and can also be run standalone:

```bash
bun scripts/imap_test_server.ts   # imap://127.0.0.1:11430 (test@example.com / testpass)
```

### Real account end-to-end

1. `bun --env-file .env.local run dev` (requires `TELEGRAM_BOT_TOKEN`, `APP_BASE_URL`,
   `APP_SECRET` in `.env.local`).
2. In Telegram: `/connect imap` → open the link → enter email + password (the IMAP
   server is auto-detected and verified; for Gmail/iCloud/Outlook use an app password).
3. Create and approve a session, then read:

```bash
SESSION=$(curl -s -X POST -H "Authorization: Bearer $PB_API_KEY" -H 'content-type: application/json' \
  -d '{"consent_hint":"trying email access"}' $APP_BASE_URL/v1/email/sessions \
  | jq -r .session_id)

curl -s -H "Authorization: Bearer $PB_API_KEY" $APP_BASE_URL/v1/email/sessions/$SESSION/folders
curl -s -X POST -H "Authorization: Bearer $PB_API_KEY" -H 'content-type: application/json' \
  -d '{"mailbox":"INBOX","query":{"unseen":true}}' $APP_BASE_URL/v1/email/sessions/$SESSION/search
curl -s -X POST -H "Authorization: Bearer $PB_API_KEY" -H 'content-type: application/json' \
  -d '{"mailbox":"INBOX","uid":1,"parts":{"text":true}}' $APP_BASE_URL/v1/email/sessions/$SESSION/read
```

Approve the Telegram prompt to see the session move `PENDING_APPROVAL → APPROVED/ACTIVE`
and the read endpoints return mail.

## Runtime note

The IMAP client uses `node:net`/`node:tls`, which are supported natively on Cloudflare
Workers (via the TCP Sockets API) with `nodejs_compat`. The existing Worker deployment
(`wrangler.toml`) serves email operations directly. Outbound port 25 is blocked by
Workers; IMAP 993/143 are fine. The protocol reader yields to the event loop between
chunks so large messages stay within the Worker CPU budget. Each operation opens its own
connection (one command per request), so no single request exceeds Worker limits. A
hand-rolled protocol client (`src/email/protocol.ts`) is used instead of `imapflow`
because `imapflow`'s stream handling does not work on the Worker `node:net`/`node:tls`
shim while the raw socket APIs do.