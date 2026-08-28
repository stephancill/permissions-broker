---
name: permissions-broker
description: Use the Permissions Broker for approval-gated external API access, Git smart-HTTP operations, and read-only email access when local credentials are unavailable or not desired. Use the bundled Python CLI at skills/permissions-broker/scripts/pb_proxy.py for proxy requests (create, poll, execute) instead of hand-writing polling logic. Supports Google, GitHub, Spotify, Cloudflare, and generic IMAP email (read-only).
---

# Permissions Broker

## Setup

1. Check for `PB_API_KEY` in local secrets.
2. If missing, ask the user to create one in Telegram:

```text
/key <name>
```

3. Ask whether to store/reuse across sessions.
4. Never print or commit the API key.

Provider linking is done by the user in Telegram with `/connect`.

## Default Approach

Use the broker as the default mechanism for external requests.

- Keep prompts action-oriented: propose the exact upstream request you will make.
- Use the CLI helper for `/v1/proxy` requests.
- If approval times out, return `request_id` and tell the user exactly what to approve in Telegram.

## CLI for Proxy Requests

Preferred script:

- `skills/permissions-broker/scripts/pb_proxy.py`

This script handles the full flow for `/v1/proxy`:

1. Create request
2. Poll for approval
3. Execute once on approval

### Required Inputs

- `PB_API_KEY` env var (or `--pb-api-key`)
- Curl-like request args (URL + optional `-X`, `-H`, `-d`, `-G`)

The CLI uses `https://permissions-broker.stupidtech.net` by default.

### Example

```bash
python3 skills/permissions-broker/scripts/pb_proxy.py \
  --pb-timeout-seconds 30 \
  "https://www.googleapis.com/drive/v3/files?pageSize=5&fields=files(id,name)"
```

### Output Contract

The CLI is curl-like:

- On execute, print upstream response body to stdout.
- Print diagnostic details (request id/status/errors) to stderr when needed.

Exit codes:

- `0` executed
- `10` timed out waiting for approval
- `11` terminal non-approved status
- `12` API/transport failure

Common curl-style examples:

```bash
# GET with headers
python3 skills/permissions-broker/scripts/pb_proxy.py \
  -H "accept: application/vnd.github+json" \
  "https://api.github.com/user"

# POST JSON
python3 skills/permissions-broker/scripts/pb_proxy.py \
  -X POST \
  -H "content-type: application/json" \
  -d '{"title":"Hello"}' \
  "https://api.github.com/repos/OWNER/REPO/issues"
```

Never include upstream `authorization` headers; broker injects OAuth.

## Supported Providers

- Google: `docs.googleapis.com`, `www.googleapis.com`, `sheets.googleapis.com`
- GitHub: `api.github.com`
- Spotify: `api.spotify.com`
- Cloudflare: `api.cloudflare.com/client/v4/*`

For unsupported hosts, explain that provider support must be added first.

## Git Smart-HTTP (Separate from /v1/proxy)

Use the bundled git-like CLI:

- `skills/permissions-broker/scripts/pb_git.py`

It is a drop-in wrapper for these workflows:

- `clone`
- `fetch`
- `pull`
- `push`

Examples:

```bash
python3 skills/permissions-broker/scripts/pb_git.py clone https://github.com/OWNER/REPO.git
python3 skills/permissions-broker/scripts/pb_git.py fetch origin --prune
python3 skills/permissions-broker/scripts/pb_git.py pull origin main
python3 skills/permissions-broker/scripts/pb_git.py push origin HEAD:refs/heads/feature-x
```

Notes:

- Push sessions are single-use.
- Tag pushes and ref deletes are rejected.
- Default branch pushes may be blocked unless explicitly approved.

## Read-only Email (Separate from /v1/proxy)

IMAP email access (`/v1/email`) is session-gated and strictly read-only.

Flow:

1. Confirm the user has connected email (`/connect imap` in Telegram opens a broker-hosted
   form; the IMAP server is auto-detected from their address).
2. Create a session: `POST /v1/email/sessions` with `{ "consent_hint": "..." }`.
3. Poll the Telegram approval: `GET /v1/email/sessions/:id`.
4. Once `APPROVED`/`ACTIVE`, run read-only operations within the session window:

```bash
# list mailboxes
curl -H "Authorization: Bearer $PB_API_KEY" \
  $PB_BASE/v1/email/sessions/$SESSION_ID/folders

# search (curated filters only)
curl -X POST -H "Authorization: Bearer $PB_API_KEY" -H "content-type: application/json" \
  -d '{"mailbox":"INBOX","query":{"subject":"invoice","unseen":true}}' \
  $PB_BASE/v1/email/sessions/$SESSION_ID/search

# read a message (uid from search)
curl -X POST -H "Authorization: Bearer $PB_API_KEY" -H "content-type: application/json" \
  -d '{"mailbox":"INBOX","uid":123,"parts":{"text":true}}' \
  $PB_BASE/v1/email/sessions/$SESSION_ID/read
```

Rules:

- Sessions expire automatically (10 min).
- Only read operations exist; the broker opens mailboxes read-only (IMAP `EXAMINE`) and
  cannot modify, delete, or send mail.
- Request `text`/`html` bodies (or small `envelope`) to keep approvals and responses small;
  fetched message source is capped at 1 MiB.

## Security Rules

- Treat API keys and OAuth-linked access as sensitive.
- Do not log secrets.
- Do not commit secrets.
- Use narrow upstream reads to keep approvals clear and responses small.

## Resources

- `skills/permissions-broker/references/api_reference.md`
