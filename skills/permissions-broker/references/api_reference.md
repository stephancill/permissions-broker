# Permissions Broker - Agent Reference

Keep this file as a quick reference for how an agent should call the broker.

## Broker API

Base URL: the broker service URL `https://permissions-broker.steer.fun`.

Auth

- Header: `Authorization: Bearer <USER_API_KEY>`
- The API key label (set by the user at key creation time) is the caller identity shown in Telegram approvals.

Create request

- `POST /v1/proxy/request`
- JSON body:
  - `upstream_url` (required): full https URL targeting allowed Google API hosts
  - `consent_hint` (optional): short explanation for the user
  - `idempotency_key` (optional): stable token to dedupe retries
- Response:
  - `request_id`
  - `status` (typically `PENDING_APPROVAL`)
  - `approval_expires_at`

Poll / retrieve

- `GET /v1/proxy/requests/:id`
- Non-terminal:
  - HTTP 202 with a small JSON status payload and `Retry-After`
- Terminal:
  - On success: returns upstream bytes (content-type preserved when available) exactly once
  - Subsequent calls: HTTP 410 (`result_consumed` or `result_expired`)
  - Denied: HTTP 403
  - Approval expired: HTTP 408

Debug

- `GET /v1/whoami` returns the authenticated key label and ids.

Connected services

- `GET /v1/accounts/`
- Response:
  - `accounts`: list of linked accounts for the authenticated user
    - `provider` (e.g. `google`)
    - `scopes`
    - `status`
    - other non-secret metadata

## Upstream URL Rules (MVP)

- Scheme: https only
- Method: GET only
- Allowed hosts:
  - `www.googleapis.com`
  - `docs.googleapis.com`

Practical guidance

- Prefer small, targeted responses; always use `fields` where supported.
- Prefer paginated list endpoints with small page sizes.

## Useful Google API URL Patterns

Drive list/search

- Host: `www.googleapis.com`
- Path: `/drive/v3/files`
- Query params:
  - `q` (Drive query language)
  - `pageSize`
  - `fields`

Drive get file metadata

- `/drive/v3/files/{fileId}?fields=...`

Drive export (Docs/Sheets to text formats)

- `/drive/v3/files/{fileId}/export?mimeType=text/plain`
- `/drive/v3/files/{fileId}/export?mimeType=text/csv`

Docs structured read

- Host: `docs.googleapis.com`
- Path: `/v1/documents/{documentId}`
- Query params:
  - `fields` (partial response)

## One-time Retrieval Gotchas

- Always parse and persist what you need on the first successful retrieval.
- If you need the same upstream content again, you must create a new proxy request (and the user must approve again).

## Recommended Agent Wording

Use short, action-forward phrasing. Do not lead with inability/disclaimer language.

Good:

- "I'll do that via your Permissions Broker. I'll request <upstream_url>, you approve in Telegram, then I'll fetch the result."
- "To read that Sheet in MVP, I'll export it via Drive as CSV and parse it."

Avoid:

- "I can't access your Google Drive" (the broker is the intended access mechanism)
- Long repo/setup explanations

## Safety / Secret Handling

- Never paste API keys into chat logs or commit them.
- Do not log full upstream responses if they may contain sensitive data.
