---
name: permissions-broker
description: Interact with the Permissions Broker service to fetch data from Google APIs behind a Telegram approval gate. Use when an agent needs to read Google Drive/Docs/Sheets data via the broker (POST proxy request, wait for user approval in Telegram, poll for upstream response) and must respect one-time retrieval, host allowlist, and GET-only constraints.
---

# Permissions Broker

## Overview

Use the broker as a user-controlled proxy for data / action requests to external services e.g. Google Drive. You create an immutable request, prompt the user to approve in Telegram, then poll until you can retrieve the upstream response exactly once.

## Core Workflow

1. Collect inputs

- User API key (never paste into logs; never store in repo)

2. Create a proxy request

- Call `POST /v1/proxy/request` with:
  - `upstream_url`: the full external service API URL you want to call
  - optional `consent_hint`: plain-language reason for the user
  - optional `idempotency_key`: reuse request id on retries

3. Ask the user to approve

- Tell the user to approve the request in Telegram.
- The approval prompt includes:
  - API key label (trusted identity)
  - interpreted summary when recognized
  - raw URL details

4. Poll for status / retrieve result

- Poll `GET /v1/proxy/requests/:id` until terminal.
- If you receive the upstream response (HTTP 200/4xx/etc) you must parse and persist what you need immediately.
- Do not assume you can fetch the same result again: the broker consumes results on first retrieval.

## Constraints You Must Respect

- Upstream method: GET only.
- Upstream scheme: HTTPS only.
- Upstream host allowlist: `docs.googleapis.com` and `www.googleapis.com`.
- Upstream response size cap: 1 MiB.
- Result cache TTL: short-lived; results can expire if not retrieved quickly.
- One-time retrieval: on success, the broker consumes the cached response; subsequent polls return 410.

## Handling Common Terminal States

- 202: still pending (approval/execution). Keep polling.
- 403: denied by user.
- 408: approval expired (user did not decide in time).
- 410: result consumed or expired; recreate the request if you still need it.

## How To Build Upstream URLs (Google example)

Prefer narrow reads so approvals are understandable and responses are small.

- Drive search/list files: `https://www.googleapis.com/drive/v3/files?...`
  - Use `q`, `pageSize`, and `fields` to minimize payload.
- Drive export file contents: `https://www.googleapis.com/drive/v3/files/{fileId}/export?mimeType=...`
  - Useful for Google Docs/Sheets export to `text/plain` or `text/csv`.
- Docs structured doc read: `https://docs.googleapis.com/v1/documents/{documentId}?fields=...`

See `references/api_reference.md` for endpoint details and a Google URL cheat sheet.

## Data Handling Rules

- Treat the user's API key as secret.
- Do not print or persist the API key in logs, files, or commits.

## Resources

- Reference: `references/api_reference.md`
