# GitHub Provider - Git Clone/Push Proxy (Plan)

Last updated: 2026-02-13

This document proposes a GitHub provider that supports pure proxy `git clone` and `git push` over HTTPS (Git smart HTTP) behind a Telegram approval gate.

The key property is one approval per clone/push request (session), not per file.

## Goals

- Support basic `git clone` and `git push` for GitHub repositories via the broker.
- Require a single Telegram approval per clone/push session.
- Use the user's GitHub OAuth token server-side; never expose tokens to the agent.
- Warn about pushes to the default branch and block them unless explicitly approved.
- Disallow deletions.
- Disallow tag pushes.

## Non-goals (MVP)

- Git LFS
- Submodules (they can be handled as separate clone sessions)
- Diff preview / commit-level interpretability (pure git pack parsing is out of scope)
- Multi-instance support

## Background: Git smart HTTP endpoints

For a GitHub repo `owner/repo`, git over HTTPS uses:

Clone/fetch:

- `GET https://github.com/owner/repo.git/info/refs?service=git-upload-pack`
- `POST https://github.com/owner/repo.git/git-upload-pack` (streaming)

Push:

- `GET https://github.com/owner/repo.git/info/refs?service=git-receive-pack`
- `POST https://github.com/owner/repo.git/git-receive-pack` (streaming)

The broker should proxy only these paths and only to `github.com`.

## Architecture

Introduce an approved "git session".

1. Agent creates a session request (`clone` or `push`) via broker API.
2. Broker sends a Telegram prompt.
3. User approves once.
4. Broker returns a session-scoped remote URL containing a short-lived secret.
5. Agent runs `git clone`/`git push` against the broker remote URL.
6. Broker proxies Git smart HTTP requests to GitHub and enforces session policy.
7. Session expires after a short inactivity window and/or short TTL.
   Note: Git protocol v2 may issue multiple `git-upload-pack` POSTs for a single
   clone (e.g. `ls-refs`, then `fetch`), so "one POST" is too strict.

## Auth model

- Use GitHub OAuth token stored in `linked_accounts` with `provider=github`.
- Proxy to GitHub using Basic auth header:
  - `Authorization: Basic base64("x-access-token:<token>")`

## Data model

Add table `git_sessions`:

- `id` (ULID)
- `user_id`
- `api_key_id` (binds session to the exact API key)
- `provider` = `github`
- `operation` = `clone` | `push`
- `repo_owner`, `repo_name`
- `status`:
  - `PENDING_APPROVAL`, `APPROVED`, `DENIED`, `EXPIRED`, `ACTIVE`, `USED`, `FAILED`
- `created_at`, `updated_at`
- `approval_expires_at`
- `last_activity_at`
- `session_secret_hash` (sha256 of secret)
- policy flags:
  - `allow_default_branch_push` (bool)
  - `deny_deletes` (bool; always true)
  - `deny_tag_updates` (bool; always true)
- push metadata:
  - `default_branch_ref` (e.g. `refs/heads/main`), populated from handshake
- `error_code`, `error_message`

## Broker API endpoints (agent/app)

All endpoints require `Authorization: Bearer <USER_API_KEY>`.

1. Create session request

- `POST /v1/git/sessions`
- body:
  - `operation`: `clone` | `push`
  - `repo`: `owner/repo`
  - optional `consent_hint`
- response:
  - `session_id`
  - `status`
  - `approval_expires_at`

2. Poll status (status-only)

- `GET /v1/git/sessions/:id`
- key-scoped: only the API key that created the session can access it.

3. Get remote URL

- `GET /v1/git/sessions/:id/remote`
- returns `{ remote_url }` only once approved.

## Git proxy endpoints (called by git)

Remote URL format:

- `https://<broker>/v1/git/session/<session_id>/<secret>/github/<owner>/<repo>.git`

Proxy routes under that base:

- `GET  .../info/refs?service=git-upload-pack` (clone)
- `POST .../git-upload-pack` (clone)
- `GET  .../info/refs?service=git-receive-pack` (push)
- `POST .../git-receive-pack` (push)

Rules:

- Only `github.com` upstream.
- Only allow the endpoints above.
- Streaming proxy for POST bodies and responses.
- Enforce request/response byte limits and timeouts.
- Session expires after short inactivity.
- For clone/fetch, allow multiple `git-upload-pack` POSTs within the session.
- For push, the broker may mark the session used on the first
  `git-receive-pack` request.

## Push protections

Deletions:

- Disallow any ref delete (`newSha` is all zeros) in receive-pack commands.

Tags:

- Disallow any update to `refs/tags/*`.

Default branch warning/block:

- Determine default branch ref by parsing the `symref=HEAD:refs/heads/<name>` capability from the receive-pack handshake advertisement.
- By default, reject push commands that update the default branch ref.
- Telegram push approval provides two approve buttons:
  - Approve push (block default branch)
  - Approve push (allow default branch)

## Telegram prompts

Clone prompt:

- Repo: owner/repo
- Operation: Clone
- Buttons: Approve / Deny

Push prompt:

- Repo: owner/repo
- Operation: Push
- Warnings:
  - Deletions are not allowed
  - Tag pushes are not allowed
  - Default branch pushes are blocked unless explicitly allowed
- Buttons:
  - Approve push (block default branch)
  - Approve push (allow default branch)
  - Deny

## Implementation notes (MVP)

- Keep this feature isolated under `src/git/` and `src/providers/github/`.
- Add minimal pkt-line parsing utilities:
  - parse advertised capabilities to extract `symref=HEAD:...`
  - parse receive-pack command section up to the flush packet (`0000`) to enforce delete/tag/default-branch rules
- For request body inspection, buffer only the initial command section and then stream the remainder.

## Rollout order

1. Add GitHub OAuth provider config and connect flow.
2. Add git session DB + broker API endpoints.
3. Add Telegram approval flow for sessions.
4. Implement git proxy endpoints with streaming.
5. Add pkt-line parsing + push enforcement.
6. Add unit tests for pkt-line parsing and basic session gating.
