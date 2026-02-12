# Permissions Broker - MVP Implementation Plan

Last updated: 2026-02-09

This plan implements `docs/TECH_SPEC_MVP.md` and keeps OAuth integration generic so we can add providers beyond Google later.

## Tech Stack

- Runtime: Bun (TypeScript)
- HTTP framework: Hono
- Database: SQLite via Bun built-in driver (`bun:sqlite`)
- Telegram integration (long polling): grammY
- OAuth (provider-agnostic): oauth4webapi
- Validation: zod
- IDs: ULID (or equivalent monotonic ID)
- Logging: pino (optional but recommended)

## Packages

Core

- `hono`
- `grammy`
- `oauth4webapi`
- `zod`
- `ulid`

Optional

- `pino` (structured logs)

Deliberately not using in MVP

- ORMs (keep SQL explicit)
- provider-specific SDKs (keep proxy behavior generic)

## Repository Layout (Suggested)

- `src/server.ts` (Bun serve + Hono app wiring)
- `src/env.ts` (zod-validated env)
- `src/db/` (sqlite open, migrations, queries)
- `src/crypto/` (sha256 helpers; AES-GCM encrypt/decrypt)
- `src/telegram/` (grammY bot, command handlers, approval UI)
- `src/oauth/` (generic OAuth provider config + flows)
- `src/providers/` (provider-specific configs and adapters)
- `src/providers/google/` (Google-specific OAuth config for MVP)
- `src/proxy/` (request creation, canonicalization, direct execution)
- `src/audit/` (audit helpers)
- `migrations/` (SQL migrations)
- `docs/` (specs)

## Milestones

### Milestone 0 - Project Scaffold

- Create Bun project setup (scripts: dev/test/lint)
- Add basic health endpoint (HTTP server running)
- Add config loader with zod
- Decide logging:
  - simplest: `console` wrapper
  - recommended: pino with request_id correlation

Exit criteria:

- `bun run dev` starts server successfully
- config validation fails fast with clear errors

Implementation notes:

- Added minimal Bun + TypeScript scaffold with Hono and a health endpoint (`src/server.ts`).
- Added zod-based env parsing with sensible defaults so `bun run dev` starts without secrets (`src/env.ts`, `.env.example`).
- Added basic scripts for dev/test/typecheck/lint/format and installed tooling (TypeScript + Biome).
- Added repo hygiene (`.gitignore`) and a minimal `README.md` with local dev commands.

### Milestone 1 - SQLite Schema + Migrations

- Implement a minimal migration runner:
  - `schema_migrations` table
  - sequential SQL files in `migrations/`
- Create tables from `docs/TECH_SPEC_MVP.md`:
  - `users`, `api_keys`, `linked_accounts`, `oauth_states`, `proxy_requests`, `approvals`, `audit_events`, `telegram_state`
- Add critical constraints and indexes:
  - unique `(user_id, label)` on `api_keys`
  - unique `(api_key_id, idempotency_key)` where present on `proxy_requests`
  - indexes for status polling loops

Exit criteria:

- fresh DB can be migrated end-to-end
- migrations are idempotent (do not reapply)

Implementation notes:

- Added a minimal SQL migration system backed by a schema_migrations table.
- Created the initial schema migration covering users, API keys, linked accounts, OAuth state, requests, approvals, audit events, and Telegram cursor.
- Added a `bun run migrate` script to apply migrations to the configured SQLite file.

### Milestone 2 - Telegram Bot (Long Poll) + Key Management

- Stand up grammY bot long polling
- Persist `last_update_id` to SQLite (`telegram_state`)
- Implement user + key UX:
  - `/start` creates user mapping
  - `/key` interactive flow: prompt for label (required), create key, show once
  - `/keys` list keys + actions:
    - rename (enforce unique label per user)
    - revoke
    - rotate (revoke + new key)
- Add audit events:
  - key created/renamed/revoked/rotated

Exit criteria:

- bot restarts without reprocessing old updates
- keys can be created and renamed with uniqueness enforced

Implementation notes:

- Use grammY for update parsing/handlers, but implement the getUpdates polling loop manually so we can persist last_update_id in SQLite.
- Store simple "pending input" state in SQLite for label capture (create/rename/rotate) so interactive flows survive process restarts.
- Bind caller identity to the API key label (user-controlled) and never accept caller labels from request payloads.

### Milestone 3 - Generic OAuth Framework (Provider Registry)

Goal: a provider-agnostic OAuth module with a thin provider config, so adding providers later is mostly configuration plus minor adapter code.

Implement `src/oauth/` with:

- Provider config shape (minimum):
  - provider id (string)
  - authorization endpoint
  - token endpoint
  - requested scopes
  - PKCE required? (boolean)
  - any extra authorize params (map)
- State storage using `oauth_states`:
  - state value, expiry, user_id, provider
  - optional PKCE verifier
- Generic functions:
  - build authorization URL
  - handle callback (code exchange)
  - refresh access token using refresh token

Add Google as first provider config in `src/providers/google/`.

Notes:

- oauth4webapi is standards-based and keeps the core logic portable across providers.
- Some providers are non-compliant; plan for an escape hatch:
  - allow provider configs to override token parsing or include custom parameters.

Exit criteria:

- `/connect` can generate an authorization link (Google provider)
- callback stores encrypted refresh token + scopes in `linked_accounts`

Implementation notes:

- Implement OAuth flows in a provider-agnostic module with a provider registry and per-provider config living under `src/providers/`.
- Store OAuth state (and PKCE verifier) in SQLite so callback handling is stateless and restart-safe.
- Encrypt refresh tokens before storing in SQLite; do not log secrets.

### Milestone 4 - API Key Authentication Middleware

- Define API key format and issuance
- Store `key_hash = sha256(key)` (fast hash; acceptable given high entropy)
- Hono middleware:
  - parse Bearer token
  - hash and lookup
  - enforce not revoked
  - update `last_used_at`

Exit criteria:

- protected endpoint returns 401 for invalid key and 200 for valid key

Implementation notes:

- Implement Hono middleware that validates `Authorization: Bearer <api_key>`, looks up the hashed key in SQLite, and attaches `userId/apiKeyId/apiKeyLabel` to the request context.
- Update `last_used_at` on successful auth.
- Add a simple `GET /v1/whoami` endpoint for manual verification during development.

### Milestone 5 - Proxy Request Creation (Always Prompts)

- Implement `POST /v1/proxy/request`:
  - validate `upstream_url`:
    - https only
    - host allowlist: `docs.googleapis.com`, `www.googleapis.com`
    - no embedded credentials
  - method fixed to GET
  - canonicalize URL + compute `request_hash`
  - insert `proxy_requests` with `PENDING_APPROVAL` and TTL
  - snapshot API key label (`api_key_label_snapshot`)
  - idempotency behavior using `idempotency_key`
- Trigger Telegram approval message (see Milestone 6)

Exit criteria:

- request row created correctly, idempotency works

Implementation notes:

- Validate and canonicalize the upstream URL (https only, allowed hosts only) before storing.
- Compute a stable request hash from the canonical request so the approval prompt can reference it.
- Always create a Telegram approval prompt on request creation; bind the prompt identity to the API key label snapshot.

### Milestone 6 - Approval UI (Interpretability + Raw)

- Build a URL recognizer for nicer summaries:
  - Docs `documents.get`
  - Drive v3 file get/list
- Always show raw host/path and raw query params (truncated)
- Telegram message includes:
  - API key label snapshot (trusted)
  - requester note (unverified): consent_hint
  - hash prefix
  - Approve/Deny buttons
- Approval handling:
  - owner-only
  - pending-only
  - expiry checks
  - transition to APPROVED/DENIED

Exit criteria:

- approving and denying update DB state reliably

Implementation notes:

- Implement a URL recognizer that extracts a human summary + key parameters for common Docs/Drive read endpoints.
- Always include raw host/path and raw query parameters (truncated) so unrecognized endpoints remain reviewable.
- Keep callback_data small and opaque; the request id is the only identifier needed.

### Milestone 7 - Executor Loop + In-Memory Result Cache

Note: This milestone is now implemented as a direct execution endpoint (no executor loop, no caching).

Updated architecture: direct execution endpoint, no caching.

- Add execute endpoint:
  - claim APPROVED -> EXECUTING in SQLite to prevent double execution
  - fetch access token via refresh token
  - fetch upstream URL (GET) with injected Authorization header
  - enforce upstream timeout
  - enforce max response bytes (1 MiB)
  - persist SUCCEEDED only for upstream 2xx; otherwise FAILED
  - return upstream bytes directly from the execute endpoint

Exit criteria:

- an approved request can be executed once and returns upstream bytes

Implementation notes:

- Execute only on demand via an explicit execute endpoint.
- Claim work by transitioning APPROVED -> EXECUTING in SQLite to avoid duplicate execution.
- Persist terminal metadata (status/content-type/bytes) in SQLite, but do not store upstream bodies.

### Milestone 8 - Polling/Retrieval Endpoint

- Implement `GET /v1/proxy/requests/:id`:
  - non-terminal returns 202 + status JSON
  - denied/expired return 403/408
  - terminal returns metadata only (status endpoint)

- Implement `POST /v1/proxy/requests/:id/execute`:
  - requires status APPROVED
  - executes the upstream request and returns upstream bytes
  - one-time execution (subsequent calls return 410)

Exit criteria:

- caller can poll status and execute the request once

Implementation notes:

- Keep `GET /v1/proxy/requests/:id` status-only.
- Add `POST /v1/proxy/requests/:id/execute` to return upstream bytes once.
- Enforce that execute must use the same API key that created the request.

### Milestone 9 - Sweeper Loop

- Expire pending approvals past `approval_expires_at` -> EXPIRED

Exit criteria:

- approvals expire automatically

Implementation notes:

- Periodically transition PENDING_APPROVAL requests past approval_expires_at to EXPIRED.

### Milestone 10 - Tests + Hardening

- Unit tests:
  - URL allowlist validation
  - canonicalization stability
  - truncation rules for Telegram
  - state transitions and TTL behavior
  - one-time execute correctness
- Integration-like tests:
  - stub upstream HTTP server (simulate Google)
  - simulate approvals by updating DB and/or invoking handlers

Exit criteria:

- critical flows covered and deterministic

Implementation notes:

- Add unit tests for URL validation/canonicalization, interpretability parsing, one-time execute semantics, and response size limiting.
- Keep integration tests lightweight by stubbing upstream HTTP responses when needed.

## Key Tradeoffs (MVP Acknowledgements)

- Upstream response bodies are not persisted; if a client needs the body again it must create a new request and be re-approved.
- OAuth is designed to be generic, but providers may require per-provider quirks.
- Dropping operation allowlists makes the proxy more flexible, but pushes safety into host boundaries, method boundaries (GET only), and user approvals.
