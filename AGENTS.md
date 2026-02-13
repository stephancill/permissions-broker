# Agent Contributing Guide

This repo is a Bun + Hono service that gates external access behind Telegram approvals.
It has two primary surfaces:

1. Generic approval-gated HTTP proxy (`/v1/proxy/*`) for supported providers
2. Git smart-HTTP proxy (`/v1/git/*`) for clone/push sessions

Keep changes small, security-minded, and consistent with existing patterns.

## Quick Start

1. Install dependencies:

```bash
bun install
```

2. Configure env:

```bash
cp .env.example .env.local
```

Fill in at least:

- `TELEGRAM_BOT_TOKEN`
- `APP_BASE_URL` (publicly reachable for OAuth callback if testing OAuth locally)
- `APP_SECRET` (encrypts tokens at rest)
- OAuth client credentials (Google/GitHub)

3. Run the server:

```bash
bun --env-file .env.local run dev
```

Health check:

```bash
curl -sf http://localhost:3000/healthz
```

Migrations run automatically on startup. You can also run:

```bash
bun --env-file .env.local run migrate
```

## Commands (Run Before PR)

```bash
bun run format
bun run lint
bun run typecheck
bun test
```

Formatting/linting uses Biome.

## Repo Map

- `src/server.ts`: server wiring / router mounting
- `src/web/`: HTTP routes
  - `src/web/proxy.ts`: create/poll/execute proxy requests
  - `src/web/git.ts`: git session APIs + smart-HTTP proxy
  - `src/web/accounts.ts`: OAuth callback + list accounts
- `src/telegram/`: bot + polling
- `src/oauth/`: generic OAuth flow + state handling
- `src/providers/<provider>/`:
  - `oauth.ts`: OAuth provider config
  - `proxy.ts`: proxy-provider implementation (host allowlist, token handling, interpretation)
- `src/proxy/`:
  - `providerRegistry.ts`: routes URL host -> provider
  - `requests.ts`: proxy request persistence + hashing
  - `interpret.ts`: delegates to provider interpretability
- `migrations/`: SQLite schema migrations
- `skills/permissions-broker/`: agent skill + reference docs

## Core Concepts

### API keys

- Clients authenticate to the broker via `Authorization: Bearer <pb_...>`.
- The API key label is the identity shown to the user in Telegram.
- Do not accept "caller_label" or similar identity claims in request bodies.

### Proxy request lifecycle (`/v1/proxy`)

- Create: `POST /v1/proxy/request` (stores immutable request; always prompts Telegram)
- Status: `GET /v1/proxy/requests/:id` (status-only JSON)
  - Returns HTTP 202 with JSON for actionable states
- Execute: `POST /v1/proxy/requests/:id/execute`
  - Executes once and returns upstream bytes
  - Mirrors upstream HTTP status and content-type
  - Subsequent execute attempts return HTTP 410

Important:

- Status and execute are scoped to the exact API key that created the request.
- Never forward caller-provided upstream `authorization`; broker injects OAuth.

### Provider model

Proxy provider selection is based on `upstream_url.hostname`.

To add a new provider:

1. Add `src/providers/<id>/oauth.ts` for OAuth config
2. Add `src/providers/<id>/proxy.ts` implementing:
   - `allowedHosts`
   - `getAccessToken` (refresh vs direct)
   - `applyUpstreamRequestHeaderDefaults`
   - `interpretRequest` (best-effort human readable)
3. Register provider in:
   - `src/oauth/registry.ts` (OAuth)
   - `src/proxy/providerRegistry.ts` (proxy)
4. Update docs in `skills/permissions-broker/` as needed
5. Add/adjust tests

### Git session lifecycle (`/v1/git`)

- Create session: `POST /v1/git/sessions` with `operation: clone|push` and `repo: owner/repo`
- Poll: `GET /v1/git/sessions/:id`
- Remote URL: `GET /v1/git/sessions/:id/remote`
- Smart HTTP proxy path: `/v1/git/session/:id/:secret/...`

Sessions are short-lived and approval-gated via Telegram.
Push sessions enforce extra protections (no tags, no deletes, default branch gating).

## Security/Privacy Rules

- Never log secrets (API keys, OAuth tokens, session secrets).
- Tokens are encrypted at rest using `APP_SECRET`.
- Keep upstream allowlists strict (hosts + https).
- Prefer narrow reads and small payloads; broker enforces size limits.

## Testing Notes

- Tests run with `bun test`.
- In test env, OAuth can be bypassed in places; do not rely on bypass behavior in production code paths.

## Docs to Keep Updated

- `skills/permissions-broker/SKILL.md`
- `skills/permissions-broker/references/api_reference.md`
- `README.md`
- `docs/*.md` when adding major features
- `AGENTS.md` when for documenting code style, conventions, contribution guidelines
