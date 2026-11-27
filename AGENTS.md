# Agent Contributing Guide

This repo is a Bun + Hono service that gates external access behind push-notified, passkey-confirmed approvals. Users interact through an installable PWA (`/app`).
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

- `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` / `VAPID_SUBJECT` (`bun scripts/vapid_keys.ts`)
- `APP_BASE_URL` (publicly reachable for OAuth callback if testing OAuth locally)
- `APP_SECRET` (encrypts short-lived approval keys, session secrets, and legacy credentials)
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

## Linting Rules

- Use Biome for both formatting and linting; do not add ESLint/Prettier alongside it.
- Run `bun run format` before `bun run lint` when touching JS/TS/JSON/MD; Biome will auto-fix formatting issues.
- Treat `bun run lint` (`biome check .`) as required; do not merge with lint failures.
- Prefer fixing issues over suppressing them. If suppression is necessary, keep it scoped and include a short rationale.
- CI runs Biome in GitHub Actions via the `Lint` workflow.

## Repo Map

- `src/server.ts`: server wiring / router mounting
- `src/web/`: HTTP routes
  - `src/web/proxy.ts`: create/poll/execute proxy requests
  - `src/web/git.ts`: git session APIs + smart-HTTP proxy
  - `src/web/email.ts`: read-only email session APIs (generic IMAP)
  - `src/web/release.ts`: Apple release sessions for CI (GitHub OIDC, ASC proxy, code signing); `src/web/appleReleaseConnect.ts`: the `apple-release` connect form
  - `src/web/accounts.ts`: OAuth callback + list accounts
  - `src/web/passkey.ts`, `src/web/approve.ts`: passkey enrollment and approval pages
- `src/web/app.ts`: PWA pages (inbox, API keys, accounts, settings), push subscribe, manifest + service worker
- `src/auth/session.ts`: passkey-created browser sessions (cookie), same-origin write checks
- `src/auth/apiKeyAdmin.ts`: API key create/rename/rotate/revoke
- `src/auth/device.ts`, `src/web/device.ts`: RFC 8628 device sign-in that issues API keys (approval page in `src/web/app.ts`, see `docs/DEVICE_AUTHORIZATION.md`)
- `src/web/mcp.ts`: MCP connector for Claude/ChatGPT (`/mcp` JSON-RPC endpoint, OAuth discovery, `/oauth/*` authorization server routes and consent page)
- `src/mcp/`: MCP tools (`tools.ts` registry; `proxyTools.ts`, `emailTools.ts`, `gitTools.ts` call `/v1` handlers in-process via `toolkit.ts`) and the OAuth authorization server logic (`oauthServer.ts`, see `docs/MCP_CONNECTOR.md`)
- `src/connect/links.ts`: OAuth/connect-form link creation, provider list
- `src/push/`: Web Push (VAPID + RFC 8291 encryption on WebCrypto) and per-user fan-out
- `public/`: PWA icons (Workers assets binding; `serveStatic` under Bun)
- `src/oauth/`: generic OAuth flow + state handling
- `src/email/`: read-only IMAP client, session persistence, curated ops
- `src/release/`: release policies and sessions, GitHub OIDC verification, the App Store Connect allowlist
- `src/apple/`: `apple-release` credential, ASC JWT, DER and CodeDirectory parsing, signing checks
- `src/providers/<provider>/`:
  - `oauth.ts`: OAuth provider config
  - `proxy.ts`: proxy-provider implementation (host allowlist, token handling, interpretation)
- `src/providers/imap/`: IMAP host auto-detection (connect flow)
- `src/proxy/`:
  - `providerRegistry.ts`: routes URL host -> provider
  - `requests.ts`: proxy request persistence + hashing
  - `interpret.ts`: delegates to provider interpretability
- `migrations/`: SQLite schema migrations
- `skills/stupid-vault/`: agent skill + reference docs

## Core Concepts

### API keys

- Clients authenticate to the broker via `Authorization: Bearer <pb_...>`.
- The API key label is the identity shown to the user in push notifications and approval pages.
- Do not accept "caller_label" or similar identity claims in request bodies.

### Device sign-in and the skill credential

- Agents get keys via `skills/stupid-vault/scripts/vault_auth.py login` (device flow).
- The skill scripts read only the credentials file (`~/.config/stupid-vault/credentials.json`,
  override `--credentials`); don't reintroduce env-var configuration in the skill.

### MCP connector (`/mcp`)

- Claude/ChatGPT sign in through the broker's own OAuth 2.1 server (DCR, PKCE S256,
  RFC 9207 `iss`); the access token is an ordinary API key labelled on the consent page.
- MCP tools must go through the existing `/v1` handlers with the caller's key
  (`callRoute` in `src/mcp/toolkit.ts`), not around them, so approvals stay identical.
- Keep the endpoint stateless (JSON responses, no SSE/sessions) and tool failures as
  `isError` results. Keep tools at parity with the skill when adding a `/v1` surface.
  See `docs/MCP_CONNECTOR.md`.

### Proxy request lifecycle (`/v1/proxy`)

- Create: `POST /v1/proxy/request` (stores immutable request; pushes to the user unless an approval window covers it)
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
4. Update docs in `skills/stupid-vault/` as needed
5. Add/adjust tests

### Git session lifecycle (`/v1/git`)

- Create session: `POST /v1/git/sessions` with `operation: clone|push` and `repo: owner/repo`
- Poll: `GET /v1/git/sessions/:id`
- Remote URL: `GET /v1/git/sessions/:id/remote`
- Smart HTTP proxy path: `/v1/git/session/:id/:secret/...`

Sessions are short-lived and approval-gated (push + passkey).
Push sessions enforce extra protections (no tags, no deletes, default branch gating).

### Email read session lifecycle (`/v1/email`)

- Create session: `POST /v1/email/sessions` (passkey approval required)
- Poll: `GET /v1/email/sessions/:id`
- Read ops: `GET /sessions/:id/folders`, `POST /sessions/:id/search`, `POST /sessions/:id/read`
- Sessions are short-lived, key-scoped, and **read-only by construction**:
  the IMAP client (`src/email/client.ts`) exposes only `list`/`search`/`fetch`/`fetchOne`
  and opens every mailbox with `EXAMINE`. Never add write methods there.

### Passkey-gated credentials

See `docs/PASSKEY_CREDENTIAL_ENCRYPTION.md`.

- Linked credentials are ECIES-encrypted to the user's public key; only the user's
  passkey (WebAuthn PRF) can unwrap the private key. The server can encrypt but
  never decrypt on its own.
- Approvals happen on `/approve/:kind/:id` (passkey assertion + DEK); the page
  requires the owner's web session. Deny needs only the session.
- Never read credentials with `decryptUtf8`; go through `src/credentials/store.ts`
  (`saveLinkedCredential`, `createGrant`, `unlockCredential`). Unlock rotates the
  ciphertext, so never cache decrypted credentials across requests.
- `src/passkey/clientCrypto.ts` must stay byte-compatible with
  `src/crypto/ecies.ts`; `tests/passkey_crypto.test.ts` checks this.
- Key-material pages must not load third-party scripts (see `src/web/pages.ts` CSP).

### Web sessions and push

See `docs/PWA_PUSH.md`.

- Accounts are identified by their passkey: sign-in is a usernameless assertion
  looked up by credential id. Sign-up is open only on an empty broker unless
  `ALLOW_SIGNUP=true`.
- Cookie-authenticated writes go through `requireSessionJson`/`requireSessionPage`
  (Origin / `Sec-Fetch-Site` check). Never add a cookie-authenticated POST without them.
- Push endpoints are restricted to the browser push services
  (`isAllowedPushEndpoint`); the broker must never POST to arbitrary URLs.
- Push payloads are end-to-end encrypted to the device but still keep them to
  summaries (no credentials, no response bodies).
- Never change `APP_BASE_URL`'s host without the domain migration in
  `docs/DOMAIN_MIGRATION.md`: passkeys are bound to their RP ID. Use the stored
  `user_passkeys.rp_id` (via `getUserPasskey`/`passkeyRpId`), never assume the
  current host, when verifying or requesting assertions.
- `users.telegram_user_id` is a legacy NOT NULL UNIQUE column that cannot be
  dropped on D1 (rebuilding `users` cascades deletes). New users get a random
  negative placeholder; nothing reads it.

## Security/Privacy Rules

- Never log secrets (API keys, OAuth tokens, session secrets, DEKs, PRF output).
- Credentials are encrypted to the user's passkey-held key; `APP_SECRET` only protects short-lived grants and legacy rows.
- Keep upstream allowlists strict (hosts + https).
- Prefer narrow reads and small payloads; broker enforces size limits.

## Testing Notes

- Tests run with `bun test`.
- In test env, OAuth can be bypassed in places; do not rely on bypass behavior in production code paths.

## Docs to Keep Updated

- `skills/stupid-vault/SKILL.md`
- `skills/stupid-vault/references/api_reference.md`
- `README.md`
- `docs/*.md` when adding major features
- `AGENTS.md` when for documenting code style, conventions, contribution guidelines
