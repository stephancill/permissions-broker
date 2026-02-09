## 0) What you’re building

A Telegram bot + backend that:

1. Lets a user **connect external accounts** (OAuth).
2. Stores **tokens/credentials** in a secure vault.
3. Exposes a **single proxy API** per user (via API key) that other apps/agents can call.
4. For sensitive operations, the proxy **pauses** and sends a Telegram approval prompt with inline **Approve/Deny** buttons.
5. On approval, the proxy executes the request against the provider and returns the response to the caller.
6. The “agent skill” is simply a client that calls your proxy API with the user’s key.

---

## 1) Core components

### A) Telegram Bot

* Handles:

  * `/start`, `/connect`, `/accounts`, `/revoke`, `/sessions`, `/policies`
  * Approval prompts with inline buttons
  * Displays request details and risk summary
* Stores:

  * Telegram user id ↔ internal user id mapping
  * Notification preferences (always approve small reads, etc.)

### B) Backend API (your product)

* Public endpoints:

  * `POST /v1/proxy/request` (agent calls this)
  * `GET /v1/proxy/requests/{id}` (poll status / retrieve result)
  * `POST /v1/accounts/connect/{provider}` (start OAuth)
  * `GET /v1/accounts/callback/{provider}` (OAuth callback)
* Internal services:

  * Policy engine (approve rules, scopes)
  * Request queue + state machine
  * Provider connectors (Google Docs/Drive, etc.)
  * Audit log service

### C) Credential Store / Vault

* Never store raw passwords if you can avoid it.
* Prefer:

  * OAuth refresh tokens
  * Service account keys only when absolutely necessary
* Encryption:

  * Envelope encryption (KMS for data keys)
  * Per-user keying ideally
* Rotation + revocation support

### D) Database

Tables you’ll want:

* `users` (telegram_id, created_at, status)
* `api_keys` (user_id, hashed_key, created_at, revoked_at, last_used_at)
* `linked_accounts` (user_id, provider, provider_user_id, scopes, token_ref, status)
* `proxy_requests` (id, user_id, provider, method, resource, params, body_hash, risk_level, status, created_at, expires_at)
* `approvals` (request_id, telegram_message_id, decision, decided_at)
* `audit_events` (who/what/when, request metadata, outcome)

### E) Queue/Worker

* A worker processes approved requests.
* Another worker handles timeouts and retries.

---

## 2) UX flows

### Flow 1 — Onboarding

1. User finds bot → `/start`.
2. Bot explains the system + warns about approvals + privacy.
3. User taps “Generate API Key”.
4. Bot shows API key **once** and encourages saving it (and provides a “Rotate key” option).

### Flow 2 — Connect an account (OAuth)

1. User: `/connect`
2. Bot: list providers (Google, Notion, Slack…)
3. User chooses Google → bot replies with OAuth link.
4. OAuth callback hits your backend → store refresh token in vault.
5. Bot confirms: “Google connected. Scopes: …”

### Flow 3 — Agent calls proxy API (request created)

Agent sends:

* user API key
* provider (e.g., google)
* operation descriptor (e.g., “drive.files.list”)
* parameters
* optional “consent_hint” (why it needs this)

Backend:

* Authenticates API key → user_id
* Validates provider is linked
* Runs policy engine:

  * if auto-approved: execute immediately
  * else: create pending request → send Telegram approval message

### Flow 4 — Telegram approval

Telegram message includes:

* “Agent wants to: **Read file list in Google Drive**”
* Request details (scopes, file/folder name, query)
* Risk label (“Read-only”, “Write”, “Share”, “Delete”, “Financial”)
* Buttons:

  * ✅ Approve once
  * ✅ Approve always for this operation (optional)
  * ❌ Deny
  * 🕒 Allow for 10 minutes (optional)
  * 🔍 View full JSON (optional)

On click:

* Bot calls backend `POST /v1/approvals/{request_id}` with decision
* Backend releases/denies the request

### Flow 5 — Result delivery

Caller can:

* Block until complete (short timeout), OR
* Receive `202 Accepted` with request id and poll `GET /v1/proxy/requests/{id}`

---

## 3) Permission + safety model (critical)

### A) Default-deny, allowlist operations

Do NOT accept arbitrary “proxy any HTTP request” at first.
Instead, define:

* Providers with explicit connector methods
* Allowlisted operations per provider

Example:

* Google Drive: list files, get file, export doc
* Google Docs: read doc content, insert text (write)
* Keep “delete”, “share externally”, “change permissions” disabled initially

### B) Scopes minimalism

Each provider link is created with minimal scopes:

* Read-only by default
* User must explicitly add write scopes later

### C) Risk-based approvals

Auto-approve only low-risk reads under certain thresholds:

* “List up to 20 file names”
* “Read a specific doc by id”
  Always prompt for:
* write actions
* permission changes
* deletes
* bulk exports
* external sharing

### D) Request integrity

Agent shouldn’t be able to trick approval by changing the request after user sees it.
So:

* Store a canonical request payload
* Display a stable summary + hash in Telegram
* On approval, execute the exact stored payload

### E) Time limits + replay prevention

* Approval expires (e.g. 2 minutes)
* Each request id single-use
* Idempotency keys for callers

---

## 4) API design sketch (minimal)

### Authentication

* `Authorization: Bearer <USER_API_KEY>`
* Store only hashed API keys (like password hashing), never plaintext.

### Create request

`POST /v1/proxy/request`

```json
{
  "provider": "google_drive",
  "operation": "files.list",
  "params": { "q": "mimeType='application/vnd.google-apps.document'", "pageSize": 20 },
  "consent_hint": "Need a list of docs to find your resume."
}
```

Response:

* `200` with immediate result, OR
* `202` with `{ "request_id": "...", "status": "PENDING_APPROVAL" }`

### Check status/result

`GET /v1/proxy/requests/{request_id}`

* returns status + result or denial reason

### Manage accounts

* `/v1/accounts` list linked providers
* `/v1/accounts/revoke/{provider}` revoke tokens

---

## 5) Telegram implementation notes

* Use inline keyboard callback data containing:

  * request_id
  * action (approve/deny)
* Verify the callback comes from the same telegram_id tied to the request’s user_id.
* Keep approval messages short; provide “View details” button for the rest.
* Handle bot being blocked / user offline:

  * request sits pending until expiry
  * caller gets pending state

---

## 6) Security checklist (non-negotiable)

1. **OAuth only** for mainstream providers; avoid password storage.
2. Encrypt tokens at rest (KMS + envelope encryption).
3. Strict operation allowlist; no arbitrary URL proxying.
4. Bind request → approval → execution (immutable payload).
5. Full audit trail (what was requested, what was approved, what happened).
6. API key rotation + immediate revocation.
7. Rate limits per API key + per user.
8. Provider token revocation support.
9. Don’t log sensitive payloads (doc content, tokens) in plaintext logs.
10. Separate environments; protect callback endpoints and webhooks.

---

## 7) MVP scope (build order)

### Phase 1 — “Read-only Google Drive/Docs”

* Telegram bot + backend auth
* API key issuance + rotation
* Google OAuth connect (read-only scopes)
* 3 operations:

  * Drive: list docs
  * Docs: read doc text (or export)
  * Drive: get file metadata
* Per-request approval always (simplify)
* Request state machine + polling

### Phase 2 — Policies + better UX

* Auto-approve rules for safe reads
* “Approve for 10 minutes”
* “Approve always for X operation”
* Better summaries + JSON view

### Phase 3 — More providers + write operations

* Add Notion, Slack, GitHub
* Introduce write operations with strict prompts
* Fine-grained scope upgrades

---

## 8) “Skill for your agent” integration

Your agent skill does:

* store user’s API key (or fetch from a secure secrets manager)
* call `POST /v1/proxy/request` when it needs external data
* handle `202` by polling
* interpret denial: ask user for alternative or re-request with narrower scope

Important: design your approval prompts so the user can understand *why* the agent is asking and what it will do.

---

## 9) The biggest risk to address upfront

If “anyone can call using your account’s API key,” then **the API key is effectively a master key**. That’s dangerous.

Mitigations:

* support **multiple keys** per user (per-agent, per-app) with separate policies
* scoped keys (only Google read-only, etc.)
* per-key rate limits
* show “Caller label” in approval prompts (“Request from: ResumeAgent v1”)

---

If you want, I can write:

* the request state machine spec (states, transitions, timeouts)
* a provider connector spec for Google Drive/Docs (operations + scopes + prompt templates)
* a policy DSL (how “Approve always” rules are represented safely)
