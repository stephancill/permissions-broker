# Permissions Broker - MVP Technical Specification

Last updated: 2026-02-09

## Overview

Permissions Broker is a Telegram-controlled proxy for Google APIs. An agent/app calls a single proxy API using a user-issued API key. For every request, the system pauses and asks the user on Telegram to approve or deny. On approval, the system executes the request using the user's Google OAuth credentials and returns the upstream response to the caller via polling.

This MVP intentionally optimizes for:

- local development simplicity
- transparent approvals
- "drop-in" upstream response semantics (status/body/headers) for terminal responses

## Goals (MVP)

- Telegram bot supports:
  - onboarding and linking a Google account (OAuth)
  - issuing API keys with user-defined labels (required, unique per user)
  - approvals with Approve/Deny buttons
- Proxy API supports:
  - creating a proxy request for an upstream Google API URL
  - polling for status and retrieving the upstream response exactly once
- Integrity:
  - the request shown for approval is the exact request executed (immutable, hashed)
- Interpretability:
  - show a human summary for recognized Docs/Drive reads
  - always show the raw URL and raw query parameters (truncated) for user decision-making
- Storage:
  - no persistent storage of upstream response bodies
  - ephemeral in-memory result cache with short TTL; consumed on first retrieval

## Non-Goals (MVP)

- No write operations (no POST/PATCH/PUT/DELETE)
- No webhook-based Telegram integration (use long polling only)
- No job queue infrastructure (single-process, in-memory cache)
- No auto-approve policies (every request prompts)
- No multi-instance deployment support (no cross-process caching / distributed locks)
- No arbitrary outbound proxying (strict host allowlist)

## Key Decisions (Locked)

- Runtime: Bun
- HTTP framework: Hono
- DB: SQLite (Bun built-in driver)
- Telegram: long polling (getUpdates) with persisted cursor
- Upstream request boundary:
  - HTTPS only
  - hosts allowed: docs.googleapis.com, www.googleapis.com
  - method allowed: GET only
  - request bodies disallowed
- Approval TTL: 2 minutes
- Result cache TTL: 2 minutes (in-memory only)
- Upstream response size cap: 1 MiB
- API key labels:
  - required at creation
  - unique per user
  - editable later
  - snapshot at request creation for consistent approvals/audit

---

## Architecture

Single Bun process runs four components:

1. HTTP API (Hono)

- public proxy endpoints (create request, poll/retrieve)
- OAuth connect and callback endpoints

2. Telegram poller loop

- calls Telegram getUpdates using long polling
- processes commands and approval callbacks
- persists last_update_id in SQLite

3. Executor loop

- processes approved requests
- fetches Google access token (refresh token flow)
- executes upstream GET against Google API
- stores terminal status metadata in SQLite
- stores upstream response bytes in in-memory cache (TTL + size cap)

4. Sweeper loop

- expires pending approvals past TTL
- evicts expired cache entries
- updates result_state when cache entries expire without retrieval

Deployment assumption (MVP): one process, one SQLite DB file.

---

## Data Model (SQLite)

All timestamps should be stored consistently (e.g., ISO8601 or unix millis). Exact SQLite types are implementation detail; use TEXT/INTEGER/BLOB as appropriate.

### users

- id (PK)
- telegram_user_id (unique)
- created_at
- status (e.g., active/blocked)

### api_keys

- id (PK)
- user_id (FK -> users)
- label (NOT NULL; unique per user)
- key_hash (NOT NULL; never store plaintext key)
- created_at
- updated_at (for rename tracking)
- revoked_at (nullable)
- last_used_at (nullable)

Uniqueness constraints:

- unique(user_id, label)
- unique(key_hash)

### linked_accounts

- id (PK)
- user_id (FK)
- provider (string identifier; google in MVP)
- provider_user_id (Google subject / user id)
- scopes (text)
- refresh_token_ciphertext (encrypted at rest)
- status (active/revoked)
- created_at
- revoked_at (nullable)

### oauth_states

- state (PK; random)
- user_id (FK)
- provider (string identifier; google in MVP)
- created_at
- expires_at
- used_at (nullable)
- pkce_verifier (nullable; only if PKCE is used)

### proxy_requests

- id (PK; ULID recommended)
- user_id (FK)
- api_key_id (FK)
- api_key_label_snapshot (NOT NULL)
- upstream_url (NOT NULL; full URL)
- request_hash (NOT NULL; sha256 of canonical payload)
- consent_hint (nullable; requester-provided note, untrusted)
- status (enum):
  - PENDING_APPROVAL
  - APPROVED
  - DENIED
  - EXECUTING
  - SUCCEEDED
  - FAILED
  - EXPIRED
- created_at
- updated_at
- approval_expires_at
- idempotency_key (nullable; unique per api key when present)
- Upstream metadata (terminal):
  - upstream_http_status (nullable)
  - upstream_content_type (nullable)
  - upstream_bytes (nullable)
- Result lifecycle:
  - result_state (enum): NONE | AVAILABLE | CONSUMED | EXPIRED
- Error fields (sanitized proxy-side):
  - error_code (nullable)
  - error_message (nullable)

Uniqueness constraints:

- unique(api_key_id, idempotency_key) where idempotency_key is not null

### approvals

- request_id (PK, FK -> proxy_requests; 1:1)
- telegram_chat_id
- telegram_message_id
- decision (approved/denied)
- decided_at
- decided_by_telegram_user_id

### audit_events (append-only)

- id (PK)
- created_at
- user_id (nullable)
- request_id (nullable)
- actor_type (api_key/telegram/system)
- actor_id (string/integer)
- event_type (string)
- event_json (sanitized metadata only)

### telegram_state

- singleton row:
  - id (fixed, e.g., 1)
  - last_update_id

Recommended indexes:

- api_keys(key_hash)
- proxy_requests(status, approval_expires_at)
- linked_accounts(user_id, provider, status)
- audit_events(user_id, created_at)

---

## Request Canonicalization and Integrity

The system must ensure "what the user approves is what executes".

Canonical payload includes:

- HTTP method (fixed GET in MVP)
- normalized upstream_url, including:
  - scheme, host, path
  - query parameters sorted by key (stable encoding; do not drop unknown keys)
- allowed caller headers (MVP: none forwarded; optionally Accept later)

Compute:

- request_hash = sha256(canonical_payload)

Rules:

- Store the canonicalized representation (or enough source data to deterministically reconstruct it) and request_hash in SQLite at request creation.
- Display a short prefix of request_hash in Telegram prompts.
- Execution uses the stored upstream_url (and method) from the DB record; never reuses caller-provided request material after creation.

---

## Proxy API (Public)

Authentication:

- Request header: Authorization: Bearer <USER_API_KEY>
- API key is associated with a single user and a user-provided label.

### POST /v1/proxy/request

Purpose:

- Create a new proxy request record and trigger a Telegram approval prompt.

Inputs:

- upstream_url (required)
- consent_hint (optional; untrusted requester note shown as such)
- idempotency_key (optional; caller-controlled dedupe token)

Validation:

- API key must be active, not revoked
- user must have active linked Google account
- upstream_url must be:
  - https scheme
  - host in allowlist (docs.googleapis.com or www.googleapis.com)
  - no userinfo / credentials embedded
- method is GET (no override)
- request body is not supported

Behavior:

- Create proxy_requests row with:
  - status = PENDING_APPROVAL
  - approval_expires_at = now + 2 minutes
  - api_key_label_snapshot from the key at creation time
- Send Telegram message prompting approval.

Idempotency behavior:

- If idempotency_key is provided and an existing request exists for the same api_key_id, return the existing request_id and current status without creating a new Telegram prompt.

Response:

- Always returns immediately with:
  - request_id
  - status
  - approval_expires_at

### GET /v1/proxy/requests/:request_id

Purpose:

- Poll status and (once terminal) retrieve upstream response exactly once.

Non-terminal statuses:

- For PENDING_APPROVAL / APPROVED / EXECUTING:
  - return HTTP 202
  - include a small proxy status payload (status + timestamps + request_id)
  - include Retry-After (suggest 1-2 seconds)

Denied/expired:

- DENIED:
  - HTTP 403
  - proxy error payload includes error_code=DENIED, plus request_id
- EXPIRED (approval TTL elapsed without decision):
  - HTTP 408
  - proxy error payload includes error_code=APPROVAL_EXPIRED, plus request_id

Success:

- If request is SUCCEEDED and cached result is AVAILABLE:
  - return upstream HTTP status (typically 200)
  - return upstream body bytes as-is
  - return upstream Content-Type when known
  - include X-Proxy-Request-Id: <request_id>
  - consume-on-read: delete cached body and mark result_state=CONSUMED

Consumed/expired result:

- If SUCCEEDED and result_state=CONSUMED:
  - HTTP 410 with error_code=RESULT_CONSUMED
- If SUCCEEDED and result_state=EXPIRED:
  - HTTP 410 with error_code=RESULT_EXPIRED

Failure:

- If FAILED:
  - preserve upstream HTTP status and upstream error body when available and within size cap
  - otherwise return proxy error payload with error_code=UPSTREAM_FAILED (or more specific codes)

Drop-in principle (terminal responses):

- Terminal success/failure should return upstream bytes unwrapped, so client parsing matches direct Google API usage.
- Proxy metadata is added via headers, not body modification.

---

## Telegram Bot (Polling)

Transport:

- Use Telegram getUpdates long polling.
- Store and update telegram_state.last_update_id durably.

Core commands (MVP):

- /start
  - create user mapping
  - show brief safety and how approvals work
- /connect
  - initiate OAuth connect for Google
- /accounts
  - list linked Google account (provider_user_id / email if available) and scopes
- /key
  - interactive flow: ask for label (required, unique per user), then create key and display once
- /keys
  - list keys with label, created_at, last_used_at, status
  - actions:
    - Rename (update label; must remain unique per user)
    - Revoke
    - Rotate (revoke + create new key; new label required)

Approval messages:

- Always include:
  - API key label (trusted: user-defined)
  - Requester note (unverified): consent_hint (if present)
  - Interpreted summary when recognized (Docs/Drive)
  - Raw host + path
  - Raw query params (truncated)
  - Hash prefix
- Buttons:
  - Approve
  - Deny
  - (Optional) Details for expanded raw query display

Callback validation:

- Only the owning Telegram user may decide.
- Only if request is still PENDING_APPROVAL and not expired.
- Decision is single-use.

---

## OAuth (Generic; Google in MVP)

Flow:

- Telegram /connect triggers OAuth start (for a specific provider, google in MVP):
  - create oauth_states row
  - redirect user to the provider consent screen
- OAuth callback:
  - validate state exists, unused, not expired
  - exchange code for tokens using the provider's token endpoint
  - store refresh token encrypted at rest in linked_accounts.refresh_token_ciphertext (when issued)
  - store granted scopes
  - notify user via Telegram

Provider configuration (implementation detail, required for extensibility):

- Each OAuth provider should be defined by a config entry containing:
  - authorization endpoint
  - token endpoint
  - scopes
  - whether PKCE is required
  - any provider-specific extra parameters

Token refresh:

- On execution, exchange refresh token for access token on-demand.
- Never log tokens.

Scopes:

- MVP should request the minimal scope set that supports the intended use cases (Docs/Drive reads).
- Requests to APIs outside granted scopes will fail with upstream authorization errors; this is acceptable and should be shown transparently.

---

## Execution and Caching

Executor loop behavior:

- Claim APPROVED requests by transitioning to EXECUTING in a transaction.
- Execute upstream GET with:
  - injected Authorization header from user's access token
  - no caller-provided Authorization/Cookie forwarding
- Enforce response cap:
  - if response exceeds 1 MiB, terminate read and mark FAILED with RESPONSE_TOO_LARGE
- On success:
  - mark SUCCEEDED
  - write upstream metadata (status, content-type, bytes)
  - set result_state=AVAILABLE
  - store body bytes in in-memory cache for 2 minutes
- On failure:
  - mark FAILED
  - store upstream metadata when available
  - cache upstream error body only if within size cap and useful for drop-in behavior

Sweeper loop behavior:

- For PENDING_APPROVAL where approval_expires_at < now:
  - set status=EXPIRED
- For cache entries past TTL:
  - evict entry
  - set result_state=EXPIRED for SUCCEEDED requests that were never retrieved

Known limitation:

- If the process restarts, cached results are lost; requests may become RESULT_EXPIRED even if SUCCEEDED.

---

## Interpretability Rules (MVP)

The bot attempts recognition for a better summary, but never hides raw request data.

Recognize and summarize:

- Docs read:
  - host = docs.googleapis.com
  - path corresponds to Docs document read endpoint
  - extract document id from path
- Drive reads:
  - host = www.googleapis.com
  - path corresponds to Drive v3 file list/get endpoints
  - extract file id from path when present
  - extract common query keys like q, pageSize, fields

Always show raw:

- host + path always shown
- query parameters shown as key/value pairs with truncation rules

Truncation rules:

- cap total keys displayed (e.g., first 20 keys)
- cap each value length (e.g., 200 chars)
- always show if fields exists (truncated) because it materially changes response shape

---

## Error Handling and Status Codes

Proxy-level errors (examples):

- INVALID_API_KEY (401)
- API_KEY_REVOKED (401/403)
- NO_LINKED_ACCOUNT (409)
- INVALID_UPSTREAM_URL (400)
- DISALLOWED_UPSTREAM_HOST (400/403)
- APPROVAL_EXPIRED (408)
- DENIED (403)
- RESULT_EXPIRED / RESULT_CONSUMED (410)
- RESPONSE_TOO_LARGE (502)
- UPSTREAM_TIMEOUT (504)
- UPSTREAM_FAILED (pass through upstream status when available)

Upstream pass-through:

- For terminal upstream responses, preserve:
  - upstream HTTP status
  - upstream Content-Type
  - upstream body bytes (within cap)
- Add X-Proxy-Request-Id to help debugging.

---

## Security Notes (MVP Baseline)

API keys:

- high-entropy random values
- store only a hash (no plaintext)
- labels are user-defined, required, and unique per user

Refresh tokens:

- encrypted at rest with a single app secret
- never logged

Outbound safety:

- enforce upstream host allowlist
- disallow forwarding sensitive headers from caller
- inject Authorization server-side

Logging and audit:

- never log Authorization header, API key, refresh token, or full response bodies
- audit contains only metadata and hashes

---

## Configuration

Required configuration values:

- SQLite DB path
- Telegram bot token
- Google OAuth client id/secret + redirect URL
- App secret for encrypting refresh tokens
- Base URL for generating OAuth links

Operational toggles (recommended):

- approval TTL
- result cache TTL
- max response bytes
- upstream request timeout

---

## Testing and Verification (MVP)

Functional:

- user can link Google account
- user can create labeled API key and rename it
- creating a proxy request sends an approval prompt that includes api key label snapshot
- approving executes request and allows exactly one successful retrieval
- denying returns DENIED
- letting approval TTL lapse returns APPROVAL_EXPIRED
- letting cache TTL lapse returns RESULT_EXPIRED

Safety:

- reject http (non-https) URLs
- reject non-allowed hosts
- reject URLs with embedded credentials
- ensure caller cannot set Authorization header (ignored/rejected)
- enforce 1 MiB cap

Reliability:

- Telegram last_update_id persists across restarts
- restarting process after SUCCEEDED but before retrieval leads to RESULT_EXPIRED (expected MVP behavior)

---

## Future Improvements (Post-MVP)

- Optional blocking "wait for approval" mode with server-side long polling (bounded)
- Persistent (encrypted) result storage with short TTL for better reliability
- Multi-instance safe execution and caching (distributed locks / shared store)
- Fine-grained policy engine (auto-approve safe reads, temporary approvals)
- Provider expansion beyond Google
- Write operations with explicit risk classification and stricter prompts
- Per-key rate limits and request quotas
- Stronger API key hashing (argon2/scrypt) if needed
