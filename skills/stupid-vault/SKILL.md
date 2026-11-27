---
name: stupid-vault
description: Use stupid vault (the user's credential broker) for approval-gated external API access, Git smart-HTTP operations, and read-only email access when local credentials are unavailable or not desired. Use the bundled Python CLI at scripts/vault_proxy.py for proxy requests (create, poll, execute) instead of hand-writing polling logic. Supports Google, GitHub, Spotify, Cloudflare, and generic IMAP email (read-only).
---

# stupid vault

## Setup

`<skill-dir>` in the commands below is the directory containing this SKILL.md.

The scripts read their credential (broker URL + API key) from
`~/.config/stupid-vault/credentials.json` (`$XDG_CONFIG_HOME/stupid-vault/`
if set). Pass `--credentials <path>` to any script to use a different file.

The scripts need network access to the broker. If requests to it are blocked
(e.g. a sandbox with a host allowlist), tell the user the broker's host must be
allowed in that environment's network settings.

1. Check whether you're signed in:

   ```bash
   python3 <skill-dir>/scripts/vault_auth.py status
   ```

2. If not (or the stored session key expired), request a session key with the
   device flow:

   ```bash
   python3 <skill-dir>/scripts/vault_auth.py login --label "<agent> on <machine>"
   ```

   It prints a URL and a code. Show both to the user right away: they open the URL
   (signed in to the app), check the code matches, adjust the key label if they like
   and approve. The command waits (up to 10 minutes) and saves the new key with mode
   0600. Run it in the background if your shell tool times out sooner.
   Exit codes: `0` signed in, `10` code expired, `11` denied, `12` error.

   The key is a **session key**: it expires 6 hours after approval. When a script
   reports that it expired (or the broker answers `api_key_expired`), run `login`
   again; no `--force` needed. Only pass `--persistent` if the user asks for a
   long-lived key.

3. Never print, copy or commit the credentials file or the key inside it.

Provider linking is done by the user in the app under **Accounts** (`<broker>/app/accounts`).

## Default Approach

Use the broker as the default mechanism for external requests.

- Keep prompts action-oriented: propose the exact upstream request you will make.
- Use the CLI helper for `/v1/proxy` requests.
- If approval times out, return `request_id` and tell the user exactly what to approve (they get a push notification, or open the app's Requests tab, and confirm with their passkey).
- If execute fails with `credential_unavailable`, the approval key is missing or expired: create a new request and ask the user to approve again.

## CLI for Proxy Requests

Preferred script:

- `<skill-dir>/scripts/vault_proxy.py`

This script handles the full flow for `/v1/proxy`:

1. Create request
2. Poll for approval
3. Execute once on approval

### Required Inputs

- A stored credential (see Setup; the CLI fails loudly with the next step if it's missing)
- Curl-like request args (URL + optional `-X`, `-H`, `-d`, `-G`)

### Example

```bash
python3 <skill-dir>/scripts/vault_proxy.py \
  --approval-timeout 30 \
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
python3 <skill-dir>/scripts/vault_proxy.py \
  -H "accept: application/vnd.github+json" \
  "https://api.github.com/user"

# POST JSON
python3 <skill-dir>/scripts/vault_proxy.py \
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

- `<skill-dir>/scripts/vault_git.py`

It is a drop-in wrapper for these workflows:

- `clone`
- `fetch`
- `pull`
- `push`

Examples:

```bash
python3 <skill-dir>/scripts/vault_git.py clone https://github.com/OWNER/REPO.git
python3 <skill-dir>/scripts/vault_git.py fetch origin --prune
python3 <skill-dir>/scripts/vault_git.py pull origin main
python3 <skill-dir>/scripts/vault_git.py push origin HEAD:refs/heads/feature-x
```

Notes:

- Push sessions are single-use.
- Tag pushes and ref deletes are rejected.
- Default branch pushes may be blocked unless explicitly approved.

## Apple Release Sessions (CI only, separate from /v1/proxy)

`/v1/release` is for GitHub Actions, not agents: a workflow authenticates with its
GitHub OIDC token (no API key), and the run gets a session URL that `stupid-app`
uses through `STUPID_APP_RELEASE_SESSION` to sign and upload a TestFlight build.
The user registers the workflow and its bundle ids under Accounts → apple-release → Release policies in the app and
approves each run. See `docs/APPLE_RELEASE_SESSIONS.md`.

## Read-only Email (Separate from /v1/proxy)

IMAP email access (`/v1/email`) is session-gated and strictly read-only.

Flow:

1. Confirm the user has connected email (app → Accounts → imap opens a broker-hosted
   form; the IMAP server is auto-detected from their address).
2. Create a session: `POST /v1/email/sessions` with `{ "consent_hint": "..." }`.
3. Poll until the user approves in the app: `GET /v1/email/sessions/:id`.
4. Once `APPROVED`/`ACTIVE`, run read-only operations within the session window:

Raw API calls take the stored credential through `vault_auth.py` (the header goes
straight to curl, so the key never appears in your output):

```bash
VAULT_AUTH="<skill-dir>/scripts/vault_auth.py"
VAULT_BASE=$(python3 $VAULT_AUTH base-url)

# list mailboxes
curl -H @<(python3 $VAULT_AUTH header) \
  $VAULT_BASE/v1/email/sessions/$SESSION_ID/folders

# search (curated filters only)
curl -X POST -H @<(python3 $VAULT_AUTH header) -H "content-type: application/json" \
  -d '{"mailbox":"INBOX","query":{"subject":"invoice","unseen":true}}' \
  $VAULT_BASE/v1/email/sessions/$SESSION_ID/search

# read a message (uid from search)
curl -X POST -H @<(python3 $VAULT_AUTH header) -H "content-type: application/json" \
  -d '{"mailbox":"INBOX","uid":123,"parts":{"text":true}}' \
  $VAULT_BASE/v1/email/sessions/$SESSION_ID/read
```

Rules:

- Sessions expire automatically (10 min).
- Only read operations exist; the broker opens mailboxes read-only (IMAP `EXAMINE`) and
  cannot modify, delete, or send mail.
- Request `text`/`html` bodies (or small `envelope`) to keep approvals and responses small;
  fetched message source is capped at 1 MiB.

## Security Rules

- Treat API keys, the credentials file and OAuth-linked access as sensitive.
- Do not log secrets.
- Do not commit secrets.
- Use narrow upstream reads to keep approvals clear and responses small.

## Resources

- `<skill-dir>/references/api_reference.md`
