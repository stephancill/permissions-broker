# MCP connector (Claude, ChatGPT)

The broker is a remote MCP server, so the user can add stupid vault as a custom
connector in Claude (claude.ai, Desktop, mobile, Claude Code) or ChatGPT
(developer mode / apps) and approve its requests with their passkey like any
other agent.

Connector URL: `<APP_BASE_URL>/mcp` (for example
`https://vault.stupidtech.net/mcp`).

## Adding it

- **Claude**: Settings → Connectors → Add custom connector. Enter the URL and
  leave the OAuth client fields empty ("register automatically"). Claude Code:
  `claude mcp add --transport http stupid-vault <APP_BASE_URL>/mcp`, then
  `/mcp` to sign in.
- **ChatGPT**: Settings → Apps & Connectors → Advanced → Developer mode, then
  Create. Enter the URL (with `/mcp`), choose OAuth, and let ChatGPT register
  its client (DCR).

Either way the client opens `<APP_BASE_URL>/oauth/authorize`. The user signs in
with their passkey if needed, sees which client is connecting and the host it
returns to, adjusts the API key label (default: the client's name, e.g.
"Claude") and approves. The client then holds an ordinary API key: its label is
what approval prompts show, it appears under **API keys**, and revoking it
disconnects the connector (the next call gets a 401 challenge and the client
asks the user to sign in again).

## Tools

| Tool | Annotations | What it does |
| --- | --- | --- |
| `whoami` | read-only | The connector's key id and label |
| `list_accounts` | read-only | Linked accounts (same as `GET /v1/accounts/`); no approval |
| `proxy_get` | read-only, open world | Approval-gated GET through `/v1/proxy` |
| `proxy_request` | destructive, open world | Approval-gated request with any allowed method and a body |
| `proxy_result` | idempotent, open world | Keep waiting on an earlier request and return its response |

The tools call the `/v1/proxy` and `/v1/accounts` handlers in-process with the
connector's own key (and the caller's IP), so approvals, approval windows, push
notifications, size limits and single-use execute are exactly those of the HTTP
API. `proxy_get`/`proxy_request` create the request and wait up to
`wait_seconds` (default 45, max 50; Claude allows 240s per tool call) for the
user's decision, then execute and return `HTTP <status> (<content-type>)` and
the body. Text bodies over 100,000 characters are truncated (Claude caps tool
results at about 150k); binary bodies are omitted. If the user hasn't decided
yet the tool returns `PENDING_APPROVAL` with the `request_id`, and the model
calls `proxy_result`. Denied, expired and broker errors come back as tool
results with `isError: true`.

Git and email sessions aren't exposed: they need a local git client or are a
better fit for a dedicated tool set.

## Protocol

- Streamable HTTP, stateless: every JSON-RPC request is a POST to `/mcp` and
  gets one `application/json` response. Notifications and client responses get
  `202`. `GET`/`DELETE` return `405` (no server stream, no sessions).
- Protocol versions `2025-11-25` (latest), `2025-06-18`, `2025-03-26`.
  `initialize` echoes a supported version and otherwise offers the latest; an
  unsupported `MCP-Protocol-Version` header gets `400`.
- Requests carrying an `Origin` other than the broker, `https://claude.ai` or
  `https://chatgpt.com` get `403` (DNS rebinding guard from the transport
  spec); hosted connectors call server-side without one.
- Methods: `initialize`, `ping`, `tools/list`, `tools/call`. Unknown tools are
  JSON-RPC `-32602`; tool failures are `isError` results.

## Authorization server

Follows the MCP authorization spec (2025-11-25):

- `GET /.well-known/oauth-protected-resource` (and `/mcp` suffix, RFC 9728):
  `resource` = `<origin>/mcp`, `authorization_servers` = [`<origin>`], scope
  `vault`.
- `401` from `/mcp` (missing, unknown or revoked key) carries
  `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource", scope="vault"`.
- `GET /.well-known/oauth-authorization-server` (RFC 8414): issuer is the
  origin; `code_challenge_methods_supported: ["S256"]`,
  `token_endpoint_auth_methods_supported: ["none"]`,
  `authorization_response_iss_parameter_supported: true`.
- `POST /oauth/register` (RFC 7591): public clients only. Redirect URIs must be
  https, or http on a loopback host (any port matches, RFC 8252, for Claude
  Code). The response always says `token_endpoint_auth_method: "none"`, even
  if the client asked for a secret. Registrations that never complete an
  authorization are swept after 24 hours.
- `GET /oauth/authorize`: needs the web session. Unknown clients or
  unregistered redirect URIs show an error page and never redirect. Otherwise
  `response_type=code`, PKCE `S256` and an accepted `resource` (`<origin>/mcp`
  or the origin) are required, and errors go back to the client. Every
  redirect carries `iss` (RFC 9207), which lets ChatGPT use its stable
  `https://chatgpt.com/connector_platform_oauth_redirect` callback; Claude uses
  `https://claude.ai/api/mcp/auth_callback`.
- `POST /oauth/authorize` (consent form, `requireSessionPage`): approve stores a
  single-use code (5 minutes, SHA-256 only) with the chosen label; deny
  redirects with `access_denied`. The consent page's CSP `form-action` adds
  the redirect URI's origin, since browsers apply it to the redirect after the
  POST.
- `POST /oauth/token` (form-encoded or JSON): `authorization_code` only.
  Checks client, redirect URI, PKCE verifier and resource, claims the code
  (`PENDING -> USED`, conditional update) and only then mints the API key, so
  its plaintext is never stored. Returns
  `{access_token, token_type: "Bearer", scope: "vault"}` without `expires_in`
  or a refresh token: the key lives until the user revokes it.

Client ID Metadata Documents aren't advertised (they'd make the broker fetch
client-chosen URLs); Claude and ChatGPT fall back to dynamic registration.

Audit events: `mcp_oauth_authorized` and `api_key_created` with
`via: "mcp_oauth"`. Schema: `migrations/0019_mcp_oauth.sql`.
