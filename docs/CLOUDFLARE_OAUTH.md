# Cloudflare over OAuth

Cloudflare is linked with OAuth (Cloudflare's self-service OAuth clients,
June 2026) instead of a pasted API token. The token form was removed.

## The OAuth client

Registered in the Cloudflare dashboard under Manage Account > OAuth clients
(the `cf` CLI token lacks "OAuth Clients Write"; the dashboard works):

- Name `stupid vault`, client URL `https://vault.stupidtech.net`, private
  (only members of the owning account can authorize it).
- Response type `code`; grants `authorization_code` + `refresh_token`;
  token auth `client_secret_post` (what `src/oauth/flow.ts` sends). PKCE S256 is
  sent as well.
- Redirect URI `https://vault.stupidtech.net/v1/accounts/callback/cloudflare`.
- Scopes: `CLOUDFLARE_OAUTH_SCOPES` in `src/providers/cloudflare/oauth.ts`
  (Workers admin/scripts/routes/KV/D1/R2/tail/observability, Pages
  (`page.*`), zones, DNS, plus account/user/membership read): enough to create
  a Worker and deploy it. Only `account-settings.read` and
  `user-details.read` are required; the rest are optional so the user can trim
  them on the consent screen. `offline_access` yields refresh tokens.
  Keep this list in sync with the client: Cloudflare rejects scopes the client
  wasn't registered with. Scope IDs come from Cloudflare's catalog,
  `GET https://api.cloudflare.com/client/v4/oauth/scopes`.
- Creating a Worker needs `workers-scripts.admin` (Workers Admin).
  `workers-scripts.edit` is Workers Editor, which can update, deploy, and set
  secrets and schedules on an existing Worker, but not create or delete one:
  Cloudflare answers an upload of a new script with 403 "No access to the
  specified resource". See Cloudflare's
  [Workers roles](https://developers.cloudflare.com/workers/authorization/workers/).
- After adding scopes to the list, add them to the client in the dashboard
  first (or the consent screen fails with `invalid_scope`), then each user
  reconnects Cloudflare under Accounts to grant them. Existing links keep
  their old scopes until then.
- Worker secrets `CLOUDFLARE_OAUTH_CLIENT_ID` / `CLOUDFLARE_OAUTH_CLIENT_SECRET`.
  The secret is shown once at creation; rotate it from the client page.

Endpoints come from `https://dash.cloudflare.com/.well-known/openid-configuration`
(issuer `https://dash.cloudflare.com`, `/oauth2/auth`, `/oauth2/token`).

## Credential

Stored (ECIES to the user's passkey key) as JSON:

- `{ refreshToken, accounts }` for OAuth. Every use refreshes the access token;
  the rotated refresh token is written back through the existing
  `updatedCredential` path, keeping `accounts`.
- `{ apiToken, accounts }` from the old token form still works (used directly)
  until the user reconnects.

`accounts` (id + name from `GET /client/v4/accounts` at connect time) is copied
into `metadata_json` so the app and `GET /v1/accounts` can show account names
without decrypting.

The callback fails loudly if Cloudflare returns no refresh token. Users can
revoke the app at Cloudflare's "Manage OAuth authorizations".
