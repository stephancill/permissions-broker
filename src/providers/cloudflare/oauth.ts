import { env } from "../../env";
import type { OAuthProviderConfig } from "../../oauth/provider";

// Scopes registered on the "stupid vault" OAuth client in Cloudflare
// (Manage Account > OAuth clients). Only account-settings.read and
// user-details.read are required; the rest are optional, so the user can
// trim them on the consent screen. IDs match the client's `scopes` field.
export const CLOUDFLARE_OAUTH_SCOPES = [
  "account-settings.read",
  "user-details.read",
  "memberships.read",
  "workers-scripts.edit",
  "workers-scripts.content_read",
  "workers-scripts.metadata_read",
  "workers-routes.read",
  "workers-routes.write",
  "workers-kv-storage.read",
  "workers-kv-storage.write",
  "d1.read",
  "d1.write",
  "workers-r2.read",
  "workers-r2.write",
  "workers-r2-bucket-item.read",
  "workers-r2-bucket-item.write",
  "workers-tail.read",
  "workers-observability.read",
  "page.read",
  "page.write",
  "zone.read",
  "zone.write",
  "dns.read",
  "dns.write",
  // Refresh tokens.
  "offline_access",
];

export function cloudflareProvider(): OAuthProviderConfig {
  if (!env.CLOUDFLARE_OAUTH_CLIENT_ID || !env.CLOUDFLARE_OAUTH_CLIENT_SECRET) {
    throw new Error("Cloudflare OAuth env vars are required");
  }

  return {
    id: "cloudflare",
    // https://dash.cloudflare.com/.well-known/openid-configuration
    issuer: "https://dash.cloudflare.com",
    authorizationEndpoint: "https://dash.cloudflare.com/oauth2/auth",
    tokenEndpoint: "https://dash.cloudflare.com/oauth2/token",
    clientId: env.CLOUDFLARE_OAUTH_CLIENT_ID,
    clientSecret: env.CLOUDFLARE_OAUTH_CLIENT_SECRET,
    scopes: CLOUDFLARE_OAUTH_SCOPES,
    pkceRequired: true,
    extraAuthorizeParams: {},
  };
}
