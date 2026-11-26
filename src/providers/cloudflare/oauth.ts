import { env } from "../../env";
import type { OAuthProviderConfig } from "../../oauth/provider";

// Scopes registered on the "stupid vault" OAuth client in Cloudflare
// (Manage Account > OAuth clients). Only account-settings.read and
// user-details.read are required; the rest are optional, so the user can
// trim them on the consent screen. IDs match the client's `scopes` field and
// Cloudflare's catalog (`GET /client/v4/oauth/scopes`).
//
// Enough to take a new project from creation to deployment: create the
// Worker (Workers Admin; Workers Editor alone can only change existing
// Workers), its storage and other bindings, its build, routes, DNS and
// zone, and read its logs.
export const CLOUDFLARE_OAUTH_SCOPES = [
  "account-settings.read",
  "user-details.read",
  "memberships.read",
  // Workers: Admin creates and deletes Workers; Editor updates, deploys,
  // and sets secrets and schedules on existing ones.
  "workers-scripts.admin",
  "workers-scripts.write",
  "workers-scripts.edit",
  "workers-scripts.read",
  "workers-scripts.content_read",
  "workers-scripts.metadata_read",
  "workers-routes.read",
  "workers-routes.write",
  // Workers Builds (CI connected to a repository).
  "workers-ci.read",
  "workers-ci.write",
  // Storage and bindings.
  "workers-kv-storage.read",
  "workers-kv-storage.write",
  "d1.read",
  "d1.write",
  "workers-r2.read",
  "workers-r2.write",
  "workers-r2-bucket-item.read",
  "workers-r2-bucket-item.write",
  "queues.read",
  "queues.write",
  "vectorize.read",
  "vectorize.write",
  "secrets-store.read",
  "secrets-store.write",
  "ai.read",
  "ai.write",
  // Containers (Workers Containers and the Cloudchamber API under them).
  "containers.read",
  "containers.write",
  "cloudchamber.read",
  "cloudchamber.write",
  // Logs and observability.
  "workers-tail.read",
  "workers-observability.read",
  "workers-observability.write",
  // Pages.
  "page.read",
  "page.write",
  // Zones and DNS (custom domains and routes).
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
