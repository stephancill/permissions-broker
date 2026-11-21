import * as oauth from "oauth4webapi";

import { isEnrolled } from "../credentials/store";
import { db } from "../db/client";
import { env } from "../env";
import { buildAuthorizationUrl } from "../oauth/flow";
import { getProvider } from "../oauth/registry";
import { createOauthState } from "../oauth/state";
import type { ProxyProviderId } from "../proxy/provider";
import { listProxyProviderIds } from "../proxy/providerRegistry";
import { createConnectState } from "./state";

// Connectable providers: every proxy provider plus the form-based IMAP email
// provider (read-only email access; not an HTTP proxy provider).
export type ConnectableProvider = ProxyProviderId | "imap";

// Providers linked through a broker-hosted form instead of OAuth.
const FORM_PROVIDERS = new Set<string>(["cloudflare", "imap"]);

export function listConnectableProviders(): ConnectableProvider[] {
  return [...listProxyProviderIds(), "imap"];
}

export function isConnectableProvider(id: string): id is ConnectableProvider {
  return (listConnectableProviders() as string[]).includes(id);
}

export class ConnectLinkError extends Error {}

// URL that starts linking `provider` for the user: an OAuth authorization URL
// or a broker-hosted connect form, both bound to a single-use state.
export async function createConnectUrl(params: {
  userId: string;
  provider: ConnectableProvider;
}): Promise<string> {
  if (!env.APP_BASE_URL || !env.APP_SECRET) {
    throw new ConnectLinkError("APP_BASE_URL and APP_SECRET must be set.");
  }
  if (!(await isEnrolled(params.userId))) {
    throw new ConnectLinkError(
      "Set up a passkey first; connected accounts are encrypted to it."
    );
  }

  const base = env.APP_BASE_URL.replace(/\/$/, "");

  if (FORM_PROVIDERS.has(params.provider)) {
    const { state } = await createConnectState({
      userId: params.userId,
      provider: params.provider,
      ttlMs: 10 * 60_000,
    });
    return `${base}/v1/accounts/connect/${params.provider}?state=${encodeURIComponent(state)}`;
  }

  let provider: ReturnType<typeof getProvider>;
  try {
    provider = getProvider(params.provider);
  } catch (err) {
    throw new ConnectLinkError(
      `OAuth provider not configured. ${err instanceof Error ? err.message : String(err)}`
    );
  }

  const codeVerifier = oauth.generateRandomCodeVerifier();
  const { state } = await createOauthState({
    userId: params.userId,
    provider: provider.id,
    ttlMs: 10 * 60_000,
    pkceVerifier: codeVerifier,
  });
  return buildAuthorizationUrl({
    provider,
    redirectUri: `${base}/v1/accounts/callback/${params.provider}`,
    state,
    codeVerifier,
  });
}

export type LinkedAccountSummary = {
  provider: string;
  status: string;
  scopes: string;
  created_at: string;
  metadata_json: string | null;
};

// Latest linked account per provider.
export async function listLinkedAccountsByProvider(
  userId: string
): Promise<Map<string, LinkedAccountSummary>> {
  const database = await db();
  const rows = await database
    .query(
      "SELECT provider, status, scopes, created_at, metadata_json FROM linked_accounts WHERE user_id = ? ORDER BY created_at DESC;"
    )
    .all<LinkedAccountSummary>(userId);
  const byProvider = new Map<string, LinkedAccountSummary>();
  for (const r of rows) {
    if (!byProvider.has(r.provider)) byProvider.set(r.provider, r);
  }
  return byProvider;
}

export async function disconnectProvider(params: {
  userId: string;
  provider: ConnectableProvider;
}): Promise<void> {
  const database = await db();
  await database
    .query(
      "UPDATE linked_accounts SET status = 'revoked', revoked_at = ? WHERE user_id = ? AND provider = ? AND status = 'active';"
    )
    .run(new Date().toISOString(), params.userId, params.provider);
}
