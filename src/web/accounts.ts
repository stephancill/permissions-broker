import { Hono } from "hono";
import { ulid } from "ulid";

import { auditEvent } from "../audit/audit";
import { requireApiKey } from "../auth/apiKey";
import { encryptUtf8 } from "../crypto/aesgcm";
import { db } from "../db/client";
import { env } from "../env";
import { exchangeAuthorizationCode } from "../oauth/flow";
import type { OAuthProviderConfig } from "../oauth/provider";
import { getProvider } from "../oauth/registry";
import { getOauthState, markOauthStateUsed } from "../oauth/state";

function nowIso(): string {
  return new Date().toISOString();
}

export const accountRouter = new Hono();

accountRouter.get("/", requireApiKey, (c) => {
  const auth = c.get("apiKeyAuth");
  const rows = db()
    .query(
      "SELECT provider, provider_user_id, scopes, status, created_at, revoked_at FROM linked_accounts WHERE user_id = ? ORDER BY created_at DESC;"
    )
    .all(auth.userId) as {
    provider: string;
    provider_user_id: string;
    scopes: string;
    status: string;
    created_at: string;
    revoked_at: string | null;
  }[];

  return c.json({ accounts: rows });
});

accountRouter.get("/callback/:provider", async (c) => {
  const providerId = c.req.param("provider");
  const state = c.req.query("state");
  if (!state) return c.text("missing state", 400);

  let provider: OAuthProviderConfig;
  try {
    provider = getProvider(providerId);
  } catch {
    return c.text("unknown provider", 404);
  }

  if (!env.APP_BASE_URL) return c.text("APP_BASE_URL not configured", 500);
  if (!env.APP_SECRET) return c.text("APP_SECRET not configured", 500);
  const redirectUri = `${env.APP_BASE_URL}/v1/accounts/callback/${providerId}`;

  const { userId, pkceVerifier } = getOauthState({
    state,
    provider: providerId,
  });
  if (!pkceVerifier) return c.text("missing pkce verifier", 400);

  let tokenResult: Awaited<ReturnType<typeof exchangeAuthorizationCode>>;
  try {
    tokenResult = await exchangeAuthorizationCode({
      provider,
      redirectUri,
      currentUrl: new URL(c.req.url),
      expectedState: state,
      codeVerifier: pkceVerifier,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.text(`oauth exchange failed: ${msg}`, 400);
  }

  markOauthStateUsed(state);

  const refreshToken = tokenResult.refresh_token;
  const scope = tokenResult.scope;

  const scopes = scope ?? provider.scopes.join(" ");

  const existing = db()
    .query(
      "SELECT id, refresh_token_ciphertext FROM linked_accounts WHERE user_id = ? AND provider = ? AND status = 'active' LIMIT 1;"
    )
    .get(userId, providerId) as {
    id: string;
    refresh_token_ciphertext: Uint8Array;
  } | null;

  if (!refreshToken && !existing) {
    return c.text(
      "No refresh token returned. Try removing app access in your provider account and reconnect.",
      400
    );
  }

  const providerUserId = "unknown";
  const now = nowIso();

  if (existing) {
    if (refreshToken) {
      const ct = await encryptUtf8(refreshToken);
      db()
        .query(
          "UPDATE linked_accounts SET scopes = ?, refresh_token_ciphertext = ?, status = 'active', revoked_at = NULL WHERE id = ?;"
        )
        .run(scopes, ct, existing.id);
    } else {
      db()
        .query(
          "UPDATE linked_accounts SET scopes = ?, status = 'active', revoked_at = NULL WHERE id = ?;"
        )
        .run(scopes, existing.id);
    }
  } else {
    const ct = await encryptUtf8(refreshToken as string);
    db()
      .query(
        "INSERT INTO linked_accounts (id, user_id, provider, provider_user_id, scopes, refresh_token_ciphertext, status, created_at, revoked_at) VALUES (?, ?, ?, ?, ?, ?, 'active', ?, NULL);"
      )
      .run(ulid(), userId, providerId, providerUserId, scopes, ct, now);
  }

  auditEvent({
    userId,
    actorType: "system",
    actorId: "oauth_callback",
    eventType: "linked_account_updated",
    event: { provider: providerId, scopes },
  });

  const telegram = db()
    .query("SELECT telegram_user_id FROM users WHERE id = ?;")
    .get(userId) as { telegram_user_id: number } | null;

  if (telegram?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
    const { createBot } = await import("../telegram/bot");
    const bot = createBot();
    bot.api
      .sendMessage(
        telegram.telegram_user_id,
        `Connected ${providerId}. Scopes: ${scopes}`
      )
      .catch(() => {});
  }

  return c.text("Connected. You can return to Telegram.");
});
