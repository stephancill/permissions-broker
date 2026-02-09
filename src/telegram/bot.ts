import { Bot, InlineKeyboard } from "grammy";
import * as oauth from "oauth4webapi";
import { ulid } from "ulid";

import { auditEvent } from "../audit/audit";
import { randomBase64Url } from "../crypto/random";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import { env } from "../env";
import { buildAuthorizationUrl } from "../oauth/flow";
import type { OAuthProviderConfig } from "../oauth/provider";
import { getProvider } from "../oauth/registry";
import { createOauthState } from "../oauth/state";

function nowIso(): string {
  return new Date().toISOString();
}

type UserRow = { id: string };

function ensureUser(telegramUserId: number): string {
  const existing = db()
    .query("SELECT id FROM users WHERE telegram_user_id = ?;")
    .get(telegramUserId) as UserRow | null;

  if (existing) return existing.id;

  const id = ulid();
  db()
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, ?);"
    )
    .run(id, telegramUserId, nowIso(), "active");

  auditEvent({
    userId: id,
    actorType: "telegram",
    actorId: String(telegramUserId),
    eventType: "user_created",
    event: {},
  });

  return id;
}

function setPendingInput(params: {
  userId: string;
  action: string;
  targetId?: string;
  ttlMs: number;
}): void {
  const createdAt = nowIso();
  const expiresAt = new Date(Date.now() + params.ttlMs).toISOString();

  db()
    .query(
      "INSERT INTO telegram_pending_inputs (user_id, action, target_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?) " +
        "ON CONFLICT(user_id) DO UPDATE SET action=excluded.action, target_id=excluded.target_id, created_at=excluded.created_at, expires_at=excluded.expires_at;"
    )
    .run(
      params.userId,
      params.action,
      params.targetId ?? null,
      createdAt,
      expiresAt
    );
}

function clearPendingInput(userId: string): void {
  db()
    .query("DELETE FROM telegram_pending_inputs WHERE user_id = ?;")
    .run(userId);
}

function getPendingInput(
  userId: string
): { action: string; target_id: string | null; expires_at: string } | null {
  return db()
    .query(
      "SELECT action, target_id, expires_at FROM telegram_pending_inputs WHERE user_id = ?;"
    )
    .get(userId) as {
    action: string;
    target_id: string | null;
    expires_at: string;
  } | null;
}

async function createApiKey(params: {
  userId: string;
  label: string;
  telegramUserId: number;
}) {
  const keyPlain = `pb_${randomBase64Url(32)}`;
  const keyHash = await sha256Hex(keyPlain);
  const id = ulid();
  const now = nowIso();

  db()
    .query(
      "INSERT INTO api_keys (id, user_id, label, key_hash, created_at, updated_at, revoked_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL);"
    )
    .run(id, params.userId, params.label, keyHash, now, now);

  auditEvent({
    userId: params.userId,
    actorType: "telegram",
    actorId: String(params.telegramUserId),
    eventType: "api_key_created",
    event: { apiKeyId: id, label: params.label },
  });

  return { id, keyPlain };
}

function normalizeLabel(label: string): string {
  return label.trim().replace(/\s+/g, " ");
}

export function createBot(): Bot {
  if (!env.TELEGRAM_BOT_TOKEN) {
    throw new Error("TELEGRAM_BOT_TOKEN is required to start the Telegram bot");
  }

  const bot = new Bot(env.TELEGRAM_BOT_TOKEN);

  bot.command("start", async (ctx) => {
    if (!ctx.from) return;
    ensureUser(ctx.from.id);
    await ctx.reply(
      "Permissions Broker is running. Use /connect to link a provider and /key to create an API key."
    );
  });

  bot.command("connect", async (ctx) => {
    if (!ctx.from) return;
    const userId = ensureUser(ctx.from.id);

    if (!env.APP_BASE_URL) {
      await ctx.reply(
        "APP_BASE_URL is not configured; cannot create OAuth link."
      );
      return;
    }

    if (!env.APP_SECRET) {
      await ctx.reply(
        "APP_SECRET is not configured; cannot store refresh tokens."
      );
      return;
    }

    let provider: OAuthProviderConfig;
    try {
      provider = getProvider("google");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await ctx.reply(`OAuth provider not configured. ${msg}`);
      return;
    }

    const redirectUri = `${env.APP_BASE_URL}/v1/accounts/callback/google`;
    const codeVerifier = oauth.generateRandomCodeVerifier();

    const { state } = createOauthState({
      userId,
      provider: provider.id,
      ttlMs: 10 * 60_000,
      pkceVerifier: codeVerifier,
    });

    const url = await buildAuthorizationUrl({
      provider,
      redirectUri,
      state,
      codeVerifier,
    });

    await ctx.reply(`Connect Google: ${url}`);
  });

  bot.command("key", async (ctx) => {
    if (!ctx.from) return;
    const userId = ensureUser(ctx.from.id);

    const raw = (ctx.match ?? "").toString();
    const label = normalizeLabel(raw);

    if (!label) {
      setPendingInput({ userId, action: "CREATE_KEY", ttlMs: 5 * 60_000 });
      await ctx.reply("Send the label for this API key (unique per user).", {
        reply_markup: { force_reply: true },
      });
      return;
    }

    try {
      const created = await createApiKey({
        userId,
        label,
        telegramUserId: ctx.from.id,
      });
      await ctx.reply(
        `API key created (shown once).\n\nLabel: ${label}\nKey: ${created.keyPlain}`
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await ctx.reply(`Failed to create API key. ${msg}`);
    }
  });

  bot.command("keys", async (ctx) => {
    if (!ctx.from) return;
    const userId = ensureUser(ctx.from.id);

    const rows = db()
      .query(
        "SELECT id, label, created_at, revoked_at, last_used_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC;"
      )
      .all(userId) as {
      id: string;
      label: string;
      created_at: string;
      revoked_at: string | null;
      last_used_at: string | null;
    }[];

    if (rows.length === 0) {
      await ctx.reply("No API keys yet. Use /key to create one.");
      return;
    }

    const kb = new InlineKeyboard();
    for (const k of rows.slice(0, 10)) {
      kb.text(`Rename: ${k.label}`, `k:rename:${k.id}`).row();
      if (!k.revoked_at) {
        kb.text(`Revoke: ${k.label}`, `k:revoke:${k.id}`).row();
        kb.text(`Rotate: ${k.label}`, `k:rotate:${k.id}`).row();
      }
    }

    const lines = rows.map((k) => {
      const status = k.revoked_at ? "revoked" : "active";
      return `- ${k.label} (${status}) created=${k.created_at} last_used=${k.last_used_at ?? "never"}`;
    });

    await ctx.reply(`API keys:\n${lines.join("\n")}`, { reply_markup: kb });
  });

  bot.callbackQuery(/k:(rename|revoke|rotate):(.+)/, async (ctx) => {
    if (!ctx.from) return;
    const action = ctx.match?.[1];
    const apiKeyId = ctx.match?.[2];
    const userId = ensureUser(ctx.from.id);

    const row = db()
      .query(
        "SELECT id, label, revoked_at FROM api_keys WHERE id = ? AND user_id = ?;"
      )
      .get(apiKeyId, userId) as {
      id: string;
      label: string;
      revoked_at: string | null;
    } | null;

    if (!row) {
      await ctx.answerCallbackQuery({ text: "Key not found" });
      return;
    }

    if (action === "revoke") {
      if (row.revoked_at) {
        await ctx.answerCallbackQuery({ text: "Already revoked" });
        return;
      }
      db()
        .query(
          "UPDATE api_keys SET revoked_at = ?, updated_at = ? WHERE id = ? AND user_id = ?;"
        )
        .run(nowIso(), nowIso(), row.id, userId);

      auditEvent({
        userId,
        actorType: "telegram",
        actorId: String(ctx.from.id),
        eventType: "api_key_revoked",
        event: { apiKeyId: row.id },
      });

      await ctx.answerCallbackQuery({ text: "Revoked" });
      return;
    }

    if (action === "rename") {
      setPendingInput({
        userId,
        action: "RENAME_KEY",
        targetId: row.id,
        ttlMs: 5 * 60_000,
      });
      await ctx.answerCallbackQuery({ text: "Send new label" });
      await ctx.reply(`Send the new label for: ${row.label}`, {
        reply_markup: { force_reply: true },
      });
      return;
    }

    if (action === "rotate") {
      if (row.revoked_at) {
        await ctx.answerCallbackQuery({ text: "Cannot rotate a revoked key" });
        return;
      }
      setPendingInput({
        userId,
        action: "ROTATE_KEY",
        targetId: row.id,
        ttlMs: 5 * 60_000,
      });
      await ctx.answerCallbackQuery({ text: "Send new label" });
      await ctx.reply(`Send a label for the rotated key (old: ${row.label}).`, {
        reply_markup: { force_reply: true },
      });
    }
  });

  bot.on("message:text", async (ctx) => {
    if (!ctx.from) return;
    const userId = ensureUser(ctx.from.id);
    const pending = getPendingInput(userId);
    if (!pending) return;

    const expiresAt = Date.parse(pending.expires_at);
    if (!Number.isFinite(expiresAt) || Date.now() > expiresAt) {
      clearPendingInput(userId);
      await ctx.reply("That action expired. Please try again.");
      return;
    }

    const text = (ctx.message.text ?? "").trim();
    if (!text || text.startsWith("/")) {
      await ctx.reply("Please send a plain text label.");
      return;
    }

    const label = normalizeLabel(text);

    try {
      if (pending.action === "CREATE_KEY") {
        const created = await createApiKey({
          userId,
          label,
          telegramUserId: ctx.from.id,
        });
        clearPendingInput(userId);
        await ctx.reply(
          `API key created (shown once).\n\nLabel: ${label}\nKey: ${created.keyPlain}`
        );
        return;
      }

      if (pending.action === "RENAME_KEY") {
        db()
          .query(
            "UPDATE api_keys SET label = ?, updated_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL;"
          )
          .run(label, nowIso(), pending.target_id, userId);
        clearPendingInput(userId);
        auditEvent({
          userId,
          actorType: "telegram",
          actorId: String(ctx.from.id),
          eventType: "api_key_renamed",
          event: { apiKeyId: pending.target_id, newLabel: label },
        });
        await ctx.reply(`Renamed key to: ${label}`);
        return;
      }

      if (pending.action === "ROTATE_KEY") {
        const oldId = pending.target_id;
        const now = nowIso();
        db().transaction(() => {
          db()
            .query(
              "UPDATE api_keys SET revoked_at = ?, updated_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL;"
            )
            .run(now, now, oldId, userId);
        })();

        const created = await createApiKey({
          userId,
          label,
          telegramUserId: ctx.from.id,
        });
        clearPendingInput(userId);

        auditEvent({
          userId,
          actorType: "telegram",
          actorId: String(ctx.from.id),
          eventType: "api_key_rotated",
          event: {
            oldApiKeyId: oldId,
            newApiKeyId: created.id,
            newLabel: label,
          },
        });

        await ctx.reply(
          `Rotated key (shown once).\n\nLabel: ${label}\nKey: ${created.keyPlain}`
        );
        return;
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await ctx.reply(`Failed: ${msg}`);
    }
  });

  return bot;
}
