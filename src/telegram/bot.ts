import { Bot, InlineKeyboard } from "grammy";
import * as oauth from "oauth4webapi";
import { ulid } from "ulid";

import { auditEvent } from "../audit/audit";
import { createConnectState } from "../connect/state";
import { randomBase64Url } from "../crypto/random";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import { env } from "../env";
import { setGitSessionStatus } from "../git/sessions";
import { buildAuthorizationUrl } from "../oauth/flow";
import type { OAuthProviderConfig } from "../oauth/provider";
import { getProvider } from "../oauth/registry";
import { createOauthState } from "../oauth/state";
import { decideProxyRequest } from "../proxy/requests";

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
  const created = await createApiKeyRow({
    userId: params.userId,
    label: params.label,
  });

  auditEvent({
    userId: params.userId,
    actorType: "telegram",
    actorId: String(params.telegramUserId),
    eventType: "api_key_created",
    event: { apiKeyId: created.id, label: params.label },
  });

  return created;
}

async function createApiKeyRow(params: {
  userId: string;
  label: string;
}): Promise<{
  id: string;
  keyPlain: string;
}> {
  const keyPlain = `pb_${randomBase64Url(32)}`;
  const keyHash = await sha256Hex(keyPlain);
  const id = ulid();
  const now = nowIso();

  db()
    .query(
      "INSERT INTO api_keys (id, user_id, label, key_hash, created_at, updated_at, revoked_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL);"
    )
    .run(id, params.userId, params.label, keyHash, now, now);

  return { id, keyPlain };
}

function rotatedLabel(oldLabel: string, oldKeyId: string): string {
  const day = nowIso().slice(0, 10);
  const suffix = oldKeyId.slice(-6);
  return `${oldLabel} (revoked ${day} ${suffix})`;
}

function normalizeLabel(label: string): string {
  return label.trim().replace(/\s+/g, " ");
}

function renderKeysMessage(userId: string): {
  text: string;
  keyboard: InlineKeyboard;
} {
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
    return {
      text: "No API keys yet. Use /key to create one.",
      keyboard: new InlineKeyboard(),
    };
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

  return {
    text: `API keys:\n${lines.join("\n")}`,
    keyboard: kb,
  };
}

function renderApprovalDecisionText(params: {
  originalText: string;
  decision: "approved" | "denied";
}): string {
  const label = params.decision === "approved" ? "APPROVED" : "DENIED";

  // The original message may contain characters that should be escaped when
  // using parse_mode=HTML.
  const original = escapeHtml(params.originalText);
  return `${original}\n\n<b>Decision</b>: <code>${label}</code> (<code>${escapeHtml(nowIso())}</code>)`;
}

function renderExpiredDecisionText(originalText: string): string {
  const original = escapeHtml(originalText);
  return `${original}\n\n<b>Decision</b>: <code>EXPIRED</code> (<code>${escapeHtml(nowIso())}</code>)`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderOneTimeKeyMessage(params: {
  label: string;
  apiKey: string;
}): string {
  const label = escapeHtml(params.label);
  const apiKey = escapeHtml(params.apiKey);
  const keyBlock = `<span class="tg-spoiler"><code>${apiKey}</code></span>`;
  return `API key (sent once)\n\nLabel: ${label}\nKey: ${keyBlock}`;
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

  async function sendConnectLink(params: {
    ctx: { reply: (text: string) => Promise<unknown> };
    userId: string;
    providerId: string;
  }): Promise<void> {
    if (!env.APP_BASE_URL) {
      await params.ctx.reply(
        "APP_BASE_URL is not configured; cannot create OAuth link."
      );
      return;
    }

    if (!env.APP_SECRET) {
      await params.ctx.reply(
        "APP_SECRET is not configured; cannot store provider credentials."
      );
      return;
    }

    if (params.providerId === "icloud") {
      const { state } = createConnectState({
        userId: params.userId,
        provider: "icloud",
        ttlMs: 10 * 60_000,
      });
      const base = env.APP_BASE_URL.replace(/\/$/, "");
      const url = `${base}/v1/accounts/connect/icloud?state=${encodeURIComponent(state)}`;
      await params.ctx.reply(`Connect icloud: ${url}`);
      return;
    }

    let provider: OAuthProviderConfig;
    try {
      provider = getProvider(params.providerId);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await params.ctx.reply(`OAuth provider not configured. ${msg}`);
      return;
    }

    const redirectUri = `${env.APP_BASE_URL}/v1/accounts/callback/${params.providerId}`;
    const codeVerifier = oauth.generateRandomCodeVerifier();
    const { state } = createOauthState({
      userId: params.userId,
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

    await params.ctx.reply(`Connect ${params.providerId}: ${url}`);
  }

  bot.command("connect", async (ctx) => {
    if (!ctx.from) return;
    const userId = ensureUser(ctx.from.id);

    const raw = (ctx.match ?? "").toString().trim();

    if (!raw) {
      const rows = db()
        .query(
          "SELECT provider, status, scopes, created_at, revoked_at FROM linked_accounts WHERE user_id = ? ORDER BY created_at DESC;"
        )
        .all(userId) as {
        provider: string;
        status: string;
        scopes: string;
        created_at: string;
        revoked_at: string | null;
      }[];

      const byProvider = new Map<string, (typeof rows)[number]>();
      for (const r of rows) {
        if (!byProvider.has(r.provider)) byProvider.set(r.provider, r);
      }

      const supported = ["google", "github", "icloud"] as const;
      const connectedLines: string[] = [];
      for (const p of supported) {
        const r = byProvider.get(p);
        if (!r) {
          connectedLines.push(`- ${p}: not connected`);
          continue;
        }
        connectedLines.push(
          `- ${p}: ${r.status} scopes=${r.scopes} created=${r.created_at}`
        );
      }

      const kb = new InlineKeyboard();
      for (const p of supported) {
        if (!byProvider.get(p) || byProvider.get(p)?.status !== "active") {
          kb.text(`Connect ${p}`, `c:connect:${p}`).row();
        }
      }

      await ctx.reply(
        `Connected accounts:\n${connectedLines.join("\n")}\n\nUse /connect <provider> or the buttons below.`,
        { reply_markup: kb }
      );
      return;
    }

    await sendConnectLink({ ctx, userId, providerId: raw });
  });

  bot.callbackQuery(/c:connect:(google|github|icloud)/, async (ctx) => {
    if (!ctx.from) return;
    const providerId = ctx.match?.[1] ?? "";
    const userId = ensureUser(ctx.from.id);

    await ctx.answerCallbackQuery({ text: "link generated" });
    await sendConnectLink({ ctx, userId, providerId });
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
        renderOneTimeKeyMessage({ label, apiKey: created.keyPlain }),
        {
          parse_mode: "HTML",
        }
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await ctx.reply(`Failed to create API key. ${msg}`);
    }
  });

  bot.command("keys", async (ctx) => {
    if (!ctx.from) return;
    const userId = ensureUser(ctx.from.id);

    const rendered = renderKeysMessage(userId);
    await ctx.reply(rendered.text, { reply_markup: rendered.keyboard });
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

      // Update the keys message so button state reflects the revoke.
      try {
        const rendered = renderKeysMessage(userId);
        await ctx.editMessageText(rendered.text, {
          reply_markup: rendered.keyboard,
        });
      } catch {
        // ignore (message may not be editable)
      }
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

      try {
        const prev =
          ctx.callbackQuery.message && "text" in ctx.callbackQuery.message
            ? ctx.callbackQuery.message.text
            : "API keys:";
        await ctx.editMessageText(`${prev}\n\nStatus: awaiting new label...`);
      } catch {
        // ignore
      }
      return;
    }

    if (action === "rotate") {
      if (row.revoked_at) {
        await ctx.answerCallbackQuery({ text: "Cannot rotate a revoked key" });
        return;
      }

      await ctx.answerCallbackQuery({ text: "Rotating..." });

      try {
        const now = nowIso();
        const oldLabel = row.label;

        // Free the label under the current unique(user_id, label) constraint by renaming the old key.
        // This keeps the user-facing "label" stable for the new key while preserving history.
        const freedLabel = rotatedLabel(oldLabel, row.id);

        db().transaction(() => {
          db()
            .query(
              "UPDATE api_keys SET revoked_at = ?, updated_at = ?, label = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL;"
            )
            .run(now, now, freedLabel, row.id, userId);
        })();

        const created = await createApiKeyRow({ userId, label: oldLabel });

        auditEvent({
          userId,
          actorType: "telegram",
          actorId: String(ctx.from.id),
          eventType: "api_key_rotated",
          event: {
            oldApiKeyId: row.id,
            newApiKeyId: created.id,
            label: oldLabel,
          },
        });

        await ctx.reply(
          renderOneTimeKeyMessage({
            label: oldLabel,
            apiKey: created.keyPlain,
          }),
          {
            parse_mode: "HTML",
          }
        );

        // Update the keys message so button state reflects the rotation.
        try {
          const rendered = renderKeysMessage(userId);
          await ctx.editMessageText(rendered.text, {
            reply_markup: rendered.keyboard,
          });
        } catch {
          // ignore
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        await ctx.reply(`Failed to rotate key. ${msg}`);
      }
    }
  });

  bot.callbackQuery(/r:(approve|deny):(.+)/, async (ctx) => {
    if (!ctx.from) return;
    const action = ctx.match?.[1];
    const requestId = ctx.match?.[2];
    const userId = ensureUser(ctx.from.id);

    const msg = ctx.callbackQuery.message;
    if (!msg || !("message_id" in msg)) {
      await ctx.answerCallbackQuery({ text: "Missing message" });
      return;
    }

    const decision = action === "approve" ? "approved" : "denied";
    const telegramChatId = "chat" in msg ? msg.chat.id : ctx.from.id;
    const res = decideProxyRequest({
      requestId,
      userId,
      decision,
      telegramUserId: ctx.from.id,
      telegramChatId,
      telegramMessageId: msg.message_id,
    });

    if (!res.ok) {
      await ctx.answerCallbackQuery({ text: res.reason });

      // Best-effort message update for common cases.
      if (res.reason === "expired") {
        try {
          if ("text" in msg && typeof msg.text === "string") {
            await ctx.editMessageText(renderExpiredDecisionText(msg.text), {
              parse_mode: "HTML",
            });
          }
          await ctx.editMessageReplyMarkup({
            reply_markup: new InlineKeyboard(),
          });
        } catch {
          // ignore
        }
      }
      return;
    }

    auditEvent({
      userId,
      requestId,
      actorType: "telegram",
      actorId: String(ctx.from.id),
      eventType:
        decision === "approved"
          ? "proxy_request_approved"
          : "proxy_request_denied",
      event: {},
    });

    await ctx.answerCallbackQuery({ text: decision });

    // Update the approval message to reflect the decision and remove buttons.
    try {
      if ("text" in msg && typeof msg.text === "string") {
        await ctx.editMessageText(
          renderApprovalDecisionText({ originalText: msg.text, decision }),
          { parse_mode: "HTML" }
        );
      }
      await ctx.editMessageReplyMarkup({ reply_markup: new InlineKeyboard() });
    } catch {
      // ignore
    }
  });

  bot.callbackQuery(
    /gs:(approve_clone|approve_push_block|approve_push_allow|deny):(.+)/,
    async (ctx) => {
      if (!ctx.from) return;
      const action = ctx.match?.[1];
      const sessionId = ctx.match?.[2];
      const userId = ensureUser(ctx.from.id);

      const sess = db()
        .query(
          "SELECT operation FROM git_sessions WHERE id = ? AND user_id = ? LIMIT 1;"
        )
        .get(sessionId, userId) as { operation: string } | null;
      const operation = sess?.operation ?? "clone";

      const msg = ctx.callbackQuery.message;
      if (!msg || !("message_id" in msg)) {
        await ctx.answerCallbackQuery({ text: "Missing message" });
        return;
      }

      try {
        if (action === "deny") {
          setGitSessionStatus({ sessionId, userId, status: "DENIED" });
          auditEvent({
            userId,
            actorType: "telegram",
            actorId: String(ctx.from.id),
            eventType: "git_session_denied",
            event: { sessionId },
          });
          await ctx.answerCallbackQuery({ text: "denied" });
        } else if (action === "approve_clone") {
          setGitSessionStatus({ sessionId, userId, status: "APPROVED" });
          auditEvent({
            userId,
            actorType: "telegram",
            actorId: String(ctx.from.id),
            eventType: "git_session_approved",
            event: { sessionId, operation },
          });
          await ctx.answerCallbackQuery({ text: "approved" });
        } else if (action === "approve_push_block") {
          setGitSessionStatus({
            sessionId,
            userId,
            status: "APPROVED",
            allowDefaultBranchPush: false,
          });
          auditEvent({
            userId,
            actorType: "telegram",
            actorId: String(ctx.from.id),
            eventType: "git_session_approved",
            event: {
              sessionId,
              operation,
              allowDefaultBranchPush: false,
            },
          });
          await ctx.answerCallbackQuery({ text: "approved" });
        } else if (action === "approve_push_allow") {
          setGitSessionStatus({
            sessionId,
            userId,
            status: "APPROVED",
            allowDefaultBranchPush: true,
          });
          auditEvent({
            userId,
            actorType: "telegram",
            actorId: String(ctx.from.id),
            eventType: "git_session_approved",
            event: {
              sessionId,
              operation,
              allowDefaultBranchPush: true,
            },
          });
          await ctx.answerCallbackQuery({ text: "approved" });
        }

        try {
          if ("text" in msg && typeof msg.text === "string") {
            const decision = action === "deny" ? "DENIED" : "APPROVED";
            await ctx.editMessageText(
              `${escapeHtml(msg.text)}\n\n<b>Decision</b>: <code>${escapeHtml(decision)}</code> (<code>${escapeHtml(nowIso())}</code>)`,
              { parse_mode: "HTML" }
            );
          }
          await ctx.editMessageReplyMarkup({
            reply_markup: new InlineKeyboard(),
          });
        } catch {
          // ignore
        }
      } catch (err) {
        const em = err instanceof Error ? err.message : String(err);
        await ctx.answerCallbackQuery({ text: em });
      }
    }
  );

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
          renderOneTimeKeyMessage({ label, apiKey: created.keyPlain }),
          {
            parse_mode: "HTML",
          }
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

      // Key rotation is handled immediately from the inline button and does not require extra user input.
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await ctx.reply(`Failed: ${msg}`);
    }
  });

  return bot;
}
