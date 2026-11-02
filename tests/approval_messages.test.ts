import { afterAll, beforeAll, beforeEach, expect, test } from "bun:test";
import { ulid } from "ulid";

import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { createEmailSession } from "../src/email/sessions";
import { sweepEmailSessions } from "../src/email/sweeper";
import { configureEnv, type Env, env } from "../src/env";
import { telegramApi } from "../src/telegram/api";
import {
  markApprovalMessage,
  sendApprovalMessage,
} from "../src/telegram/approvalMessages";

type Call = { method: string; payload: Record<string, unknown> };

await migrate();

const calls: Call[] = [];
let prevEnv: Env;

// Scope the bot token to this file: other tests create sessions without
// APP_BASE_URL and must not try to build Telegram prompts.
beforeAll(() => {
  prevEnv = env;
  configureEnv({ ...env, TELEGRAM_BOT_TOKEN: "123:test-token" });
  // Intercept Bot API calls instead of hitting Telegram.
  telegramApi().config.use(async (_prev, method, payload) => {
    calls.push({ method, payload: payload as Record<string, unknown> });
    const result =
      method === "sendMessage"
        ? { message_id: 42, chat: { id: 777, type: "private" }, date: 0 }
        : true;
    return { ok: true, result } as never;
  });
});

afterAll(() => {
  configureEnv(prevEnv);
});

const PROMPT_HTML = "<b>Email read session request</b>\n\nReview and approve.";
const KEYBOARD = {
  inline_keyboard: [[{ text: "Deny", callback_data: "es:deny:x" }]],
};

async function createPendingSession(): Promise<string> {
  const database = await db();
  const userId = ulid();
  const apiKeyId = ulid();
  const now = new Date().toISOString();
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, 'active');"
    )
    .run(userId, 777, now);
  await database
    .query(
      "INSERT INTO api_keys (id, user_id, label, key_hash, created_at, updated_at, revoked_at, last_used_at) VALUES (?, ?, 'agent', ?, ?, ?, NULL, NULL);"
    )
    .run(apiKeyId, userId, ulid(), now, now);
  const { sessionId } = await createEmailSession({
    userId,
    apiKeyId,
    approvalTtlMs: 60_000,
  });
  await sendApprovalMessage({
    kind: "email",
    id: sessionId,
    chatId: 777,
    html: PROMPT_HTML,
    replyMarkup: KEYBOARD,
  });
  return sessionId;
}

beforeEach(async () => {
  calls.length = 0;
  const database = await db();
  for (const table of ["email_sessions", "api_keys", "users"]) {
    await database.exec(`DELETE FROM ${table};`);
  }
});

test("sendApprovalMessage stores the sent message reference", async () => {
  const sessionId = await createPendingSession();
  const database = await db();
  const row = await database
    .query(
      "SELECT telegram_chat_id, telegram_message_id, telegram_message_html FROM email_sessions WHERE id = ?;"
    )
    .get(sessionId);
  expect(row).toEqual({
    telegram_chat_id: 777,
    telegram_message_id: 42,
    telegram_message_html: PROMPT_HTML,
  });
  expect(calls.map((c) => c.method)).toEqual(["sendMessage"]);
});

test("markApprovalMessage appends the decision and clears the buttons", async () => {
  const sessionId = await createPendingSession();
  await markApprovalMessage({
    kind: "email",
    id: sessionId,
    decision: "APPROVED",
    note: "Default-branch pushes <allowed>.",
  });

  const edit = calls.find((c) => c.method === "editMessageText");
  expect(edit?.payload.chat_id).toBe(777);
  expect(edit?.payload.message_id).toBe(42);
  expect(edit?.payload.parse_mode).toBe("HTML");
  expect(edit?.payload.reply_markup).toEqual({ inline_keyboard: [] });
  const text = String(edit?.payload.text);
  expect(
    text.startsWith(`${PROMPT_HTML}\n\n<b>Decision</b>: <code>APPROVED</code>`)
  ).toBe(true);
  expect(text.endsWith("\nDefault-branch pushes &lt;allowed&gt;.")).toBe(true);
});

test("sweeper marks prompts of expired pending sessions", async () => {
  const sessionId = await createPendingSession();
  const database = await db();
  await database
    .query("UPDATE email_sessions SET approval_expires_at = ? WHERE id = ?;")
    .run(new Date(Date.now() - 1000).toISOString(), sessionId);

  await sweepEmailSessions();
  const edits = calls.filter((c) => c.method === "editMessageText");
  expect(edits).toHaveLength(1);
  expect(String(edits[0]?.payload.text)).toContain(
    "<b>Decision</b>: <code>EXPIRED</code>"
  );

  // Already expired: a second sweep must not edit again.
  await sweepEmailSessions();
  expect(calls.filter((c) => c.method === "editMessageText")).toHaveLength(1);
});
