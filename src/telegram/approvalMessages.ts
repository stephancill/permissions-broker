import type { InlineKeyboardMarkup } from "grammy/types";

import { db } from "../db/client";
import { env } from "../env";
import { telegramApi } from "./api";

export type ApprovalMessageKind = "proxy" | "git" | "email";
export type ApprovalMessageDecision = "APPROVED" | "DENIED" | "EXPIRED";

export type ApprovalMessageRef = {
  id: string;
  telegram_chat_id: number | null;
  telegram_message_id: number | null;
  telegram_message_html: string | null;
};

const TABLES: Record<ApprovalMessageKind, string> = {
  proxy: "proxy_requests",
  git: "git_sessions",
  email: "email_sessions",
};

function nowIso(): string {
  return new Date().toISOString();
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

// Sends the approval prompt and remembers it so the decision can be shown on
// it later, wherever the decision is made.
export async function sendApprovalMessage(params: {
  kind: ApprovalMessageKind;
  id: string;
  chatId: number;
  html: string;
  replyMarkup: InlineKeyboardMarkup;
}): Promise<void> {
  try {
    const msg = await telegramApi().sendMessage(params.chatId, params.html, {
      reply_markup: params.replyMarkup,
      parse_mode: "HTML",
    });
    const database = await db();
    await database
      .query(
        `UPDATE ${TABLES[params.kind]} SET telegram_chat_id = ?, telegram_message_id = ?, telegram_message_html = ? WHERE id = ?;`
      )
      .run(msg.chat.id, msg.message_id, params.html, params.id);
  } catch (err) {
    console.error(
      `telegram approval message send failed (${params.kind} ${params.id}): ${errorMessage(err)}`
    );
  }
}

// Appends the decision to the approval prompt and removes its buttons.
// Best-effort: the decision is already persisted when this runs.
export async function editApprovalMessages(params: {
  kind: ApprovalMessageKind;
  refs: ApprovalMessageRef[];
  decision: ApprovalMessageDecision;
  note?: string;
}): Promise<void> {
  if (!env.TELEGRAM_BOT_TOKEN) return;
  const note = params.note ? `\n${escapeHtml(params.note)}` : "";
  for (const ref of params.refs) {
    if (
      ref.telegram_chat_id == null ||
      ref.telegram_message_id == null ||
      ref.telegram_message_html == null
    ) {
      continue;
    }
    try {
      await telegramApi().editMessageText(
        ref.telegram_chat_id,
        ref.telegram_message_id,
        `${ref.telegram_message_html}\n\n<b>Decision</b>: <code>${params.decision}</code> (<code>${nowIso()}</code>)${note}`,
        { parse_mode: "HTML", reply_markup: { inline_keyboard: [] } }
      );
    } catch (err) {
      console.error(
        `telegram approval message edit failed (${params.kind} ${ref.id}): ${errorMessage(err)}`
      );
    }
  }
}

export async function markApprovalMessage(params: {
  kind: ApprovalMessageKind;
  id: string;
  decision: ApprovalMessageDecision;
  note?: string;
}): Promise<void> {
  const database = await db();
  const ref = await database
    .query(
      `SELECT id, telegram_chat_id, telegram_message_id, telegram_message_html FROM ${TABLES[params.kind]} WHERE id = ?;`
    )
    .get<ApprovalMessageRef>(params.id);
  if (!ref) return;
  await editApprovalMessages({
    kind: params.kind,
    refs: [ref],
    decision: params.decision,
    note: params.note,
  });
}
