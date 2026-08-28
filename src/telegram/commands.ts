import { db } from "../db/client";
import { telegramApi } from "./api";

const COMMAND_REFRESH_MS = 24 * 60 * 60 * 1000;

const botCommands = [
  { command: "start", description: "Start permissions broker" },
  { command: "connect", description: "Link or manage provider accounts" },
  { command: "key", description: "Create a new API key" },
  { command: "keys", description: "List, rotate, rename, or revoke API keys" },
];

function nowIso(): string {
  return new Date().toISOString();
}

function shouldRefresh(registeredAt: string | null): boolean {
  if (!registeredAt) return true;
  const t = Date.parse(registeredAt);
  return !Number.isFinite(t) || Date.now() - t > COMMAND_REFRESH_MS;
}

export async function ensureTelegramBotCommandsRegistered(): Promise<void> {
  const database = await db();
  const row = (await database
    .query(
      "SELECT bot_commands_registered_at FROM telegram_state WHERE id = 1 LIMIT 1;"
    )
    .get()) as { bot_commands_registered_at: string | null } | null;

  if (!shouldRefresh(row?.bot_commands_registered_at ?? null)) return;

  await telegramApi().setMyCommands(botCommands);

  await database
    .query(
      "UPDATE telegram_state SET bot_commands_registered_at = ? WHERE id = 1;"
    )
    .run(nowIso());
}
