import type { Bot } from "grammy";

import { db } from "../db/client";

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export async function startTelegramPoller(bot: Bot): Promise<void> {
  // grammY requires initialization (fetches bot info via getMe) before handleUpdate.
  await bot.init();

  // Long polling and webhooks are mutually exclusive in Telegram.
  // Ensure we can receive updates via getUpdates in local/dev.
  await bot.api.deleteWebhook({ drop_pending_updates: false });

  const database = await db();
  let lastUpdateId = (
    (await database
      .query("SELECT last_update_id FROM telegram_state WHERE id = 1;")
      .get()) as { last_update_id: number } | null
  )?.last_update_id;

  if (typeof lastUpdateId !== "number") lastUpdateId = 0;

  let retryMs = 1_000;

  for (;;) {
    let updates: Awaited<ReturnType<typeof bot.api.getUpdates>>;
    try {
      updates = await bot.api.getUpdates({
        offset: lastUpdateId + 1,
        timeout: 30,
        allowed_updates: ["message", "callback_query"],
      });
      retryMs = 1_000;
    } catch (err) {
      console.error("telegram getUpdates failed; retrying", err);
      await sleep(retryMs);
      retryMs = Math.min(retryMs * 2, 30_000);
      continue;
    }

    for (const u of updates) {
      try {
        await bot.handleUpdate(u);
      } catch (err) {
        console.error(
          "telegram update handling failed",
          { updateId: u.update_id },
          err
        );
      } finally {
        lastUpdateId = u.update_id;
        await database
          .query("UPDATE telegram_state SET last_update_id = ? WHERE id = 1;")
          .run(lastUpdateId);
      }
    }
  }
}
