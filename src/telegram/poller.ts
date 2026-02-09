import type { Bot } from "grammy";

import { db } from "../db/client";

export async function startTelegramPoller(bot: Bot): Promise<void> {
  // grammY requires initialization (fetches bot info via getMe) before handleUpdate.
  await bot.init();

  let lastUpdateId = (
    db()
      .query("SELECT last_update_id FROM telegram_state WHERE id = 1;")
      .get() as { last_update_id: number } | null
  )?.last_update_id;

  if (typeof lastUpdateId !== "number") lastUpdateId = 0;

  for (;;) {
    const updates = await bot.api.getUpdates({
      offset: lastUpdateId + 1,
      timeout: 30,
      allowed_updates: ["message", "callback_query"],
    });

    for (const u of updates) {
      await bot.handleUpdate(u);
      lastUpdateId = u.update_id;
      db()
        .query("UPDATE telegram_state SET last_update_id = ? WHERE id = 1;")
        .run(lastUpdateId);
    }
  }
}
