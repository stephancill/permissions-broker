import { createApp } from "./app";
import { migrate } from "./db/migrate";
import { env } from "./env";

if (env.NODE_ENV !== "test") {
  await migrate();
}

if (env.TELEGRAM_BOT_TOKEN) {
  const { createBot } = await import("./telegram/bot");
  const { startTelegramPoller } = await import("./telegram/poller");
  const bot = createBot();
  startTelegramPoller(bot).catch((err) => {
    console.error("telegram poller failed", err);
  });
}

if (env.NODE_ENV !== "test") {
  const { startSweeperLoop } = await import("./proxy/sweeper");
  startSweeperLoop().catch((err) => {
    console.error("sweeper failed", err);
  });
}

const app = createApp({ includeGit: true });

Bun.serve({
  port: env.PORT,
  fetch: app.fetch,
});

console.log(`listening on http://localhost:${env.PORT}`);
