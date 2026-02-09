import { Hono } from "hono";
import { migrate } from "./db/migrate";
import { env } from "./env";

import { accountRouter } from "./web/accounts";

if (env.NODE_ENV !== "test") {
  migrate();
}

if (env.TELEGRAM_BOT_TOKEN) {
  const { createBot } = await import("./telegram/bot");
  const { startTelegramPoller } = await import("./telegram/poller");
  const bot = createBot();
  startTelegramPoller(bot).catch((err) => {
    console.error("telegram poller failed", err);
  });
}

const app = new Hono();

app.get("/", (c) => c.text("ok"));
app.get("/healthz", (c) => c.json({ ok: true }));

app.route("/v1/accounts", accountRouter);

Bun.serve({
  port: env.PORT,
  fetch: app.fetch,
});

console.log(`listening on http://localhost:${env.PORT}`);
