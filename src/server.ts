import { Hono } from "hono";
import { migrate } from "./db/migrate";
import { env } from "./env";

import { accountRouter } from "./web/accounts";
import { gitRouter } from "./web/git";
import { proxyRouter } from "./web/proxy";
import { whoamiRouter } from "./web/whoami";

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

if (env.NODE_ENV !== "test") {
  const { startSweeperLoop } = await import("./proxy/sweeper");
  startSweeperLoop().catch((err) => {
    console.error("sweeper failed", err);
  });
}

const app = new Hono();

app.get("/", (c) => c.text("ok"));
app.get("/healthz", (c) => c.json({ ok: true }));

app.route("/v1/accounts", accountRouter);
app.route("/v1/git", gitRouter);
app.route("/v1/proxy", proxyRouter);
app.route("/v1", whoamiRouter);

Bun.serve({
  port: env.PORT,
  fetch: app.fetch,
});

console.log(`listening on http://localhost:${env.PORT}`);
