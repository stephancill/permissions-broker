import { Hono } from "hono";

import { accountRouter } from "./web/accounts";
import { emailRouter } from "./web/email";
import { gitRouter } from "./web/git";
import { proxyRouter } from "./web/proxy";
import { whoamiRouter } from "./web/whoami";

type CreateAppOptions = {
  includeGit?: boolean;
  includeTelegramWebhook?: boolean;
};

export function createApp(options: CreateAppOptions = {}) {
  const app = new Hono();

  app.get("/", (c) => c.text("ok"));
  app.get("/healthz", (c) => c.json({ ok: true }));

  if (options.includeTelegramWebhook) {
    app.post("/telegram/webhook", async (c) => {
      const { createBot } = await import("./telegram/bot");
      const bot = createBot();
      await bot.init();
      await bot.handleUpdate(await c.req.json());
      return c.json({ ok: true });
    });
  }

  app.route("/v1/accounts", accountRouter);
  app.route("/v1/email", emailRouter);
  if (options.includeGit) app.route("/v1/git", gitRouter);
  app.route("/v1/proxy", proxyRouter);
  app.route("/v1", whoamiRouter);

  return app;
}
