import { Hono } from "hono";

import { accountRouter } from "./web/accounts";
import { approveRouter } from "./web/approve";
import { emailRouter } from "./web/email";
import { gitRouter } from "./web/git";
import { passkeyRouter } from "./web/passkey";
import { proxyRouter } from "./web/proxy";
import { whoamiRouter } from "./web/whoami";

type CreateAppOptions = {
  includeGit?: boolean;
  includeTelegramWebhook?: boolean;
};

// Defense-in-depth response headers applied to every reply. The connect forms
// and OAuth callback render untrusted (state-derived) HTML, so we lock down
// framing and resource loading; the rest of the surface is a JSON/octet API.
const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "no-referrer",
  "X-XSS-Protection": "0",
  // Default for the connect forms (inline <style>, no scripts). Passkey pages
  // set their own nonce-based CSP, which must not be overwritten.
  "Content-Security-Policy":
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
};

export function createApp(options: CreateAppOptions = {}) {
  const app = new Hono();

  app.use("*", async (c, next) => {
    await next();
    // Fill in defaults only; handlers that set a header (e.g. a stricter or
    // nonce-based CSP) keep theirs.
    for (const [name, value] of Object.entries(securityHeaders)) {
      if (!c.res.headers.has(name)) c.res.headers.set(name, value);
    }
  });

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

  // Browser pages for passkey enrollment and approvals.
  app.route("/passkey", passkeyRouter);
  app.route("/approve", approveRouter);

  app.route("/v1/accounts", accountRouter);
  app.route("/v1/email", emailRouter);
  if (options.includeGit) app.route("/v1/git", gitRouter);
  app.route("/v1/proxy", proxyRouter);
  app.route("/v1", whoamiRouter);

  return app;
}
