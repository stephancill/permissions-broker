import { Hono } from "hono";

import {
  expectedOrigin,
  legacyRpId,
  relatedOriginsDocument,
} from "./passkey/webauthn";
import { accountRouter } from "./web/accounts";
import { appRouter, MANIFEST, SERVICE_WORKER_JS } from "./web/app";
import { approveRouter } from "./web/approve";
import { emailRouter } from "./web/email";
import { gitRouter } from "./web/git";
import { passkeyRouter } from "./web/passkey";
import { proxyRouter } from "./web/proxy";
import { whoamiRouter } from "./web/whoami";

type CreateAppOptions = {
  includeGit?: boolean;
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

  // Previous domain while migrating (WEBAUTHN_LEGACY_RP_ID): it vouches for
  // the new origin so old passkeys keep working, and keeps serving the agent
  // API (agents and OAuth callbacks may still use it). Pages redirect.
  app.use("*", async (c, next) => {
    const legacy = legacyRpId();
    const url = new URL(c.req.url);
    if (!legacy || url.hostname !== legacy) return next();
    if (url.pathname === "/.well-known/webauthn") {
      c.header("Cache-Control", "no-cache");
      return c.json(relatedOriginsDocument());
    }
    if (url.pathname.startsWith("/v1/") || url.pathname === "/healthz") {
      return next();
    }
    return c.redirect(`${expectedOrigin()}${url.pathname}${url.search}`, 308);
  });

  app.get("/", (c) => c.redirect("/app", 302));
  app.get("/healthz", (c) => c.json({ ok: true }));

  // PWA: installable app shell, passkey sign-in/enrollment and approvals.
  app.get("/manifest.webmanifest", (c) => {
    c.header("Content-Type", "application/manifest+json");
    c.header("Cache-Control", "no-cache");
    return c.body(JSON.stringify(MANIFEST));
  });
  app.get("/sw.js", (c) => {
    c.header("Content-Type", "text/javascript; charset=utf-8");
    c.header("Cache-Control", "no-cache");
    c.header("Content-Security-Policy", "default-src 'self'");
    return c.body(SERVICE_WORKER_JS);
  });
  app.route("/app", appRouter);
  app.route("/passkey", passkeyRouter);
  app.route("/approve", approveRouter);

  app.route("/v1/accounts", accountRouter);
  app.route("/v1/email", emailRouter);
  if (options.includeGit) app.route("/v1/git", gitRouter);
  app.route("/v1/proxy", proxyRouter);
  app.route("/v1", whoamiRouter);

  return app;
}
