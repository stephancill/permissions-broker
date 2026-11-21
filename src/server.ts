import { Hono } from "hono";
import { serveStatic } from "hono/bun";

import { createApp } from "./app";
import { migrate } from "./db/migrate";
import { env } from "./env";

if (env.NODE_ENV !== "test") {
  await migrate();
}

if (env.NODE_ENV !== "test") {
  const { startSweeperLoop } = await import("./proxy/sweeper");
  startSweeperLoop().catch((err) => {
    console.error("sweeper failed", err);
  });
}

// On Workers, public/ is served by the assets binding (wrangler.toml).
const app = new Hono();
app.use("*", serveStatic({ root: "./public" }));
app.route("/", createApp({ includeGit: true }));

Bun.serve({
  port: env.PORT,
  fetch: app.fetch,
});

console.log(`listening on http://localhost:${env.PORT}`);
