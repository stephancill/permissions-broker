import { Hono } from "hono";
import { env } from "./env";

const app = new Hono();

app.get("/", (c) => c.text("ok"));
app.get("/healthz", (c) => c.json({ ok: true }));

Bun.serve({
  port: env.PORT,
  fetch: app.fetch,
});

console.log(`listening on http://localhost:${env.PORT}`);
