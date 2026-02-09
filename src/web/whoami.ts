import { Hono } from "hono";

import { requireApiKey } from "../auth/apiKey";

export const whoamiRouter = new Hono();

whoamiRouter.get("/whoami", requireApiKey, (c) => {
  const auth = c.get("apiKeyAuth");
  return c.json({
    user_id: auth.userId,
    api_key_id: auth.apiKeyId,
    api_key_label: auth.apiKeyLabel,
  });
});
