import { type Context, Hono } from "hono";
import { z } from "zod";

import { ApiKeyLabelSchema } from "../auth/apiKeyAdmin";
import { createDeviceAuthorization, pollDeviceToken } from "../auth/device";
import { expectedOrigin } from "../passkey/webauthn";

// RFC 8628 device authorization endpoints. Unauthenticated by design: the CLI
// has no credential yet. The user approves at /device (see web/app.ts).

export const deviceRouter = new Hono();

const DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";

const AuthorizeSchema = z.object({
  client_id: z
    .string()
    .regex(/^[A-Za-z0-9._-]{1,64}$/)
    .default("stupid-vault-cli"),
  // Suggested API key label (e.g. the machine name); the user can edit it.
  label: ApiKeyLabelSchema.optional(),
});

const TokenSchema = z.object({
  grant_type: z.literal(DEVICE_CODE_GRANT),
  device_code: z.string().min(1).max(128),
});

// RFC 8628 uses form encoding; JSON is accepted for convenience.
async function readParams(c: Context): Promise<Record<string, unknown>> {
  const type = c.req.header("content-type") ?? "";
  if (type.includes("application/json")) {
    const body = await c.req.json().catch(() => null);
    return body && typeof body === "object" ? body : {};
  }
  if (type.includes("application/x-www-form-urlencoded")) {
    const form = await c.req.parseBody();
    return Object.fromEntries(
      Object.entries(form).filter(([, v]) => typeof v === "string")
    );
  }
  return {};
}

function noStore(c: Context): void {
  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");
}

deviceRouter.post("/authorize", async (c) => {
  noStore(c);
  const parsed = AuthorizeSchema.safeParse(await readParams(c));
  if (!parsed.success) {
    return c.json(
      {
        error: "invalid_request",
        error_description: parsed.error.issues[0]?.message,
      },
      400
    );
  }
  const created = await createDeviceAuthorization({
    clientId: parsed.data.client_id,
    labelHint: parsed.data.label ?? null,
  });
  const verificationUri = `${expectedOrigin()}/device`;
  return c.json({
    device_code: created.deviceCode,
    user_code: created.userCode,
    verification_uri: verificationUri,
    verification_uri_complete: `${verificationUri}?user_code=${encodeURIComponent(created.userCode)}`,
    expires_in: created.expiresIn,
    interval: created.interval,
  });
});

deviceRouter.post("/token", async (c) => {
  noStore(c);
  const params = await readParams(c);
  if (params.grant_type !== DEVICE_CODE_GRANT) {
    return c.json({ error: "unsupported_grant_type" }, 400);
  }
  const parsed = TokenSchema.safeParse(params);
  if (!parsed.success) {
    return c.json({ error: "invalid_request" }, 400);
  }
  const result = await pollDeviceToken({ deviceCode: parsed.data.device_code });
  if (!result.ok) {
    return c.json(
      {
        error: result.error,
        ...(result.description
          ? { error_description: result.description }
          : {}),
      },
      400
    );
  }
  return c.json({
    access_token: result.accessToken,
    token_type: "Bearer",
    api_key_label: result.label,
  });
});
