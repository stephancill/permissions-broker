import {
  generateRegistrationOptions,
  type RegistrationResponseJSON,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { Hono } from "hono";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { getConnectState, markConnectStateUsed } from "../connect/state";
import {
  getUserPublicKey,
  migrateLegacyCredentials,
  revokeUndecryptableCredentials,
} from "../credentials/store";
import { bytesEqual, fromBase64Url, toBase64Url } from "../crypto/bytes";
import { randomBase64Url } from "../crypto/random";
import { db } from "../db/client";
import { env } from "../env";
import {
  consumeChallenge,
  expectedOrigin,
  expectedRpId,
  getUserPasskey,
  getWrappedPrivateKey,
  storeChallenge,
} from "../passkey/webauthn";
import {
  escapeHtml,
  scriptJson,
  sendKeyPage,
  sendMessagePage,
  TELEGRAM_WEBVIEW_NOTICE,
  TELEGRAM_WEBVIEW_SCRIPT,
} from "./pages";

export const PASSKEY_CONNECT_PROVIDER = "passkey";

const EnrollMode = z.enum(["new", "rewrap", "replace_lost"]);

const OptionsSchema = z.object({ state: z.string().min(1) });

const VerifySchema = z.object({
  state: z.string().min(1),
  nonce: z.string().min(1),
  mode: EnrollMode,
  registration: z.record(z.string(), z.unknown()),
  public_key: z.string().min(1),
  wrapped_private_key: z.string().min(1),
});

function nowIso(): string {
  return new Date().toISOString();
}

async function userIdForState(state: string): Promise<string> {
  const { userId } = await getConnectState({
    state,
    provider: PASSKEY_CONNECT_PROVIDER,
  });
  return userId;
}

export const passkeyRouter = new Hono();

passkeyRouter.get("/enroll", async (c) => {
  const state = c.req.query("state");
  if (!state) {
    return sendMessagePage(c, {
      title: "Passkey setup",
      message: "Missing link state. Use /passkey in Telegram.",
      status: 400,
    });
  }

  let userId: string;
  try {
    userId = await userIdForState(state);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return sendMessagePage(c, {
      title: "Passkey setup",
      message: `This link is no longer valid (${msg}). Use /passkey in Telegram for a new one.`,
      status: 400,
    });
  }

  const enrolled = (await getUserPublicKey(userId)) != null;
  const body = `
    <h1>${enrolled ? "Replace passkey" : "Set up your passkey"}</h1>
    ${TELEGRAM_WEBVIEW_NOTICE}
    <div id="main">
      <p>Your connected accounts are encrypted with a key that only this passkey can unlock. Every approval needs Face ID / Touch ID.</p>
      <p class="note">Save the passkey in your device's password manager (e.g. Apple Passwords). It must support the passkey PRF extension.</p>
      ${
        enrolled
          ? `<button id="rewrap" type="button">Replace passkey (I still have my current one)</button>
             <button id="replace_lost" type="button">I lost my passkey — start over</button>
             <p class="note">Starting over disconnects every linked account; you will need to reconnect them.</p>`
          : `<button id="new" type="button">Create passkey</button>`
      }
      <p id="status"></p>
    </div>`;

  const script = `
    ${TELEGRAM_WEBVIEW_SCRIPT}
    var STATE = ${scriptJson(state)};
    var statusEl = document.getElementById("status");
    function setStatus(text, cls) { statusEl.textContent = text; statusEl.className = cls || ""; }

    async function postJson(path, body) {
      var res = await fetch(path, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      var json = await res.json().catch(function () { return {}; });
      if (!res.ok) throw new Error(json.message || json.error || ("HTTP " + res.status));
      return json;
    }

    async function prfFromGet(rpId, credentialIdBytes, salt) {
      var a = await navigator.credentials.get({ publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rpId: rpId,
        allowCredentials: [{ type: "public-key", id: credentialIdBytes }],
        userVerification: "required",
        extensions: { prf: { eval: { first: salt } } },
      }});
      return PB.prfFirst(a);
    }

    async function enroll(mode) {
      if (mode === "replace_lost" && !confirm("This disconnects all linked accounts. Continue?")) return;
      setStatus("Preparing…");
      var o = await postJson("/passkey/enroll/options", { state: STATE });
      var opts = o.registration_options;
      var userId = o.user_id;

      var privateKey, publicKeyRaw;
      if (mode === "rewrap") {
        setStatus("Unlock your current passkey…");
        var oldPrf = await prfFromGet(opts.rp.id, PB.unb64u(o.existing.credential_id), PB.unb64u(o.existing.prf_salt));
        if (!oldPrf) throw new Error("Current passkey did not return a PRF value.");
        var oldKek = await PB.deriveKek(oldPrf, userId);
        privateKey = await PB.unwrapPrivateKey(oldKek, PB.unb64u(o.existing.wrapped_private_key), userId, true);
        publicKeyRaw = PB.unb64u(o.existing.public_key);
      } else {
        var pair = await PB.generateUserKeypair();
        privateKey = pair.privateKey;
        publicKeyRaw = pair.publicKeyRaw;
      }

      setStatus("Create the passkey…");
      var salt = PB.unb64u(o.prf_salt);
      var cred = await navigator.credentials.create({ publicKey: {
        rp: opts.rp,
        user: { id: PB.unb64u(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
        challenge: PB.unb64u(opts.challenge),
        pubKeyCredParams: opts.pubKeyCredParams,
        timeout: opts.timeout,
        attestation: "none",
        authenticatorSelection: { residentKey: "required", requireResidentKey: true, userVerification: "required" },
        extensions: { prf: { eval: { first: salt } } },
      }});

      var prf = PB.prfFirst(cred);
      if (!prf) {
        setStatus("Unlock the new passkey once more…");
        prf = await prfFromGet(opts.rp.id, new Uint8Array(cred.rawId), salt);
      }
      if (!prf) throw new Error("This passkey provider does not support the PRF extension. Try Apple Passwords.");

      var kek = await PB.deriveKek(prf, userId);
      var wrapped = await PB.wrapPrivateKey(kek, privateKey, userId);

      setStatus("Saving…");
      var r = await postJson("/passkey/enroll/verify", {
        state: STATE,
        nonce: o.nonce,
        mode: mode,
        registration: PB.registrationToJSON(cred),
        public_key: PB.b64u(publicKeyRaw),
        wrapped_private_key: PB.b64u(wrapped),
      });
      setStatus(r.message, "ok");
      document.querySelectorAll("button").forEach(function (b) { b.disabled = true; });
    }

    if (!guardTelegramWebview("main")) {
      ["new", "rewrap", "replace_lost"].forEach(function (mode) {
        var b = document.getElementById(mode);
        if (b) b.onclick = function () {
          enroll(mode).catch(function (e) { setStatus("Failed: " + (e && e.message ? e.message : e), "error"); });
        };
      });
    }
  `;

  return sendKeyPage(c, { title: "Passkey setup", body, script });
});

passkeyRouter.post("/enroll/options", async (c) => {
  const parsed = OptionsSchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);

  let userId: string;
  try {
    userId = await userIdForState(parsed.data.state);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.json({ error: "invalid_state", message: msg }, 400);
  }

  const registrationOptions = await generateRegistrationOptions({
    rpName: "Permissions Broker",
    rpID: expectedRpId(),
    userName: "Permissions Broker",
    userDisplayName: "Permissions Broker",
    userID: new TextEncoder().encode(userId),
    attestationType: "none",
    authenticatorSelection: {
      residentKey: "required",
      userVerification: "required",
    },
  });

  const prfSalt = randomBase64Url(32);
  const { nonce } = await storeChallenge({
    userId,
    purpose: "enroll",
    challenge: registrationOptions.challenge,
    options: { prf_salt: prfSalt },
  });

  const passkey = await getUserPasskey(userId);
  const publicKey = await getUserPublicKey(userId);
  const wrapped = await getWrappedPrivateKey(userId);

  return c.json({
    nonce,
    user_id: userId,
    prf_salt: prfSalt,
    registration_options: registrationOptions,
    existing:
      passkey && publicKey && wrapped
        ? {
            credential_id: passkey.credential_id,
            prf_salt: passkey.prf_salt,
            public_key: toBase64Url(publicKey),
            wrapped_private_key: toBase64Url(wrapped),
          }
        : null,
  });
});

passkeyRouter.post("/enroll/verify", async (c) => {
  const parsed = VerifySchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);
  const body = parsed.data;

  let userId: string;
  try {
    userId = await userIdForState(body.state);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.json({ error: "invalid_state", message: msg }, 400);
  }

  const challenge = await consumeChallenge({
    nonce: body.nonce,
    userId,
    purpose: "enroll",
  });
  if (!challenge) return c.json({ error: "invalid_challenge" }, 400);
  const prfSalt = (
    JSON.parse(challenge.options_json ?? "{}") as { prf_salt?: string }
  ).prf_salt;
  if (!prfSalt) return c.json({ error: "invalid_challenge" }, 400);

  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response: body.registration as unknown as RegistrationResponseJSON,
      expectedChallenge: challenge.challenge,
      expectedOrigin: expectedOrigin(),
      expectedRPID: expectedRpId(),
      requireUserVerification: true,
    });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return c.json({ error: "registration_failed", message: msg }, 400);
  }
  if (!verification.verified) {
    return c.json({ error: "registration_failed" }, 400);
  }

  const publicKey = fromBase64Url(body.public_key);
  const wrappedPrivateKey = fromBase64Url(body.wrapped_private_key);
  if (publicKey.byteLength !== 65 || publicKey[0] !== 4) {
    return c.json({ error: "invalid_public_key" }, 400);
  }
  if (wrappedPrivateKey.byteLength < 64) {
    return c.json({ error: "invalid_wrapped_private_key" }, 400);
  }

  const existingPublicKey = await getUserPublicKey(userId);
  if (!existingPublicKey && body.mode !== "new") {
    return c.json(
      { error: "invalid_mode", message: "no passkey to replace" },
      400
    );
  }
  if (existingPublicKey && body.mode === "new") {
    return c.json(
      { error: "invalid_mode", message: "a passkey is already enrolled" },
      400
    );
  }
  if (
    body.mode === "rewrap" &&
    existingPublicKey &&
    !bytesEqual(existingPublicKey, publicKey)
  ) {
    return c.json(
      { error: "invalid_mode", message: "re-wrap must keep the same key" },
      400
    );
  }

  const database = await db();
  const now = nowIso();

  let revoked = 0;
  if (body.mode === "replace_lost") {
    revoked = await revokeUndecryptableCredentials(userId);
  }

  const cred = verification.registrationInfo.credential;
  await database
    .query(
      "INSERT INTO user_passkeys (user_id, credential_id, public_key, sign_count, transports, prf_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(user_id) DO UPDATE SET credential_id = excluded.credential_id, public_key = excluded.public_key, sign_count = excluded.sign_count, transports = excluded.transports, prf_salt = excluded.prf_salt, created_at = excluded.created_at;"
    )
    .run(
      userId,
      cred.id,
      cred.publicKey,
      cred.counter,
      cred.transports ? JSON.stringify(cred.transports) : null,
      prfSalt,
      now
    );

  await database
    .query(
      "INSERT INTO user_keys (user_id, public_key, wrapped_private_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?) " +
        "ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key, wrapped_private_key = excluded.wrapped_private_key, updated_at = excluded.updated_at;"
    )
    .run(userId, publicKey, wrappedPrivateKey, now, now);

  const migration = await migrateLegacyCredentials(userId);
  await markConnectStateUsed(body.state);

  await auditEvent({
    userId,
    actorType: "system",
    actorId: "passkey_enroll",
    eventType: "passkey_enrolled",
    event: {
      mode: body.mode,
      credential_id: cred.id,
      migrated: migration.migrated,
      migration_failed: migration.failed,
      revoked,
    },
  });

  const parts = ["Passkey saved."];
  if (migration.migrated)
    parts.push(
      `Re-encrypted ${migration.migrated} linked account(s) to your passkey.`
    );
  if (migration.failed)
    parts.push(
      `${migration.failed} account(s) could not be migrated and were disconnected.`
    );
  if (revoked)
    parts.push(
      `${revoked} account(s) were disconnected; reconnect them with /connect.`
    );
  const message = `${parts.join(" ")} You can return to Telegram.`;

  const telegram = (await database
    .query("SELECT telegram_user_id FROM users WHERE id = ?;")
    .get(userId)) as { telegram_user_id: number } | null;
  if (telegram?.telegram_user_id && env.TELEGRAM_BOT_TOKEN) {
    const { telegramApi } = await import("../telegram/api");
    await telegramApi()
      .sendMessage(telegram.telegram_user_id, escapeHtml(message), {
        parse_mode: "HTML",
      })
      .catch(() => {});
  }

  return c.json({ ok: true, message });
});
