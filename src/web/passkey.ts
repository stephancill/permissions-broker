import {
  type AuthenticationResponseJSON,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type RegistrationResponseJSON,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { type Context, Hono } from "hono";
import { ulid } from "ulid";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import {
  createWebSession,
  endWebSession,
  requireSameOrigin,
  requireSessionJson,
  requireSessionPage,
} from "../auth/session";
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
  consumeAuthChallenge,
  consumeChallenge,
  expectedOrigin,
  expectedRpId,
  getUserPasskey,
  getWrappedPrivateKey,
  storeAuthChallenge,
  storeChallenge,
  userIdForCredential,
  verifyPasskeyAssertion,
} from "../passkey/webauthn";
import { POST_JSON_SCRIPT, sendPage } from "./pages";

const ReplaceMode = z.enum(["rewrap", "replace_lost"]);
type EnrollMode = "new" | z.infer<typeof ReplaceMode>;

const EnrollmentFields = {
  nonce: z.string().min(1),
  registration: z.record(z.string(), z.unknown()),
  public_key: z.string().min(1),
  wrapped_private_key: z.string().min(1),
};

const SignupVerifySchema = z.object(EnrollmentFields);
const ReplaceVerifySchema = z.object({
  ...EnrollmentFields,
  mode: ReplaceMode,
});
const SigninVerifySchema = z.object({
  nonce: z.string().min(1),
  assertion: z.record(z.string(), z.unknown()),
});

function nowIso(): string {
  return new Date().toISOString();
}

// Open while the broker has no users (first-run bootstrap) or when enabled.
export async function isSignupAllowed(): Promise<boolean> {
  if (env.ALLOW_SIGNUP) return true;
  const database = await db();
  const row = (await database
    .query("SELECT COUNT(*) AS n FROM users;")
    .get()) as { n: number } | null;
  return (row?.n ?? 0) === 0;
}

// users.telegram_user_id is a legacy NOT NULL UNIQUE column (see migration
// 0014); new accounts get a random negative placeholder.
function legacyUserIdPlaceholder(): number {
  const b = crypto.getRandomValues(new Uint8Array(6));
  let n = 0;
  for (const x of b) n = n * 256 + x;
  return -(n + 1);
}

async function registrationOptionsFor(userId: string) {
  return generateRegistrationOptions({
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
}

type ParsedEnrollment = {
  credential: {
    id: string;
    publicKey: Uint8Array;
    counter: number;
    transports?: string[];
  };
  publicKey: Uint8Array;
  wrappedPrivateKey: Uint8Array;
};

async function verifyEnrollment(params: {
  body: z.infer<typeof SignupVerifySchema>;
  expectedChallenge: string;
}): Promise<
  { ok: true; value: ParsedEnrollment } | { ok: false; error: string }
> {
  let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
  try {
    verification = await verifyRegistrationResponse({
      response: params.body.registration as unknown as RegistrationResponseJSON,
      expectedChallenge: params.expectedChallenge,
      expectedOrigin: expectedOrigin(),
      expectedRPID: expectedRpId(),
      requireUserVerification: true,
    });
  } catch {
    return { ok: false, error: "registration_failed" };
  }
  if (!verification.verified)
    return { ok: false, error: "registration_failed" };

  const publicKey = fromBase64Url(params.body.public_key);
  const wrappedPrivateKey = fromBase64Url(params.body.wrapped_private_key);
  if (publicKey.byteLength !== 65 || publicKey[0] !== 4) {
    return { ok: false, error: "invalid_public_key" };
  }
  if (wrappedPrivateKey.byteLength < 64) {
    return { ok: false, error: "invalid_wrapped_private_key" };
  }
  return {
    ok: true,
    value: {
      credential: verification.registrationInfo.credential,
      publicKey,
      wrappedPrivateKey,
    },
  };
}

async function savePasskey(params: {
  userId: string;
  enrollment: ParsedEnrollment;
  prfSalt: string;
}): Promise<void> {
  const database = await db();
  const now = nowIso();
  const cred = params.enrollment.credential;
  await database
    .query(
      "INSERT INTO user_passkeys (user_id, credential_id, public_key, sign_count, transports, prf_salt, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) " +
        "ON CONFLICT(user_id) DO UPDATE SET credential_id = excluded.credential_id, public_key = excluded.public_key, sign_count = excluded.sign_count, transports = excluded.transports, prf_salt = excluded.prf_salt, created_at = excluded.created_at;"
    )
    .run(
      params.userId,
      cred.id,
      cred.publicKey,
      cred.counter,
      cred.transports ? JSON.stringify(cred.transports) : null,
      params.prfSalt,
      now
    );
  await database
    .query(
      "INSERT INTO user_keys (user_id, public_key, wrapped_private_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?) " +
        "ON CONFLICT(user_id) DO UPDATE SET public_key = excluded.public_key, wrapped_private_key = excluded.wrapped_private_key, updated_at = excluded.updated_at;"
    )
    .run(
      params.userId,
      params.enrollment.publicKey,
      params.enrollment.wrappedPrivateKey,
      now,
      now
    );
}

function prfSaltFrom(optionsJson: string | null): string | null {
  return (
    (JSON.parse(optionsJson ?? "{}") as { prf_salt?: string }).prf_salt ?? null
  );
}

// Browser side of enrollment, shared by sign-up and passkey replacement:
// creates the passkey, gets its PRF output, and wraps the user's private key.
export const ENROLL_SCRIPT = `
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

  // o: options response; mode: "new" | "rewrap" | "replace_lost".
  async function createPasskeyEnrollment(o, mode, setStatus) {
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
    return {
      nonce: o.nonce,
      registration: PB.registrationToJSON(cred),
      public_key: PB.b64u(publicKeyRaw),
      wrapped_private_key: PB.b64u(wrapped),
    };
  }
`;

// Browser side of sign-in: usernameless assertion with a discoverable passkey.
export const SIGNIN_SCRIPT = `
  async function signInWithPasskey() {
    var o = await postJson("/passkey/signin/options", {});
    var a = await navigator.credentials.get({ publicKey: {
      challenge: PB.unb64u(o.challenge),
      rpId: o.rp_id,
      userVerification: "required",
    }});
    return postJson("/passkey/signin/verify", { nonce: o.nonce, assertion: PB.assertionToJSON(a) });
  }
`;

export const passkeyRouter = new Hono();

// --- Sign-up: creates the account and its passkey in one step. ---

passkeyRouter.post("/signup/options", requireSameOrigin, async (c) => {
  if (!(await isSignupAllowed())) {
    return c.json(
      { error: "signup_closed", message: "Sign-up is closed." },
      403
    );
  }
  const userId = ulid();
  const registrationOptions = await registrationOptionsFor(userId);
  const prfSalt = randomBase64Url(32);
  const { nonce } = await storeAuthChallenge({
    purpose: "signup",
    userId,
    challenge: registrationOptions.challenge,
    options: { prf_salt: prfSalt },
  });
  return c.json({
    nonce,
    user_id: userId,
    prf_salt: prfSalt,
    registration_options: registrationOptions,
    existing: null,
  });
});

passkeyRouter.post("/signup/verify", requireSameOrigin, async (c) => {
  const parsed = SignupVerifySchema.safeParse(
    await c.req.json().catch(() => null)
  );
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);

  const challenge = await consumeAuthChallenge({
    nonce: parsed.data.nonce,
    purpose: "signup",
  });
  const prfSalt = prfSaltFrom(challenge?.options_json ?? null);
  if (!challenge?.user_id || !prfSalt) {
    return c.json({ error: "invalid_challenge" }, 400);
  }
  // Re-check: sign-up may have closed since the options were issued.
  if (!(await isSignupAllowed())) {
    return c.json(
      { error: "signup_closed", message: "Sign-up is closed." },
      403
    );
  }

  const verified = await verifyEnrollment({
    body: parsed.data,
    expectedChallenge: challenge.challenge,
  });
  if (!verified.ok) return c.json({ error: verified.error }, 400);

  const userId = challenge.user_id;
  const database = await db();
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, 'active');"
    )
    .run(userId, legacyUserIdPlaceholder(), nowIso());
  await savePasskey({ userId, enrollment: verified.value, prfSalt });

  await auditEvent({
    userId,
    actorType: "passkey",
    actorId: verified.value.credential.id,
    eventType: "user_created",
    event: {},
  });

  await createWebSession({ c, userId });
  return c.json({ ok: true, message: "Account created." });
});

// --- Sign-in ---

passkeyRouter.post("/signin/options", requireSameOrigin, async (c) => {
  const options = await generateAuthenticationOptions({
    rpID: expectedRpId(),
    userVerification: "required",
  });
  const { nonce } = await storeAuthChallenge({
    purpose: "signin",
    challenge: options.challenge,
  });
  return c.json({ nonce, challenge: options.challenge, rp_id: expectedRpId() });
});

passkeyRouter.post("/signin/verify", requireSameOrigin, async (c) => {
  const parsed = SigninVerifySchema.safeParse(
    await c.req.json().catch(() => null)
  );
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);

  const challenge = await consumeAuthChallenge({
    nonce: parsed.data.nonce,
    purpose: "signin",
  });
  if (!challenge) return c.json({ error: "invalid_challenge" }, 400);

  const assertion = parsed.data
    .assertion as unknown as AuthenticationResponseJSON;
  const userId =
    typeof assertion.id === "string"
      ? await userIdForCredential(assertion.id)
      : null;
  if (
    !userId ||
    !(await verifyPasskeyAssertion({
      userId,
      response: assertion,
      expectedChallenge: challenge.challenge,
    }))
  ) {
    return c.json(
      {
        error: "signin_failed",
        message: "This passkey isn't registered with the broker.",
      },
      403
    );
  }

  await createWebSession({ c, userId });
  await auditEvent({
    userId,
    actorType: "passkey",
    actorId: assertion.id,
    eventType: "signed_in",
    event: {},
  });
  return c.json({ ok: true });
});

passkeyRouter.post("/signout", requireSameOrigin, async (c) => {
  await endWebSession(c);
  return c.redirect("/app/signin", 303);
});

// --- Replace the passkey of a signed-in user. ---

passkeyRouter.get("/enroll", requireSessionPage, async (c) => {
  const body = `
    <h1>Replace passkey</h1>
    <p>Your connected accounts are encrypted with a key that only your passkey can unlock. Every approval needs Face ID / Touch ID.</p>
    <p class="note">Save the passkey in your device's password manager (e.g. Apple Passwords). It must support the passkey PRF extension.</p>
    <button id="rewrap" type="button">Replace passkey (I still have my current one)</button>
    <button id="replace_lost" type="button">I lost my passkey — start over</button>
    <p class="note">Starting over disconnects every linked account; you will need to reconnect them.</p>
    <p id="status"></p>`;

  const script = `
    ${POST_JSON_SCRIPT}
    ${ENROLL_SCRIPT}
    var statusEl = document.getElementById("status");
    function setStatus(text, cls) { statusEl.textContent = text; statusEl.className = cls || ""; }

    async function replace(mode) {
      if (mode === "replace_lost" && !confirm("This disconnects all linked accounts. Continue?")) return;
      setStatus("Preparing…");
      var o = await postJson("/passkey/enroll/options", {});
      var enrollment = await createPasskeyEnrollment(o, mode, setStatus);
      enrollment.mode = mode;
      setStatus("Saving…");
      var r = await postJson("/passkey/enroll/verify", enrollment);
      setStatus(r.message, "ok");
      document.querySelectorAll("button").forEach(function (b) { b.disabled = true; });
    }

    ["rewrap", "replace_lost"].forEach(function (mode) {
      document.getElementById(mode).onclick = function () {
        replace(mode).catch(function (e) { setStatus("Failed: " + errorText(e), "error"); });
      };
    });
  `;

  return sendPage(c, {
    title: "Replace passkey",
    body,
    script,
    crypto: true,
    nav: "/app/settings",
  });
});

passkeyRouter.post("/enroll/options", requireSessionJson, async (c) => {
  const { userId } = c.get("webSession");
  const registrationOptions = await registrationOptionsFor(userId);
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

passkeyRouter.post("/enroll/verify", requireSessionJson, async (c) => {
  const { userId } = c.get("webSession");
  const parsed = ReplaceVerifySchema.safeParse(
    await c.req.json().catch(() => null)
  );
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);
  const body = parsed.data;

  const challenge = await consumeChallenge({
    nonce: body.nonce,
    userId,
    purpose: "enroll",
  });
  const prfSalt = prfSaltFrom(challenge?.options_json ?? null);
  if (!challenge || !prfSalt) {
    return c.json({ error: "invalid_challenge" }, 400);
  }

  const verified = await verifyEnrollment({
    body,
    expectedChallenge: challenge.challenge,
  });
  if (!verified.ok) return c.json({ error: verified.error }, 400);

  return finishReplacement(c, {
    userId,
    mode: body.mode,
    enrollment: verified.value,
    prfSalt,
  });
});

async function finishReplacement(
  c: Context,
  params: {
    userId: string;
    mode: EnrollMode;
    enrollment: ParsedEnrollment;
    prfSalt: string;
  }
): Promise<Response> {
  const existingPublicKey = await getUserPublicKey(params.userId);
  if (!existingPublicKey) {
    return c.json(
      { error: "invalid_mode", message: "no passkey to replace" },
      400
    );
  }
  if (
    params.mode === "rewrap" &&
    !bytesEqual(existingPublicKey, params.enrollment.publicKey)
  ) {
    return c.json(
      { error: "invalid_mode", message: "re-wrap must keep the same key" },
      400
    );
  }

  let revoked = 0;
  if (params.mode === "replace_lost") {
    revoked = await revokeUndecryptableCredentials(params.userId);
  }
  await savePasskey({
    userId: params.userId,
    enrollment: params.enrollment,
    prfSalt: params.prfSalt,
  });
  const migration = await migrateLegacyCredentials(params.userId);

  await auditEvent({
    userId: params.userId,
    actorType: "system",
    actorId: "passkey_enroll",
    eventType: "passkey_enrolled",
    event: {
      mode: params.mode,
      credential_id: params.enrollment.credential.id,
      migrated: migration.migrated,
      migration_failed: migration.failed,
      revoked,
    },
  });

  const parts = ["Passkey saved."];
  if (migration.migrated) {
    parts.push(
      `Re-encrypted ${migration.migrated} linked account(s) to your passkey.`
    );
  }
  if (migration.failed) {
    parts.push(
      `${migration.failed} account(s) could not be migrated and were disconnected.`
    );
  }
  if (revoked) {
    parts.push(
      `${revoked} account(s) were disconnected; reconnect them under Accounts.`
    );
  }
  return c.json({ ok: true, message: parts.join(" ") });
}
