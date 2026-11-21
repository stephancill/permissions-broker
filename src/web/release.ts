import { type Context, Hono } from "hono";
import { z } from "zod";

import {
  type AppleReleaseCredential,
  ASC_API_ORIGIN,
  createAscJwt,
  parseAppleReleaseCredential,
} from "../apple/credential";
import {
  SigningRequestError,
  signAttributes,
  validateSigningRequest,
} from "../apple/signing";
import { auditEvent } from "../audit/audit";
import {
  CredentialError,
  deleteGrantsForTarget,
  findGrantId,
  getActiveLinkedAccount,
  unlockCredential,
} from "../credentials/store";
import { decryptUtf8 } from "../crypto/aesgcm";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import { approvalPath, expectedOrigin } from "../passkey/webauthn";
import { notifyUser } from "../push/notify";
import {
  authorizeAscRequest,
  learnFromResponse,
} from "../release/ascAllowlist";
import {
  type GithubOidcClaims,
  OidcError,
  splitWorkflowRef,
  verifyGithubOidcToken,
} from "../release/oidc";
import {
  cachedAscJwt,
  createReleaseSession,
  findActivePolicy,
  getReleaseSession,
  RELEASE_APPROVAL_TTL_MS,
  type ReleaseSessionRow,
  recordSignedBundle,
  saveLearnedScope,
  sessionScope,
  setReleaseSessionStatus,
  storeAscJwt,
  takeSessionSecretCiphertext,
  touchReleaseSession,
} from "../release/store";

export const APPLE_RELEASE_PROVIDER = "apple-release";

const MAX_ASC_REQUEST_BYTES = 64 * 1024;
const MAX_ASC_RESPONSE_BYTES = 8 * 1024 * 1024;
const MAX_SIGN_FIELD_BYTES = 256 * 1024;
const JWT_REFRESH_MARGIN_MS = 2 * 60_000;

const BUNDLE_ID = /^[A-Za-z0-9.-]{1,155}$/;

const CreateSchema = z.object({
  bundle_ids: z.array(z.string().regex(BUNDLE_ID)).min(1).max(10),
  version: z.string().min(1).max(32),
  build_number: z.string().min(1).max(32),
});

const SignSchema = z.object({
  codeDirectory: z.string().min(1).max(MAX_SIGN_FIELD_BYTES),
  signedAttributes: z.string().min(1).max(MAX_SIGN_FIELD_BYTES),
});

function fromBase64(s: string): Uint8Array | null {
  try {
    const raw = atob(s);
    const out = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

async function oidcClaims(
  c: Context
): Promise<
  { ok: true; claims: GithubOidcClaims } | { ok: false; res: Response }
> {
  const header = c.req.header("authorization") ?? "";
  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : "";
  if (!token) return { ok: false, res: c.json({ error: "unauthorized" }, 401) };
  try {
    const claims = await verifyGithubOidcToken({
      token,
      audience: expectedOrigin(),
    });
    return { ok: true, claims };
  } catch (err) {
    if (err instanceof OidcError) {
      return {
        ok: false,
        res: c.json({ error: "invalid_oidc_token", message: err.message }, 401),
      };
    }
    throw err;
  }
}

function sessionBaseUrl(params: { id: string; secret: string }): string {
  return `${expectedOrigin()}/v1/release/session/${params.id}/${params.secret}`;
}

export const releaseRouter = new Hono();

// A workflow run asks to release. Its OIDC identity must match an active policy.
releaseRouter.post("/sessions", async (c) => {
  const auth = await oidcClaims(c);
  if (!auth.ok) return auth.res;
  const { claims } = auth;

  const parsed = CreateSchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);

  const workflow = splitWorkflowRef(claims.workflow_ref, claims.repository);
  if (!workflow || workflow.ref !== claims.ref) {
    return c.json(
      { error: "invalid_oidc_token", message: "unexpected workflow_ref" },
      401
    );
  }
  const policy = await findActivePolicy({
    repository: claims.repository,
    workflowPath: workflow.path,
    ref: claims.ref,
  });
  if (!policy) {
    return c.json(
      {
        error: "no_release_policy",
        message: `No release policy allows ${claims.repository} ${workflow.path} on ${claims.ref}. Add one under Accounts → apple-release → Release policies in the app.`,
      },
      403
    );
  }
  const allowed = JSON.parse(policy.bundle_ids_json) as string[];
  const bundleIds = [...new Set(parsed.data.bundle_ids)];
  const notAllowed = bundleIds.filter((b) => !allowed.includes(b));
  if (notAllowed.length > 0) {
    return c.json(
      {
        error: "bundle_not_allowed",
        message: `The policy does not allow ${notAllowed.join(", ")}.`,
      },
      403
    );
  }

  const account = await getActiveLinkedAccount({
    userId: policy.user_id,
    provider: APPLE_RELEASE_PROVIDER,
  });
  if (!account) {
    return c.json(
      {
        error: "no_linked_apple_release",
        message: "Link an Apple release credential in the app first.",
      },
      409
    );
  }

  const created = await createReleaseSession({
    userId: policy.user_id,
    policyId: policy.id,
    repository: claims.repository,
    workflowRef: claims.workflow_ref,
    ref: claims.ref,
    sha: claims.sha,
    runId: claims.run_id,
    runAttempt: claims.run_attempt,
    actor: claims.actor,
    bundleIds,
    version: parsed.data.version,
    buildNumber: parsed.data.build_number,
  });

  await auditEvent({
    userId: policy.user_id,
    actorType: "github_oidc",
    actorId: `${claims.repository}#${claims.run_id}`,
    eventType: "release_session_created",
    event: {
      session_id: created.sessionId,
      sha: claims.sha,
      bundle_ids: bundleIds,
      version: parsed.data.version,
      build_number: parsed.data.build_number,
    },
  });

  await notifyUser({
    userId: policy.user_id,
    notification: {
      title: `Release ${bundleIds[0]} ${parsed.data.version} (${parsed.data.build_number})`,
      body: `${claims.repository} @ ${claims.sha.slice(0, 7)} by ${claims.actor} wants to sign and upload to TestFlight.`,
      url: approvalPath({ kind: "release", id: created.sessionId }),
      tag: `release:${created.sessionId}`,
    },
    ttlSeconds: Math.floor(RELEASE_APPROVAL_TTL_MS / 1000),
    urgency: "high",
  });

  return c.json({
    session_id: created.sessionId,
    status: "PENDING_APPROVAL",
    approval_expires_at: created.approvalExpiresAt,
  });
});

// The same run polls; once approved the session URL is returned exactly once.
releaseRouter.get("/sessions/:id", async (c) => {
  const auth = await oidcClaims(c);
  if (!auth.ok) return auth.res;
  const session = await getReleaseSession(c.req.param("id"));
  if (
    !session ||
    session.repository !== auth.claims.repository ||
    session.run_id !== auth.claims.run_id ||
    session.workflow_ref !== auth.claims.workflow_ref
  ) {
    return c.json({ error: "not_found" }, 404);
  }

  if (
    session.status === "PENDING_APPROVAL" &&
    Date.parse(session.approval_expires_at) < Date.now()
  ) {
    await setReleaseSessionStatus({
      id: session.id,
      from: ["PENDING_APPROVAL"],
      status: "EXPIRED",
    });
    return c.json({ session_id: session.id, status: "EXPIRED" });
  }

  if (session.status === "APPROVED" && !session.secret_delivered_at) {
    const ciphertext = await takeSessionSecretCiphertext(session.id);
    if (ciphertext) {
      const secret = await decryptUtf8(ciphertext);
      return c.json({
        session_id: session.id,
        status: session.status,
        expires_at: session.expires_at,
        session_url: sessionBaseUrl({ id: session.id, secret }),
      });
    }
  }
  return c.json({
    session_id: session.id,
    status: session.status,
    approval_expires_at: session.approval_expires_at,
    expires_at: session.expires_at,
  });
});

type Loaded = { session: ReleaseSessionRow };

async function loadBySecret(
  c: Context
): Promise<{ ok: true; value: Loaded } | { ok: false; res: Response }> {
  const session = await getReleaseSession(c.req.param("id") ?? "");
  const secret = c.req.param("secret") ?? "";
  if (!session || (await sha256Hex(secret)) !== session.session_secret_hash) {
    return { ok: false, res: c.json({ error: "not_found" }, 404) };
  }
  if (session.status !== "APPROVED" && session.status !== "ACTIVE") {
    return {
      ok: false,
      res: c.json({ error: "session_closed", status: session.status }, 410),
    };
  }
  if (session.expires_at && Date.parse(session.expires_at) < Date.now()) {
    await setReleaseSessionStatus({
      id: session.id,
      from: ["APPROVED", "ACTIVE"],
      status: "CLOSED",
    });
    return {
      ok: false,
      res: c.json({ error: "session_closed", status: "CLOSED" }, 410),
    };
  }
  await touchReleaseSession(session.id);
  return { ok: true, value: { session } };
}

async function unlockAppleCredential(
  c: Context,
  session: ReleaseSessionRow
): Promise<
  | { ok: true; credential: AppleReleaseCredential }
  | { ok: false; res: Response }
> {
  try {
    const unlocked = await unlockCredential({
      grantId: await findGrantId({
        targetKind: "release",
        targetId: session.id,
      }),
      userId: session.user_id,
    });
    const credential = parseAppleReleaseCredential(unlocked.plaintext);
    if (!credential) {
      return {
        ok: false,
        res: c.json({ error: "invalid_apple_release_credential" }, 500),
      };
    }
    return { ok: true, credential };
  } catch (err) {
    if (err instanceof CredentialError) {
      return {
        ok: false,
        res: c.json(
          {
            error: "credential_unavailable",
            code: err.code,
            message: err.message,
          },
          409
        ),
      };
    }
    throw err;
  }
}

// Team and certificate from the credential's display metadata (no decrypt).
async function accountMetadata(session: ReleaseSessionRow): Promise<{
  teamId: string;
  distributionCertificateId: string;
} | null> {
  const database = await db();
  const row = (await database
    .query(
      "SELECT metadata_json FROM linked_accounts WHERE user_id = ? AND provider = ? AND status = 'active' LIMIT 1;"
    )
    .get(session.user_id, APPLE_RELEASE_PROVIDER)) as {
    metadata_json: string | null;
  } | null;
  try {
    const m = JSON.parse(row?.metadata_json ?? "null") as {
      apple_release?: Record<string, unknown>;
    } | null;
    const a = m?.apple_release;
    if (
      typeof a?.teamId === "string" &&
      typeof a.distributionCertificateId === "string"
    ) {
      return {
        teamId: a.teamId,
        distributionCertificateId: a.distributionCertificateId,
      };
    }
  } catch {
    // fall through
  }
  return null;
}

releaseRouter.get("/session/:id/:secret/info", async (c) => {
  const loaded = await loadBySecret(c);
  if (!loaded.ok) return loaded.res;
  const { session } = loaded.value;
  const meta = await accountMetadata(session);
  if (!meta) return c.json({ error: "no_linked_apple_release" }, 409);
  return c.json({
    teamId: meta.teamId,
    distributionCertificateId: meta.distributionCertificateId,
    bundleIds: JSON.parse(session.bundle_ids_json),
  });
});

async function ascJwt(
  c: Context,
  session: ReleaseSessionRow
): Promise<{ ok: true; token: string } | { ok: false; res: Response }> {
  const cached = await cachedAscJwt({ id: session.id });
  if (
    cached &&
    Date.parse(cached.expiresAt) - JWT_REFRESH_MARGIN_MS > Date.now()
  ) {
    return { ok: true, token: await decryptUtf8(cached.ciphertext) };
  }
  const unlocked = await unlockAppleCredential(c, session);
  if (!unlocked.ok) return unlocked;
  const jwt = await createAscJwt({ credential: unlocked.credential });
  await storeAscJwt({
    id: session.id,
    token: jwt.token,
    expiresAt: new Date(jwt.expiresAt * 1000).toISOString(),
  });
  return { ok: true, token: jwt.token };
}

releaseRouter.all("/session/:id/:secret/asc/v1/*", async (c) => {
  const loaded = await loadBySecret(c);
  if (!loaded.ok) return loaded.res;
  const { session } = loaded.value;
  const meta = await accountMetadata(session);
  if (!meta) return c.json({ error: "no_linked_apple_release" }, 409);

  const url = new URL(c.req.url);
  const marker = "/asc/v1/";
  const path = url.pathname.slice(url.pathname.indexOf(marker) + marker.length);
  const method = c.req.method.toUpperCase();

  let bodyText: string | null = null;
  let body: unknown = null;
  if (method === "POST" || method === "PATCH") {
    bodyText = await c.req.text();
    if (bodyText.length > MAX_ASC_REQUEST_BYTES) {
      return c.json({ error: "request_too_large" }, 413);
    }
    try {
      body = JSON.parse(bodyText);
    } catch {
      return c.json({ error: "invalid_request" }, 400);
    }
  }

  const scope = sessionScope({
    session,
    certificateId: meta.distributionCertificateId,
  });
  const decision = authorizeAscRequest({
    method,
    path,
    search: url.searchParams,
    body,
    scope,
  });
  if (!decision.ok) {
    await auditEvent({
      userId: session.user_id,
      actorType: "release_session",
      actorId: session.id,
      eventType: "release_asc_refused",
      event: { method, path, reason: decision.reason },
    });
    return c.json(
      {
        errors: [
          {
            status: "403",
            code: "FORBIDDEN_BY_BROKER",
            detail: decision.reason,
          },
        ],
      },
      403
    );
  }

  const jwt = await ascJwt(c, session);
  if (!jwt.ok) return jwt.res;

  const upstream = await fetch(`${ASC_API_ORIGIN}/v1/${path}${url.search}`, {
    method,
    headers: {
      Authorization: `Bearer ${jwt.token}`,
      Accept: "application/json",
      ...(bodyText !== null ? { "Content-Type": "application/json" } : {}),
    },
    body: bodyText ?? undefined,
  });
  const responseBytes = new Uint8Array(await upstream.arrayBuffer());
  if (responseBytes.length > MAX_ASC_RESPONSE_BYTES) {
    return c.json({ error: "response_too_large" }, 502);
  }

  if (upstream.ok && decision.learn) {
    let parsedResponse: unknown = null;
    try {
      parsedResponse = JSON.parse(new TextDecoder().decode(responseBytes));
    } catch {
      parsedResponse = null;
    }
    const learned = learnFromResponse({
      learn: decision.learn,
      body: parsedResponse,
      scope,
    });
    await saveLearnedScope({ id: session.id, learned });
  }

  return new Response(responseBytes, {
    status: upstream.status,
    headers: {
      "Content-Type":
        upstream.headers.get("content-type") ?? "application/json",
    },
  });
});

releaseRouter.post("/session/:id/:secret/sign", async (c) => {
  const loaded = await loadBySecret(c);
  if (!loaded.ok) return loaded.res;
  const { session } = loaded.value;
  const meta = await accountMetadata(session);
  if (!meta) return c.json({ error: "no_linked_apple_release" }, 409);

  const parsed = SignSchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);
  const codeDirectory = fromBase64(parsed.data.codeDirectory);
  const signedAttributes = fromBase64(parsed.data.signedAttributes);
  if (!codeDirectory || !signedAttributes) {
    return c.json({ error: "invalid_request" }, 400);
  }

  let validated: { bundleId: string; cdhash: string };
  try {
    validated = await validateSigningRequest({
      codeDirectory,
      signedAttributes,
      teamId: meta.teamId,
      approvedBundleIds: JSON.parse(session.bundle_ids_json) as string[],
    });
  } catch (err) {
    if (err instanceof SigningRequestError) {
      await auditEvent({
        userId: session.user_id,
        actorType: "release_session",
        actorId: session.id,
        eventType: "release_sign_refused",
        event: { reason: err.message },
      });
      return c.json({ error: "signing_refused", message: err.message }, 403);
    }
    throw err;
  }

  if (!(await recordSignedBundle({ session, bundleId: validated.bundleId }))) {
    return c.json(
      {
        error: "signing_refused",
        message: `${validated.bundleId} was already signed in this session`,
      },
      403
    );
  }

  const unlocked = await unlockAppleCredential(c, session);
  if (!unlocked.ok) return unlocked.res;
  const signature = await signAttributes({
    distributionKeyPem: unlocked.credential.distributionKeyPem,
    signedAttributes,
  });

  await auditEvent({
    userId: session.user_id,
    actorType: "release_session",
    actorId: session.id,
    eventType: "release_signed",
    event: { bundle_id: validated.bundleId, cdhash: validated.cdhash },
  });
  return c.json({ signature: toBase64(signature) });
});

releaseRouter.delete("/session/:id/:secret", async (c) => {
  const loaded = await loadBySecret(c);
  if (!loaded.ok) return loaded.res;
  await setReleaseSessionStatus({
    id: loaded.value.session.id,
    from: ["APPROVED", "ACTIVE"],
    status: "CLOSED",
  });
  await deleteGrantsForTarget({
    targetKind: "release",
    targetId: loaded.value.session.id,
  });
  return c.json({ ok: true });
});
