import { afterAll, expect, test } from "bun:test";
import { Hono } from "hono";
import { ulid } from "ulid";

import {
  checkSignedAttributes,
  validateSigningRequest,
} from "../src/apple/signing";
import { createGrant, saveLinkedCredential } from "../src/credentials/store";
import { bufferSource, toBase64Url } from "../src/crypto/bytes";
import { db } from "../src/db/client";
import { migrate } from "../src/db/migrate";
import { configureEnv, env } from "../src/env";
import { CLIENT_CRYPTO_JS } from "../src/passkey/clientCrypto";
import {
  authorizeAscRequest,
  learnFromResponse,
  type SessionScope,
} from "../src/release/ascAllowlist";
import { setJwksForTests, verifyGithubOidcToken } from "../src/release/oidc";
import {
  activateReleasePolicy,
  createReleasePolicy,
  setReleaseSessionStatus,
} from "../src/release/store";
import { releaseRouter } from "../src/web/release";

await migrate();
configureEnv({
  ...env,
  APP_SECRET: "test-app-secret",
  APP_BASE_URL: "https://broker.example",
});

const BASE = "https://broker.example";
const TEAM = "TEAMID1234";
const BUNDLE = "net.example.app";
const EXTENSION = "net.example.app.NotificationService";

// --- DER helpers for building what stupid-app sends ---

function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}
function der(tag: number, content: Uint8Array): Uint8Array {
  return new Uint8Array([tag, ...derLength(content.length), ...content]);
}
function cat(...parts: Uint8Array[]): Uint8Array {
  return new Uint8Array(parts.flatMap((p) => [...p]));
}
function oid(dotted: string): Uint8Array {
  const parts = dotted.split(".").map(Number);
  const out = [parts[0] * 40 + parts[1]];
  for (const p of parts.slice(2)) {
    const stack = [p & 0x7f];
    let v = p >> 7;
    while (v > 0) {
      stack.unshift((v & 0x7f) | 0x80);
      v >>= 7;
    }
    out.push(...stack);
  }
  return der(0x06, new Uint8Array(out));
}
function compare(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}
function attribute(oidString: string, value: Uint8Array): Uint8Array {
  return der(0x30, cat(oid(oidString), der(0x31, value)));
}
function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

// A CodeDirectory shaped like stupid-app's (version 0x20400, SHA-256).
function codeDirectory(identifier: string, teamId: string): Uint8Array {
  const ident = new TextEncoder().encode(`${identifier}\0`);
  const team = new TextEncoder().encode(`${teamId}\0`);
  const header = new Uint8Array(88);
  const view = new DataView(header.buffer);
  const length = 88 + ident.length + team.length + 32;
  view.setUint32(0, 0xfade0c02);
  view.setUint32(4, length);
  view.setUint32(8, 0x20400);
  view.setUint32(16, 88 + ident.length + team.length);
  view.setUint32(20, 88);
  view.setUint32(28, 1);
  header[36] = 32;
  header[37] = 2;
  header[39] = 12;
  view.setUint32(48, 88 + ident.length);
  return cat(header, ident, team, crypto.getRandomValues(new Uint8Array(32)));
}

async function signedAttributes(
  cd: Uint8Array,
  extra?: Uint8Array
): Promise<Uint8Array> {
  const digest = new Uint8Array(
    await crypto.subtle.digest("SHA-256", bufferSource(cd))
  );
  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
\t<key>cdhashes</key>
\t<array>
\t\t<data>
\t\t${b64(digest.subarray(0, 20))}
\t\t</data>
\t</array>
</dict>
</plist>
`;
  const values = [
    attribute("1.2.840.113549.1.9.3", oid("1.2.840.113549.1.7.1")),
    attribute("1.2.840.113549.1.9.4", der(0x04, digest)),
    attribute(
      "1.2.840.113635.100.9.1",
      der(0x04, new TextEncoder().encode(plist))
    ),
    attribute(
      "1.2.840.113635.100.9.2",
      der(0x30, cat(oid("2.16.840.1.101.3.4.2.1"), der(0x04, digest)))
    ),
    ...(extra ? [extra] : []),
  ].sort(compare);
  return der(0x31, cat(...values));
}

// --- Allowlist ---

const scope: SessionScope = {
  bundleIds: [BUNDLE, EXTENSION],
  certificateId: "CERT123",
  appIds: ["APP1"],
  bundleResourceIds: ["BID1"],
  buildIds: ["BUILD1"],
  buildUploadIds: ["UP1"],
  buildUploadFileIds: ["FILE1"],
};

function decide(method: string, pathAndQuery: string, body: unknown = null) {
  const [path, query = ""] = pathAndQuery.split("?");
  return authorizeAscRequest({
    method,
    path,
    search: new URLSearchParams(query),
    body,
    scope,
  });
}

test("allowlist permits the requests a release makes for approved resources", () => {
  for (const [method, path, body] of [
    ["GET", `apps?filter[bundleId]=${BUNDLE}`],
    ["GET", `bundleIds?filter[identifier]=${EXTENSION}`],
    [
      "GET",
      "bundleIds/BID1/profiles?fields[profiles]=name,profileContent&limit=200",
    ],
    ["GET", "certificates/CERT123"],
    [
      "GET",
      "builds?filter[app]=APP1&filter[version]=12&include=preReleaseVersion&limit=200",
    ],
    ["GET", "builds?filter[app]=APP1&sort=-uploadedDate&limit=1"],
    ["GET", "builds/BUILD1"],
    ["GET", "builds/BUILD1/buildBetaDetail"],
    ["GET", "buildUploads/UP1"],
    [
      "POST",
      "buildUploads",
      { data: { relationships: { app: { data: { id: "APP1" } } } } },
    ],
    [
      "POST",
      "buildUploadFiles",
      { data: { relationships: { buildUpload: { data: { id: "UP1" } } } } },
    ],
    ["PATCH", "buildUploadFiles/FILE1", { data: {} }],
  ] as const) {
    expect(decide(method, path, body ?? null).ok).toBe(true);
  }
});

test("allowlist refuses other apps, other resources and everything else", () => {
  for (const [method, path, body] of [
    ["GET", "apps?filter[bundleId]=net.other.app"],
    ["GET", `apps?filter[bundleId]=${BUNDLE},net.other.app`],
    ["GET", "apps"],
    ["GET", "builds?filter[app]=APP2"],
    ["GET", "builds/BUILD2"],
    ["GET", "bundleIds/BID2/profiles"],
    ["GET", "certificates/OTHER"],
    ["GET", "certificates"],
    ["GET", "profiles"],
    ["GET", "devices"],
    ["GET", "buildUploads/UP2"],
    ["POST", "certificates", { data: {} }],
    ["POST", "profiles", { data: {} }],
    [
      "POST",
      "buildUploads",
      { data: { relationships: { app: { data: { id: "APP2" } } } } },
    ],
    [
      "POST",
      "buildUploadFiles",
      { data: { relationships: { buildUpload: { data: { id: "UP2" } } } } },
    ],
    ["PATCH", "buildUploadFiles/FILE2", { data: {} }],
    ["DELETE", "profiles/P1"],
    ["PATCH", "apps/APP1", { data: {} }],
    ["POST", "betaAppReviewSubmissions", { data: {} }],
    ["GET", "builds/BUILD1/../../devices"],
    ["GET", "apps?filter[bundleId]=net.example.app&filter[name]=x"],
  ] as const) {
    expect(decide(method, path, body ?? null).ok).toBe(false);
  }
});

test("responses teach the session only its approved resources", () => {
  const learned = learnFromResponse({
    learn: "apps",
    body: {
      data: [
        { id: "APP9", attributes: { bundleId: BUNDLE } },
        { id: "APP8", attributes: { bundleId: "net.other.app" } },
      ],
    },
    scope: { ...scope, appIds: [] },
  });
  expect(learned.appIds).toEqual(["APP9"]);
});

// --- Signing request checks ---

test("a CodeDirectory for an approved bundle with matching attributes is accepted", async () => {
  const cd = codeDirectory(BUNDLE, TEAM);
  const result = await validateSigningRequest({
    codeDirectory: cd,
    signedAttributes: await signedAttributes(cd),
    teamId: TEAM,
    approvedBundleIds: [BUNDLE],
  });
  expect(result.bundleId).toBe(BUNDLE);
  expect(result.cdhash).toHaveLength(40);
});

test("signing requests for other bundles, teams or digests are refused", async () => {
  const cd = codeDirectory(BUNDLE, TEAM);
  const other = codeDirectory("net.other.app", TEAM);
  const otherTeam = codeDirectory(BUNDLE, "OTHERTEAM1");
  const cases: Array<[Uint8Array, Uint8Array]> = [
    [other, await signedAttributes(other)],
    [otherTeam, await signedAttributes(otherTeam)],
    // Attributes for a different CodeDirectory.
    [cd, await signedAttributes(codeDirectory(BUNDLE, TEAM))],
    // An extra attribute (a signing time).
    [
      cd,
      await signedAttributes(
        cd,
        attribute(
          "1.2.840.113549.1.9.5",
          der(0x17, new TextEncoder().encode("261121000000Z"))
        )
      ),
    ],
  ];
  for (const [codeDir, attrs] of cases) {
    await expect(
      validateSigningRequest({
        codeDirectory: codeDir,
        signedAttributes: attrs,
        teamId: TEAM,
        approvedBundleIds: [BUNDLE],
      })
    ).rejects.toThrow();
  }
  // Arbitrary bytes are never signable.
  expect(() =>
    checkSignedAttributes({
      signedAttributes: new TextEncoder().encode("hello"),
      digest: new Uint8Array(32),
    })
  ).toThrow();
});

// --- OIDC ---

const oidcKeys = (await crypto.subtle.generateKey(
  {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: "SHA-256",
  },
  true,
  ["sign", "verify"]
)) as CryptoKeyPair;
const oidcJwk = (await crypto.subtle.exportKey("jwk", oidcKeys.publicKey)) as {
  kty?: string;
  n?: string;
  e?: string;
};
setJwksForTests([{ kty: oidcJwk.kty, n: oidcJwk.n, e: oidcJwk.e, kid: "k1" }]);
afterAll(() => setJwksForTests(null));

const REPO = "owner/app";
const WORKFLOW = ".github/workflows/testflight.yml";

async function oidcToken(
  overrides: Record<string, unknown> = {}
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const enc = (v: unknown) =>
    toBase64Url(new TextEncoder().encode(JSON.stringify(v)));
  const header = enc({ alg: "RS256", kid: "k1", typ: "JWT" });
  const payload = enc({
    iss: "https://token.actions.githubusercontent.com",
    aud: BASE,
    iat: now,
    nbf: now,
    exp: now + 300,
    repository: REPO,
    repository_owner: "owner",
    workflow_ref: `${REPO}/${WORKFLOW}@refs/heads/main`,
    ref: "refs/heads/main",
    sha: "a".repeat(40),
    run_id: "1001",
    run_attempt: "1",
    actor: "octocat",
    event_name: "workflow_dispatch",
    ...overrides,
  });
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      oidcKeys.privateKey,
      new TextEncoder().encode(`${header}.${payload}`)
    )
  );
  return `${header}.${payload}.${toBase64Url(signature)}`;
}

test("OIDC tokens are checked for signature, audience and expiry", async () => {
  const claims = await verifyGithubOidcToken({
    token: await oidcToken(),
    audience: BASE,
  });
  expect(claims.repository).toBe(REPO);
  await expect(
    verifyGithubOidcToken({
      token: await oidcToken({ aud: "https://other.example" }),
      audience: BASE,
    })
  ).rejects.toThrow("audience");
  await expect(
    verifyGithubOidcToken({
      token: await oidcToken({ exp: 1 }),
      audience: BASE,
    })
  ).rejects.toThrow("expired");
  const [h, p] = (await oidcToken()).split(".");
  const forged = `${h}.${p}.${toBase64Url(new Uint8Array(256))}`;
  await expect(
    verifyGithubOidcToken({ token: forged, audience: BASE })
  ).rejects.toThrow();
});

// --- End to end: request, approval grant, info, App Store Connect, sign, close ---

type ClientCrypto = {
  generateUserKeypair(): Promise<{
    publicKeyRaw: Uint8Array;
    privateKey: CryptoKey;
  }>;
  deriveDek(
    privateKey: CryptoKey,
    epkRaw: Uint8Array,
    linkedAccountId: string
  ): Promise<Uint8Array>;
};
new Function(CLIENT_CRYPTO_JS)();
const PB = (globalThis as unknown as { PB: ClientCrypto }).PB;

async function pkcs8Pem(key: CryptoKey): Promise<string> {
  const der = new Uint8Array(await crypto.subtle.exportKey("pkcs8", key));
  const body = Buffer.from(der)
    .toString("base64")
    .match(/.{1,64}/g)
    ?.join("\n");
  return `-----BEGIN PRIVATE KEY-----\n${body}\n-----END PRIVATE KEY-----\n`;
}

test("a release session runs from request to signature without exposing keys", async () => {
  const database = await db();
  for (const table of [
    "credential_grants",
    "release_sessions",
    "release_policies",
    "linked_accounts",
    "user_keys",
    "users",
  ]) {
    await database.exec(`DELETE FROM ${table};`);
  }
  const userId = ulid();
  const now = new Date().toISOString();
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, 'active');"
    )
    .run(userId, -Math.floor(Math.random() * 1e9), now);
  const userKey = await PB.generateUserKeypair();
  await database
    .query(
      "INSERT INTO user_keys (user_id, public_key, wrapped_private_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?);"
    )
    .run(userId, userKey.publicKeyRaw, new Uint8Array([0]), now, now);

  const ascKeys = (await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
  const distKeys = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  )) as CryptoKeyPair;
  const credential = {
    teamId: TEAM,
    ascKeyId: "KEYID12345",
    ascIssuerId: crypto.randomUUID(),
    ascKeyPem: await pkcs8Pem(ascKeys.privateKey),
    distributionKeyPem: await pkcs8Pem(distKeys.privateKey),
    distributionCertificateId: "CERT123",
  };
  const { linkedAccountId } = await saveLinkedCredential({
    userId,
    provider: "apple-release",
    providerUserId: `${TEAM}:KEYID12345`,
    scopes: "testflight_release",
    plaintext: JSON.stringify(credential),
  });

  const policyId = await createReleasePolicy({
    userId,
    repository: REPO,
    workflowPath: WORKFLOW,
    ref: "refs/heads/main",
    bundleIds: [BUNDLE, EXTENSION],
  });
  expect(await activateReleasePolicy({ id: policyId, userId })).toBe(true);

  const app = new Hono();
  app.route("/v1/release", releaseRouter);
  const call = (path: string, init: RequestInit = {}) =>
    app.request(`${BASE}${path}`, init);
  const token = await oidcToken();
  const auth = {
    Authorization: `Bearer ${token}`,
    "Content-Type": "application/json",
  };

  // A bundle outside the policy is refused; an unknown workflow too.
  expect(
    (
      await call("/v1/release/sessions", {
        method: "POST",
        headers: auth,
        body: JSON.stringify({
          bundle_ids: ["net.other.app"],
          version: "1.0",
          build_number: "7",
        }),
      })
    ).status
  ).toBe(403);
  const otherWorkflow = await oidcToken({
    workflow_ref: `${REPO}/.github/workflows/other.yml@refs/heads/main`,
  });
  expect(
    (
      await call("/v1/release/sessions", {
        method: "POST",
        headers: { ...auth, Authorization: `Bearer ${otherWorkflow}` },
        body: JSON.stringify({
          bundle_ids: [BUNDLE],
          version: "1.0",
          build_number: "7",
        }),
      })
    ).status
  ).toBe(403);

  const created = await call("/v1/release/sessions", {
    method: "POST",
    headers: auth,
    body: JSON.stringify({
      bundle_ids: [BUNDLE, EXTENSION],
      version: "1.0",
      build_number: "7",
    }),
  });
  expect(created.status).toBe(200);
  const { session_id: sessionId } = (await created.json()) as {
    session_id: string;
  };

  const pending = (await (
    await call(`/v1/release/sessions/${sessionId}`, { headers: auth })
  ).json()) as Record<string, unknown>;
  expect(pending.status).toBe("PENDING_APPROVAL");
  expect(pending.session_url).toBeUndefined();

  // What the approval page does: the passkey-derived DEK becomes a grant.
  const account = (await database
    .query("SELECT credential_epk FROM linked_accounts WHERE id = ?;")
    .get(linkedAccountId)) as { credential_epk: Uint8Array };
  const dek = await PB.deriveDek(
    userKey.privateKey,
    new Uint8Array(account.credential_epk),
    linkedAccountId
  );
  const expiresAt = new Date(Date.now() + 45 * 60_000).toISOString();
  await createGrant({
    userId,
    linkedAccountId,
    targetKind: "release",
    targetId: sessionId,
    dek,
    expiresAt,
  });
  expect(
    await setReleaseSessionStatus({
      id: sessionId,
      from: ["PENDING_APPROVAL"],
      status: "APPROVED",
      expiresAt,
    })
  ).toBe(true);

  // The session URL is returned once, only to the same run.
  const otherRun = await oidcToken({ run_id: "2002" });
  expect(
    (
      await call(`/v1/release/sessions/${sessionId}`, {
        headers: { Authorization: `Bearer ${otherRun}` },
      })
    ).status
  ).toBe(404);
  const approved = (await (
    await call(`/v1/release/sessions/${sessionId}`, { headers: auth })
  ).json()) as { session_url?: string };
  expect(approved.session_url).toStartWith(
    `${BASE}/v1/release/session/${sessionId}/rs_`
  );
  const again = (await (
    await call(`/v1/release/sessions/${sessionId}`, { headers: auth })
  ).json()) as { session_url?: string };
  expect(again.session_url).toBeUndefined();
  const sessionPath = new URL(approved.session_url as string).pathname;

  expect(
    (await call(`/v1/release/session/${sessionId}/rs_wrong/info`)).status
  ).toBe(404);
  const info = (await (await call(`${sessionPath}/info`)).json()) as Record<
    string,
    unknown
  >;
  expect(info).toEqual({
    teamId: TEAM,
    distributionCertificateId: "CERT123",
    bundleIds: [BUNDLE, EXTENSION],
  });

  // App Store Connect: the broker adds a JWT signed with the stored key.
  const upstream: Array<{ url: string; auth: string | null }> = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = (async (
    input: string | URL | Request,
    init?: RequestInit
  ) => {
    const url = String(input);
    upstream.push({
      url,
      auth: new Headers(init?.headers).get("authorization"),
    });
    return new Response(
      JSON.stringify({
        data: [{ id: "APP1", attributes: { bundleId: BUNDLE } }],
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }
    );
  }) as typeof fetch;
  try {
    const apps = await call(
      `${sessionPath}/asc/v1/apps?filter[bundleId]=${BUNDLE}`,
      {
        headers: { Authorization: "Bearer caller-supplied" },
      }
    );
    expect(apps.status).toBe(200);
    expect(upstream).toHaveLength(1);
    expect(upstream[0].url).toBe(
      `https://api.appstoreconnect.apple.com/v1/apps?filter[bundleId]=${BUNDLE}`
    );
    const [h, p, s] = (upstream[0].auth as string)
      .replace("Bearer ", "")
      .split(".");
    expect(
      await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" },
        ascKeys.publicKey,
        Buffer.from(s, "base64url"),
        new TextEncoder().encode(`${h}.${p}`)
      )
    ).toBe(true);
    expect(JSON.parse(Buffer.from(p, "base64url").toString()).aud).toBe(
      "appstoreconnect-v1"
    );

    // Learned APP1, so a build upload for it is forwarded; devices never are.
    const upload = await call(`${sessionPath}/asc/v1/buildUploads`, {
      method: "POST",
      body: JSON.stringify({
        data: {
          type: "buildUploads",
          relationships: { app: { data: { type: "apps", id: "APP1" } } },
        },
      }),
    });
    expect(upload.status).toBe(200);
    const devices = await call(`${sessionPath}/asc/v1/devices`);
    expect(devices.status).toBe(403);
    expect(upstream).toHaveLength(2);
  } finally {
    globalThis.fetch = realFetch;
  }

  // Signing: one signature per approved bundle, verifiable with the certificate's key.
  const cd = codeDirectory(BUNDLE, TEAM);
  const attrs = await signedAttributes(cd);
  const sign = (codeDir: Uint8Array, a: Uint8Array) =>
    call(`${sessionPath}/sign`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        codeDirectory: b64(codeDir),
        signedAttributes: b64(a),
      }),
    });
  const signed = await sign(cd, attrs);
  expect(signed.status).toBe(200);
  const { signature } = (await signed.json()) as { signature: string };
  expect(
    await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      distKeys.publicKey,
      Buffer.from(signature, "base64"),
      bufferSource(attrs)
    )
  ).toBe(true);
  expect((await sign(cd, attrs)).status).toBe(403);
  const other = codeDirectory("net.other.app", TEAM);
  expect((await sign(other, await signedAttributes(other))).status).toBe(403);

  expect((await call(sessionPath, { method: "DELETE" })).status).toBe(200);
  expect((await call(`${sessionPath}/info`)).status).toBe(410);
  const grants = (await database
    .query(
      "SELECT COUNT(*) AS n FROM credential_grants WHERE target_kind = 'release';"
    )
    .get()) as { n: number };
  expect(grants.n).toBe(0);
});

// --- App pages: Releases and the two approval kinds ---

test("the Releases page adds a pending policy and the approval pages render both kinds", async () => {
  const { createApp } = await import("../src/app");
  const { sha256Hex } = await import("../src/crypto/sha256");
  const database = await db();
  for (const table of [
    "credential_grants",
    "release_sessions",
    "release_policies",
    "linked_accounts",
    "user_keys",
    "user_passkeys",
    "web_sessions",
    "users",
  ]) {
    await database.exec(`DELETE FROM ${table};`);
  }
  const userId = ulid();
  const now = new Date().toISOString();
  await database
    .query(
      "INSERT INTO users (id, telegram_user_id, created_at, status) VALUES (?, ?, ?, 'active');"
    )
    .run(userId, -Math.floor(Math.random() * 1e9), now);
  await database
    .query(
      "INSERT INTO user_passkeys (user_id, credential_id, public_key, sign_count, transports, prf_salt, created_at) VALUES (?, 'cred', ?, 0, NULL, 'salt', ?);"
    )
    .run(userId, new Uint8Array([1]), now);
  const userKey = await PB.generateUserKeypair();
  await database
    .query(
      "INSERT INTO user_keys (user_id, public_key, wrapped_private_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?);"
    )
    .run(userId, userKey.publicKeyRaw, new Uint8Array([0]), now, now);
  const token = "web-session-token";
  await database
    .query(
      "INSERT INTO web_sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?);"
    )
    .run(
      ulid(),
      userId,
      await sha256Hex(token),
      now,
      now,
      new Date(Date.now() + 3_600_000).toISOString()
    );

  const app = createApp();
  const headers = { Cookie: `pb_session=${token}`, Origin: BASE };

  const form = new URLSearchParams({
    repository: REPO,
    workflow_path: WORKFLOW,
    ref: "refs/heads/main",
    bundle_ids: `${BUNDLE}\n${EXTENSION}`,
  });
  const added = await app.request(`${BASE}/app/releases`, {
    method: "POST",
    headers: {
      ...headers,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });
  expect(added.status).toBe(303);
  const approvePath = added.headers.get("location") as string;
  expect(approvePath).toStartWith("/approve/release_policy/");

  const policyPage = await (
    await app.request(`${BASE}${approvePath}`, { headers })
  ).text();
  expect(policyPage).toContain("Allow CI releases");
  expect(policyPage).toContain(EXTENSION);

  const releases = await (
    await app.request(`${BASE}/app/releases`, { headers })
  ).text();
  expect(releases).toContain("waiting for confirmation");

  const bad = await app.request(`${BASE}/app/releases`, {
    method: "POST",
    headers: {
      ...headers,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      repository: REPO,
      workflow_path: WORKFLOW,
      ref: "refs/heads/main",
      bundle_ids: "net.example.*",
    }).toString(),
  });
  expect(await bad.text()).toContain("no wildcards");

  // A pending release request shows the run on its approval page and in the inbox.
  await saveLinkedCredential({
    userId,
    provider: "apple-release",
    providerUserId: `${TEAM}:KEYID12345`,
    scopes: "testflight_release",
    plaintext: JSON.stringify({
      teamId: TEAM,
      ascKeyId: "KEYID12345",
      ascIssuerId: crypto.randomUUID(),
      ascKeyPem: "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
      distributionKeyPem:
        "-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----",
      distributionCertificateId: "CERT123",
    }),
  });
  const policyId = approvePath.split("/").pop() as string;
  expect(await activateReleasePolicy({ id: policyId, userId })).toBe(true);
  const created = await app.request(`${BASE}/v1/release/sessions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${await oidcToken()}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      bundle_ids: [BUNDLE],
      version: "2.0",
      build_number: "9",
    }),
  });
  const { session_id } = (await created.json()) as { session_id: string };
  const releasePage = await (
    await app.request(`${BASE}/approve/release/${session_id}`, { headers })
  ).text();
  expect(releasePage).toContain("TestFlight release request");
  expect(releasePage).toContain(
    `https://github.com/${REPO}/actions/runs/1001/attempts/1`
  );
  expect(releasePage).toContain('"credential":{');
  const inbox = await (await app.request(`${BASE}/app`, { headers })).text();
  expect(inbox).toContain(`/approve/release/${session_id}`);
});
