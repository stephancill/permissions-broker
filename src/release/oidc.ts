import { z } from "zod";

import { bufferSource, fromBase64Url } from "../crypto/bytes";

// GitHub Actions OIDC tokens (RS256, signed by GitHub's published JWKS).
// The only identity a release session accepts: no long-lived broker secret is
// stored in GitHub.

export const GITHUB_OIDC_ISSUER = "https://token.actions.githubusercontent.com";
const JWKS_URL = `${GITHUB_OIDC_ISSUER}/.well-known/jwks`;
const JWKS_CACHE_MS = 10 * 60_000;
const CLOCK_SKEW_SECONDS = 60;

const ClaimsSchema = z.object({
  iss: z.literal(GITHUB_OIDC_ISSUER),
  aud: z.union([z.string(), z.array(z.string())]),
  exp: z.number(),
  nbf: z.number().optional(),
  iat: z.number(),
  repository: z.string().min(1),
  repository_owner: z.string().min(1),
  workflow_ref: z.string().min(1),
  job_workflow_ref: z.string().min(1).optional(),
  ref: z.string().min(1),
  sha: z.string().min(1),
  run_id: z.string().min(1),
  run_attempt: z.string().min(1),
  actor: z.string().min(1),
  event_name: z.string().min(1),
});

export type GithubOidcClaims = z.infer<typeof ClaimsSchema>;

export class OidcError extends Error {}

type Jwk = {
  kty?: string;
  n?: string;
  e?: string;
  kid?: string;
};
let jwksCache: { keys: Jwk[]; fetchedAt: number } | null = null;

// Tests inject keys here instead of fetching GitHub's.
let jwksOverride: Jwk[] | null = null;
export function setJwksForTests(keys: Jwk[] | null): void {
  jwksOverride = keys;
  jwksCache = null;
}

async function jwks(forceRefresh: boolean): Promise<Jwk[]> {
  if (jwksOverride) return jwksOverride;
  if (
    !forceRefresh &&
    jwksCache &&
    Date.now() - jwksCache.fetchedAt < JWKS_CACHE_MS
  ) {
    return jwksCache.keys;
  }
  const res = await fetch(JWKS_URL, {
    headers: { Accept: "application/json" },
  });
  if (!res.ok)
    throw new OidcError(`could not fetch GitHub JWKS (${res.status})`);
  const body = (await res.json()) as { keys?: Jwk[] };
  if (!Array.isArray(body.keys)) throw new OidcError("malformed GitHub JWKS");
  jwksCache = { keys: body.keys, fetchedAt: Date.now() };
  return body.keys;
}

function decodeJson(segment: string): unknown {
  return JSON.parse(new TextDecoder().decode(fromBase64Url(segment)));
}

export async function verifyGithubOidcToken(params: {
  token: string;
  audience: string;
  nowSeconds?: number;
}): Promise<GithubOidcClaims> {
  const parts = params.token.split(".");
  if (parts.length !== 3) throw new OidcError("malformed token");
  const [headerB64, payloadB64, signatureB64] = parts;

  let header: { alg?: string; kid?: string };
  try {
    header = decodeJson(headerB64) as typeof header;
  } catch {
    throw new OidcError("malformed token header");
  }
  if (header.alg !== "RS256" || !header.kid) {
    throw new OidcError("unsupported token algorithm");
  }

  let jwk = (await jwks(false)).find((k) => k.kid === header.kid);
  // GitHub rotates keys; refresh once for an unknown kid.
  if (!jwk) jwk = (await jwks(true)).find((k) => k.kid === header.kid);
  if (!jwk) throw new OidcError("unknown signing key");

  const key = await crypto.subtle.importKey(
    "jwk",
    { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    bufferSource(fromBase64Url(signatureB64)),
    bufferSource(new TextEncoder().encode(`${headerB64}.${payloadB64}`))
  );
  if (!valid) throw new OidcError("invalid token signature");

  let raw: unknown;
  try {
    raw = decodeJson(payloadB64);
  } catch {
    throw new OidcError("malformed token payload");
  }
  const parsed = ClaimsSchema.safeParse(raw);
  if (!parsed.success) throw new OidcError("token is missing required claims");
  const claims = parsed.data;

  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(params.audience)) {
    throw new OidcError("token audience does not match this broker");
  }
  const now = params.nowSeconds ?? Math.floor(Date.now() / 1000);
  if (claims.exp + CLOCK_SKEW_SECONDS < now)
    throw new OidcError("token expired");
  if ((claims.nbf ?? claims.iat) - CLOCK_SKEW_SECONDS > now) {
    throw new OidcError("token not yet valid");
  }
  return claims;
}

// `owner/repo/.github/workflows/file.yml@refs/heads/main` → path and ref.
export function splitWorkflowRef(
  workflowRef: string,
  repository: string
): { path: string; ref: string } | null {
  const prefix = `${repository}/`;
  if (!workflowRef.startsWith(prefix)) return null;
  const rest = workflowRef.slice(prefix.length);
  const at = rest.lastIndexOf("@");
  if (at <= 0) return null;
  return { path: rest.slice(0, at), ref: rest.slice(at + 1) };
}
