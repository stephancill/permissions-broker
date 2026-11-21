import { z } from "zod";

import { bufferSource, toBase64Url } from "../crypto/bytes";
import { pemToDer } from "./der";

// The `apple-release` linked credential: one Apple developer team's App Store
// Connect API key and distribution signing key. Encrypted to the user's passkey
// key like every other credential; display metadata lives in metadata_json.
export const AppleReleaseCredentialSchema = z.object({
  teamId: z.string().regex(/^[A-Z0-9]{10}$/),
  ascKeyId: z.string().regex(/^[A-Z0-9]{8,16}$/),
  ascIssuerId: z.string().uuid(),
  ascKeyPem: z.string().includes("-----BEGIN PRIVATE KEY-----"),
  distributionKeyPem: z.string().includes("-----BEGIN PRIVATE KEY-----"),
  distributionCertificateId: z.string().regex(/^[A-Z0-9]{6,20}$/),
});

export type AppleReleaseCredential = z.infer<
  typeof AppleReleaseCredentialSchema
>;

export function parseAppleReleaseCredential(
  stored: string
): AppleReleaseCredential | null {
  try {
    const parsed = AppleReleaseCredentialSchema.safeParse(JSON.parse(stored));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

export const ASC_API_ORIGIN = "https://api.appstoreconnect.apple.com";
export const ASC_JWT_LIFETIME_SECONDS = 15 * 60;

function base64UrlJson(value: unknown): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

// ES256 JWT for the App Store Connect API (max 20 minutes).
export async function createAscJwt(params: {
  credential: AppleReleaseCredential;
  nowSeconds?: number;
}): Promise<{ token: string; expiresAt: number }> {
  const now = params.nowSeconds ?? Math.floor(Date.now() / 1000);
  const exp = now + ASC_JWT_LIFETIME_SECONDS;
  const header = base64UrlJson({
    alg: "ES256",
    kid: params.credential.ascKeyId,
    typ: "JWT",
  });
  const payload = base64UrlJson({
    iss: params.credential.ascIssuerId,
    iat: now,
    exp,
    aud: "appstoreconnect-v1",
  });
  const key = await crypto.subtle.importKey(
    "pkcs8",
    bufferSource(pemToDer(params.credential.ascKeyPem, "PRIVATE KEY")),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const signingInput = `${header}.${payload}`;
  // WebCrypto ECDSA returns r||s, the JWS encoding.
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      bufferSource(new TextEncoder().encode(signingInput))
    )
  );
  return { token: `${signingInput}.${toBase64Url(signature)}`, expiresAt: exp };
}
