import type { Hono } from "hono";

import {
  AppleReleaseCredentialSchema,
  ASC_API_ORIGIN,
  createAscJwt,
} from "../apple/credential";
import { keyMatchesCertificate } from "../apple/signing";
import { auditEvent } from "../audit/audit";
import { getConnectState, markConnectStateUsed } from "../connect/state";
import { isEnrolled, saveLinkedCredential } from "../credentials/store";

// Form-based connect for the `apple-release` credential: one Apple developer
// team's App Store Connect API key and distribution signing key. Checked
// against App Store Connect before saving.

function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

const STYLE = `body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 24px; max-width: 720px; margin: 0 auto; }
      h1 { font-size: 20px; margin: 0 0 12px; }
      p { color: #333; line-height: 1.4; }
      label { display: block; margin: 12px 0 6px; font-weight: 600; }
      input, textarea { width: 100%; padding: 10px; font-size: 14px; box-sizing: border-box; }
      textarea { height: 8em; font-family: ui-monospace, monospace; font-size: 12px; }
      button { margin-top: 16px; padding: 10px 14px; font-size: 14px; }
      .note { font-size: 13px; color: #444; }
      code { background: #f3f3f3; padding: 2px 4px; }`;

function page(title: string, body: string): string {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      ${STYLE}
    </style>
  </head>
  <body>
    ${body}
  </body>
</html>`;
}

function renderForm(state: string): string {
  return page(
    "Connect Apple release",
    `<h1>Connect Apple release signing</h1>
    <p>Lets approved CI runs sign and upload TestFlight builds. Both keys are encrypted to your passkey and never leave the broker: runs get signatures and App Store Connect responses, not keys.</p>
    <p class="note">Use a dedicated App Store Connect team key (Users and Access &gt; Integrations; the Developer role is enough for internal TestFlight uploads) so it can be revoked on its own. The distribution key is <code>~/.stupid-app/credentials/distribution.key.pem</code> from <code>stupid-app signing setup</code> (PKCS#8, <code>BEGIN PRIVATE KEY</code>), its certificate ID is in <code>distribution.cert.id</code>.</p>
    <form method="post" action="/v1/accounts/connect/apple-release">
      <input type="hidden" name="state" value="${escapeHtml(state)}" />
      <label>Team ID</label>
      <input name="team_id" autocomplete="off" required />
      <label>App Store Connect key ID</label>
      <input name="asc_key_id" autocomplete="off" required />
      <label>App Store Connect issuer ID</label>
      <input name="asc_issuer_id" autocomplete="off" required />
      <label>App Store Connect key (.p8 contents)</label>
      <textarea name="asc_key_pem" autocomplete="off" spellcheck="false" required></textarea>
      <label>Distribution certificate ID</label>
      <input name="distribution_certificate_id" autocomplete="off" required />
      <label>Distribution private key (PEM)</label>
      <textarea name="distribution_key_pem" autocomplete="off" spellcheck="false" required></textarea>
      <button type="submit">Check and connect</button>
    </form>`
  );
}

function renderResult(params: { ok: boolean; message: string }): string {
  const title = params.ok ? "Connected" : "Connection failed";
  return page(
    title,
    `<h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(params.message)}</p>
    <p><a href="/app/accounts">Back to accounts</a></p>`
  );
}

function field(body: Record<string, unknown>, name: string): string {
  const v = body[name];
  return typeof v === "string" ? v.trim() : "";
}

export class AppleReleaseCheckError extends Error {}

// Checks the key against App Store Connect: the certificate must be an active
// distribution certificate and the private key must belong to it.
async function checkCredential(params: {
  credential: ReturnType<typeof AppleReleaseCredentialSchema.parse>;
}): Promise<void> {
  let jwt: string;
  try {
    jwt = (await createAscJwt({ credential: params.credential })).token;
  } catch {
    throw new AppleReleaseCheckError(
      "The App Store Connect key is not a PKCS#8 P-256 key (.p8)."
    );
  }
  const res = await fetch(
    `${ASC_API_ORIGIN}/v1/certificates/${encodeURIComponent(params.credential.distributionCertificateId)}`,
    { headers: { Authorization: `Bearer ${jwt}`, Accept: "application/json" } }
  );
  if (res.status === 401) {
    throw new AppleReleaseCheckError(
      "App Store Connect refused the key (check the key ID and issuer ID)."
    );
  }
  if (!res.ok) {
    throw new AppleReleaseCheckError(
      `App Store Connect could not read the certificate (HTTP ${res.status}).`
    );
  }
  const body = (await res.json()) as {
    data?: {
      attributes?: { certificateType?: string; certificateContent?: string };
    };
  };
  const attrs = body.data?.attributes;
  if (!attrs?.certificateContent) {
    throw new AppleReleaseCheckError(
      "App Store Connect returned no certificate content."
    );
  }
  if (
    attrs.certificateType !== "DISTRIBUTION" &&
    attrs.certificateType !== "IOS_DISTRIBUTION"
  ) {
    throw new AppleReleaseCheckError(
      `Certificate type is ${attrs.certificateType}, not a distribution certificate.`
    );
  }
  const der = Uint8Array.from(atob(attrs.certificateContent), (ch) =>
    ch.charCodeAt(0)
  );
  let matches = false;
  try {
    matches = await keyMatchesCertificate({
      distributionKeyPem: params.credential.distributionKeyPem,
      certificateDer: der,
    });
  } catch {
    throw new AppleReleaseCheckError(
      "The distribution key is not a PKCS#8 RSA key (BEGIN PRIVATE KEY)."
    );
  }
  if (!matches) {
    throw new AppleReleaseCheckError(
      "The distribution key does not belong to that certificate."
    );
  }
}

export function registerAppleReleaseConnect(router: Hono): void {
  router.get("/connect/apple-release", async (c) => {
    const state = c.req.query("state");
    if (!state) return c.text("missing state", 400);
    try {
      const { userId } = await getConnectState({
        state,
        provider: "apple-release",
      });
      if (!(await isEnrolled(userId))) {
        return c.html(
          renderResult({ ok: false, message: "Set up a passkey first." }),
          409
        );
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.html(renderResult({ ok: false, message: msg }), 400);
    }
    return c.html(renderForm(state));
  });

  router.post("/connect/apple-release", async (c) => {
    const body = await c.req.parseBody();
    const state = field(body, "state");
    if (!state) {
      return c.html(renderResult({ ok: false, message: "missing state" }), 400);
    }

    let userId: string;
    try {
      ({ userId } = await getConnectState({
        state,
        provider: "apple-release",
      }));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return c.html(renderResult({ ok: false, message: msg }), 400);
    }

    const parsed = AppleReleaseCredentialSchema.safeParse({
      teamId: field(body, "team_id"),
      ascKeyId: field(body, "asc_key_id"),
      ascIssuerId: field(body, "asc_issuer_id"),
      ascKeyPem: field(body, "asc_key_pem"),
      distributionKeyPem: field(body, "distribution_key_pem"),
      distributionCertificateId: field(body, "distribution_certificate_id"),
    });
    if (!parsed.success) {
      const fields = [
        ...new Set(parsed.error.issues.map((i) => String(i.path[0]))),
      ];
      return c.html(
        renderResult({
          ok: false,
          message: `Check these fields: ${fields.join(", ")}. Keys must be PKCS#8 PEM (BEGIN PRIVATE KEY).`,
        }),
        400
      );
    }

    try {
      await checkCredential({ credential: parsed.data });
    } catch (err) {
      if (err instanceof AppleReleaseCheckError) {
        return c.html(renderResult({ ok: false, message: err.message }), 400);
      }
      throw err;
    }

    await saveLinkedCredential({
      userId,
      provider: "apple-release",
      providerUserId: `${parsed.data.teamId}:${parsed.data.ascKeyId}`,
      scopes: "testflight_release",
      plaintext: JSON.stringify(parsed.data),
    });
    await markConnectStateUsed(state);
    await auditEvent({
      userId,
      actorType: "system",
      actorId: "connect_apple_release",
      eventType: "linked_account_updated",
      event: {
        provider: "apple-release",
        team_id: parsed.data.teamId,
        certificate_id: parsed.data.distributionCertificateId,
      },
    });
    return c.html(
      renderResult({
        ok: true,
        message: `Apple release signing connected for team ${parsed.data.teamId}.`,
      })
    );
  });
}
