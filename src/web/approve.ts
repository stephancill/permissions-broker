import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { type Context, Hono } from "hono";
import { ulid } from "ulid";
import { z } from "zod";

import { auditEvent } from "../audit/audit";
import { requireSessionJson, requireSessionPage } from "../auth/session";
import {
  CredentialError,
  createGrant,
  deleteGrant,
  type GrantTargetKind,
  getActiveLinkedAccount,
  type LinkedAccountRow,
} from "../credentials/store";
import { fromBase64Url, toBase64Url } from "../crypto/bytes";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import {
  approvalChallenge,
  consumeChallenge,
  getUserPasskey,
  getWrappedPrivateKey,
  storeChallenge,
  verifyPasskeyAssertion,
} from "../passkey/webauthn";
import {
  APPROVAL_WINDOW_MINUTES,
  APPROVAL_WINDOW_SCOPES,
  createApprovalWindow,
} from "../proxy/approvalWindows";
import { getProxyProviderForUrl } from "../proxy/providerRegistry";
import { summarizeStoredProxyRequest, truncate } from "../proxy/summary";
import {
  activateReleasePolicy,
  getReleasePolicy,
  getReleaseSession,
  RELEASE_SESSION_MAX_MS,
  setReleaseSessionStatus,
} from "../release/store";
import {
  escapeHtml,
  POST_JSON_SCRIPT,
  scriptJson,
  sendMessagePage,
  sendPage,
} from "./pages";
import { APPLE_RELEASE_PROVIDER } from "./release";

// Session grants are wiped when the session ends; this is a hard cap.
const SESSION_GRANT_MAX_MS = 60 * 60_000;

const ApprovalKind = z.enum([
  "proxy",
  "git",
  "email",
  "release",
  "release_policy",
]);
type ApprovalKind = z.infer<typeof ApprovalKind>;

const ProxyOptions = z.union([
  z.object({ mode: z.literal("once") }),
  z.object({
    mode: z.literal("window"),
    minutes: z.union(
      APPROVAL_WINDOW_MINUTES.map((m) => z.literal(m)) as [
        z.ZodLiteral<15>,
        z.ZodLiteral<60>,
      ]
    ),
    scope: z.enum(APPROVAL_WINDOW_SCOPES),
  }),
]);
const GitOptions = z.object({ allow_default_branch_push: z.boolean() });
const EmailOptions = z.object({});
const NoOptions = z.object({});

type ApprovalOptions =
  | z.infer<typeof ProxyOptions>
  | z.infer<typeof GitOptions>
  | z.infer<typeof EmailOptions>;

const ChallengeSchema = z.object({
  options: z.unknown(),
});

const ApproveSchema = z.object({
  nonce: z.string().min(1),
  assertion: z.record(z.string(), z.unknown()),
  dek: z.string().optional(),
});

function nowIso(): string {
  return new Date().toISOString();
}

type ApprovalTarget = {
  kind: ApprovalKind;
  id: string;
  userId: string;
  status: string;
  approvalExpiresAt: string;
  requestHash: string;
  heading: string;
  apiKeyLabel: string;
  lines: Array<[string, string]>;
  details: string[];
  body?: string;
  consentHint: string | null;
  // Provider whose stored credential this approval unlocks (if linked).
  credentialProvider: string | null;
  // Proxy only: approval windows need the requester IP to scope them.
  requesterIp: string | null;
  apiKeyId: string;
  operation?: string;
  upstreamUrl?: string;
  method?: string;
};

async function loadTarget(
  kind: ApprovalKind,
  id: string
): Promise<ApprovalTarget | null> {
  const database = await db();

  if (kind === "proxy") {
    const row = (await database
      .query(
        "SELECT id, user_id, api_key_id, api_key_label_snapshot, requester_ip, upstream_url, method, request_headers_json, request_body_base64, request_hash, consent_hint, status, approval_expires_at FROM proxy_requests WHERE id = ?;"
      )
      .get(id)) as {
      id: string;
      user_id: string;
      api_key_id: string;
      api_key_label_snapshot: string;
      requester_ip: string | null;
      upstream_url: string;
      method: string;
      request_headers_json: string | null;
      request_body_base64: string | null;
      request_hash: string;
      consent_hint: string | null;
      status: string;
      approval_expires_at: string;
    } | null;
    if (!row) return null;

    const summary = summarizeStoredProxyRequest(row);
    let providerId: string | null = null;
    try {
      providerId = getProxyProviderForUrl(new URL(row.upstream_url)).id;
    } catch {
      providerId = null;
    }

    return {
      kind,
      id: row.id,
      userId: row.user_id,
      status: row.status,
      approvalExpiresAt: row.approval_expires_at,
      requestHash: row.request_hash,
      heading: "Permission request",
      apiKeyLabel: row.api_key_label_snapshot,
      lines: [
        ["Action", summary.action],
        ["Request", summary.request],
      ],
      details: summary.details,
      body: summary.body,
      consentHint: row.consent_hint,
      credentialProvider: providerId,
      requesterIp: row.requester_ip,
      apiKeyId: row.api_key_id,
      upstreamUrl: row.upstream_url,
      method: row.method,
    };
  }

  if (kind === "git") {
    const row = (await database
      .query(
        "SELECT g.id, g.user_id, g.api_key_id, g.operation, g.repo_owner, g.repo_name, g.status, g.approval_expires_at, k.label AS api_key_label FROM git_sessions g JOIN api_keys k ON k.id = g.api_key_id WHERE g.id = ?;"
      )
      .get(id)) as {
      id: string;
      user_id: string;
      api_key_id: string;
      operation: string;
      repo_owner: string;
      repo_name: string;
      status: string;
      approval_expires_at: string;
      api_key_label: string;
    } | null;
    if (!row) return null;
    const repo = `${row.repo_owner}/${row.repo_name}`;
    const isPush = row.operation === "push";
    return {
      kind,
      id: row.id,
      userId: row.user_id,
      status: row.status,
      approvalExpiresAt: row.approval_expires_at,
      requestHash: await sha256Hex(`git:${row.operation}:${repo}`),
      heading: "Git session request",
      apiKeyLabel: row.api_key_label,
      lines: [
        ["Repo", `github.com/${repo}`],
        [
          "Operation",
          `${row.operation.toUpperCase()} (${isPush ? "write" : "read"})`,
        ],
      ],
      details: isPush
        ? ["Ref deletions and tag updates are always blocked."]
        : [],
      consentHint: null,
      credentialProvider: "github",
      requesterIp: null,
      apiKeyId: row.api_key_id,
      operation: row.operation,
    };
  }

  if (kind === "release") {
    const session = await getReleaseSession(id);
    if (!session) return null;
    const bundleIds = JSON.parse(session.bundle_ids_json) as string[];
    return {
      kind,
      id: session.id,
      userId: session.user_id,
      status: session.status,
      approvalExpiresAt: session.approval_expires_at,
      requestHash: await sha256Hex(
        `release:${session.repository}:${session.sha}:${session.run_id}:${bundleIds.join(",")}:${session.version}:${session.build_number}`
      ),
      heading: "TestFlight release request",
      apiKeyLabel: `GitHub Actions (${session.actor})`,
      lines: [
        ["Repository", session.repository],
        ["Workflow", session.workflow_ref],
        ["Commit", session.sha],
        [
          "Run",
          `https://github.com/${session.repository}/actions/runs/${session.run_id}/attempts/${session.run_attempt}`,
        ],
        ["Bundles", bundleIds.join(", ")],
        ["Version", `${session.version} (${session.build_number})`],
      ],
      details: [
        "Signs one build of each bundle with your distribution key and lets the run upload it to App Store Connect (internal TestFlight).",
        "The keys stay in the broker. The session ends after 45 minutes or 15 minutes without requests.",
      ],
      consentHint: null,
      credentialProvider: APPLE_RELEASE_PROVIDER,
      requesterIp: null,
      apiKeyId: "",
    };
  }

  if (kind === "release_policy") {
    const policy = await getReleasePolicy(id);
    if (!policy) return null;
    const bundleIds = JSON.parse(policy.bundle_ids_json) as string[];
    return {
      kind,
      id: policy.id,
      userId: policy.user_id,
      status: policy.status,
      approvalExpiresAt: policy.approval_expires_at,
      requestHash: await sha256Hex(
        `release_policy:${policy.repository}:${policy.workflow_path}:${policy.ref}:${bundleIds.join(",")}`
      ),
      heading: "Allow CI releases",
      apiKeyLabel: "You (Releases page)",
      lines: [
        ["Repository", policy.repository],
        ["Workflow", policy.workflow_path],
        ["Branch", policy.ref],
        ["Bundles", bundleIds.join(", ")],
      ],
      details: [
        "Lets this workflow ask for TestFlight releases of these bundles. Each release still needs your approval.",
      ],
      consentHint: null,
      credentialProvider: null,
      requesterIp: null,
      apiKeyId: "",
    };
  }

  const row = (await database
    .query(
      "SELECT e.id, e.user_id, e.api_key_id, e.status, e.approval_expires_at, e.consent_hint, k.label AS api_key_label FROM email_sessions e JOIN api_keys k ON k.id = e.api_key_id WHERE e.id = ?;"
    )
    .get(id)) as {
    id: string;
    user_id: string;
    api_key_id: string;
    status: string;
    approval_expires_at: string;
    consent_hint: string | null;
    api_key_label: string;
  } | null;
  if (!row) return null;
  return {
    kind,
    id: row.id,
    userId: row.user_id,
    status: row.status,
    approvalExpiresAt: row.approval_expires_at,
    requestHash: await sha256Hex(`email:read:${row.id}`),
    heading: "Email read session request",
    apiKeyLabel: row.api_key_label,
    lines: [
      ["Provider", "imap"],
      ["Access", "READ ONLY"],
    ],
    details: [
      "Lets the agent list folders, search, and read messages while the session is active.",
    ],
    consentHint: row.consent_hint,
    credentialProvider: "imap",
    requesterIp: null,
    apiKeyId: row.api_key_id,
  };
}

function parseOptions(
  target: ApprovalTarget,
  raw: unknown
): ApprovalOptions | null {
  if (target.kind === "proxy") {
    const p = ProxyOptions.safeParse(raw);
    if (!p.success) return null;
    if (p.data.mode === "window") {
      if (!target.requesterIp) return null;
      if (p.data.scope === "provider" && !target.credentialProvider) {
        return null;
      }
    }
    return p.data;
  }
  if (target.kind === "git") {
    const p = GitOptions.safeParse(raw);
    if (!p.success) return null;
    if (target.operation !== "push" && p.data.allow_default_branch_push) {
      return null;
    }
    return p.data;
  }
  if (target.kind === "release" || target.kind === "release_policy") {
    const p = NoOptions.safeParse(raw);
    return p.success ? p.data : null;
  }
  const p = EmailOptions.safeParse(raw);
  return p.success ? p.data : null;
}

function isExpired(target: ApprovalTarget): boolean {
  const exp = Date.parse(target.approvalExpiresAt);
  return Number.isFinite(exp) && Date.now() > exp;
}

async function markExpired(target: ApprovalTarget): Promise<void> {
  const database = await db();
  const table = tableFor(target.kind);
  const extra =
    target.kind === "proxy" ? ", error_code = 'APPROVAL_EXPIRED'" : "";
  await database
    .query(
      `UPDATE ${table} SET status = 'EXPIRED', updated_at = ?${extra} WHERE id = ? AND status = 'PENDING_APPROVAL';`
    )
    .run(nowIso(), target.id);
}

function tableFor(kind: ApprovalKind): string {
  switch (kind) {
    case "proxy":
      return "proxy_requests";
    case "git":
      return "git_sessions";
    case "email":
      return "email_sessions";
    case "release":
      return "release_sessions";
    case "release_policy":
      return "release_policies";
  }
}

function eventName(
  kind: ApprovalKind,
  decision: "approved" | "denied"
): string {
  switch (kind) {
    case "proxy":
      return `proxy_request_${decision}`;
    case "git":
      return `git_session_${decision}`;
    case "email":
      return `email_session_${decision}`;
    case "release":
      return `release_session_${decision}`;
    case "release_policy":
      return `release_policy_${decision}`;
  }
}

// Targets are only visible to the signed-in user who owns them.
async function resolveTarget(
  c: Context
): Promise<
  { ok: true; target: ApprovalTarget } | { ok: false; error: string }
> {
  const kindParsed = ApprovalKind.safeParse(c.req.param("kind"));
  const id = c.req.param("id");
  if (!kindParsed.success || !id) return { ok: false, error: "not_found" };
  const kind = kindParsed.data;

  const target = await loadTarget(kind, id);
  if (!target || target.userId !== c.get("webSession").userId) {
    return { ok: false, error: "not_found" };
  }
  return { ok: true, target };
}

function renderTargetHtml(target: ApprovalTarget): string {
  const rows = [
    ["API key", target.apiKeyLabel] as [string, string],
    ...target.lines,
  ]
    .map(([k, v]) => `<li><b>${escapeHtml(k)}</b>: ${escapeHtml(v)}</li>`)
    .join("");
  const details = target.details.length
    ? `<p><b>Details</b></p><ul>${target.details
        .map((d) => `<li>${escapeHtml(d)}</li>`)
        .join("")}</ul>`
    : "";
  const body = target.body
    ? `<p><b>Body</b></p><pre>${escapeHtml(target.body)}</pre>`
    : "";
  const note = target.consentHint
    ? `<p><b>Requester note</b>: ${escapeHtml(truncate(target.consentHint, 300))}</p>`
    : "";
  return `<ul>${rows}</ul>${details}${body}${note}<p class="note">Hash: <code>${escapeHtml(target.requestHash.slice(0, 12))}</code></p>`;
}

function renderOptionsHtml(target: ApprovalTarget): string {
  if (target.kind === "proxy") {
    const windows = target.requesterIp
      ? APPROVAL_WINDOW_MINUTES.map(
          (m) =>
            `<label><input type="radio" name="opt" value="window:endpoint:${m}" /> Approve this endpoint for ${m} minutes</label>`
        ).join("")
      : "";
    const provider = target.credentialProvider
      ? escapeHtml(target.credentialProvider)
      : null;
    const advanced =
      target.requesterIp && provider
        ? `<details id="advanced"><summary>Advanced</summary>
          <p class="error"><b>Warning:</b> this auto-approves <b>every</b> ${provider} request from this API key and IP, including writes and deletes on anything your linked ${provider} account can access. You will not be asked again until it expires. Only use this for an agent you fully trust.</p>
          ${APPROVAL_WINDOW_MINUTES.map(
            (m) =>
              `<label><input type="radio" name="opt" value="window:provider:${m}" /> Approve all ${provider} requests for ${m} minutes</label>`
          ).join("")}
        </details>`
        : "";
    return `<label><input type="radio" name="opt" value="once" checked /> Approve once</label>${windows}${advanced}`;
  }
  if (target.kind === "git" && target.operation === "push") {
    return `<label><input type="radio" name="opt" value="block_default" checked /> Allow push (block the default branch)</label>
      <label><input type="radio" name="opt" value="allow_default" /> Allow push including the default branch</label>`;
  }
  return "";
}

export const approveRouter = new Hono();

approveRouter.get("/:kind/:id", requireSessionPage, async (c) => {
  const resolved = await resolveTarget(c);
  if (!resolved.ok) {
    return sendMessagePage(c, {
      title: "Approval",
      message: "Request not found.",
      status: 404,
    });
  }
  const target = resolved.target;

  if (target.status === "PENDING_APPROVAL" && isExpired(target)) {
    await markExpired(target);
    target.status = "EXPIRED";
  }
  if (target.status !== "PENDING_APPROVAL") {
    return sendMessagePage(c, {
      title: target.heading,
      message: `This request is no longer pending (status: ${target.status}).`,
    });
  }

  const passkey = await getUserPasskey(target.userId);
  const wrapped = await getWrappedPrivateKey(target.userId);
  if (!passkey || !wrapped) {
    return sendMessagePage(c, {
      title: target.heading,
      message: "No passkey is set up for this account.",
      status: 409,
    });
  }

  let account: LinkedAccountRow | null = null;
  if (target.credentialProvider) {
    account = await getActiveLinkedAccount({
      userId: target.userId,
      provider: target.credentialProvider,
    });
  }
  if (account && (account.enc_version !== 1 || !account.credential_epk)) {
    return sendMessagePage(c, {
      title: target.heading,
      message: `Your ${target.credentialProvider} credential has not been migrated to passkey encryption. Replace your passkey under Settings or reconnect the account.`,
      status: 409,
    });
  }

  const data = {
    kind: target.kind,
    id: target.id,
    // The passkey's own RP ID (the previous domain until it is moved).
    rp_id: passkey.rp_id,
    user_id: target.userId,
    passkey: {
      credential_id: passkey.credential_id,
      prf_salt: passkey.prf_salt,
      wrapped_private_key: toBase64Url(wrapped),
    },
    credential: account?.credential_epk
      ? {
          linked_account_id: account.id,
          epk: toBase64Url(account.credential_epk),
        }
      : null,
  };

  const noCredentialNote =
    target.credentialProvider && !account
      ? `<p class="note">No ${escapeHtml(target.credentialProvider)} account is linked; the request will run without your credentials.</p>`
      : "";

  const body = `
    <h1>${escapeHtml(target.heading)}</h1>
    ${renderTargetHtml(target)}
    ${noCredentialNote}
    <form id="opts">${renderOptionsHtml(target)}</form>
    <button id="approve" type="button">Approve with passkey</button>
    <button id="deny" type="button">Deny</button>
    <p id="status"></p>`;

  const script = `
    ${POST_JSON_SCRIPT}
    var DATA = ${scriptJson(data)};
    var statusEl = document.getElementById("status");
    function setStatus(text, cls) { statusEl.textContent = text; statusEl.className = cls || ""; }

    // Remove this request's notification from the device once decided.
    function closeNotification() {
      if (!("serviceWorker" in navigator)) return;
      navigator.serviceWorker.getRegistration().then(function (reg) {
        if (!reg) return;
        return reg.getNotifications({ tag: DATA.kind + ":" + DATA.id }).then(function (ns) {
          ns.forEach(function (n) { n.close(); });
        });
      }).catch(function () {});
    }

    function decided(message) {
      setStatus(message, "ok");
      document.getElementById("approve").disabled = true;
      document.getElementById("deny").disabled = true;
      closeNotification();
    }

    function selectedOptions() {
      var el = document.querySelector("input[name=opt]:checked");
      var v = el ? el.value : "";
      if (DATA.kind === "proxy") {
        var parts = v.split(":");
        if (parts[0] === "window") return { mode: "window", scope: parts[1], minutes: Number(parts[2]) };
        return { mode: "once" };
      }
      if (DATA.kind === "git") return { allow_default_branch_push: v === "allow_default" };
      return {};
    }

    async function approve() {
      var base = "/approve/" + DATA.kind + "/" + encodeURIComponent(DATA.id);
      setStatus("Preparing…");
      var ch = await postJson(base + "/challenge", { options: selectedOptions() });

      setStatus("Confirm with your passkey…");
      var a = await navigator.credentials.get({ publicKey: {
        challenge: PB.unb64u(ch.challenge),
        rpId: DATA.rp_id,
        allowCredentials: [{ type: "public-key", id: PB.unb64u(DATA.passkey.credential_id) }],
        userVerification: "required",
        extensions: { prf: { eval: { first: PB.unb64u(DATA.passkey.prf_salt) } } },
      }});

      var body = { nonce: ch.nonce, assertion: PB.assertionToJSON(a) };
      if (DATA.credential) {
        var prf = PB.prfFirst(a);
        if (!prf) throw new Error("Passkey did not return a PRF value.");
        var kek = await PB.deriveKek(prf, DATA.user_id);
        var priv = await PB.unwrapPrivateKey(kek, PB.unb64u(DATA.passkey.wrapped_private_key), DATA.user_id, false);
        var dek = await PB.deriveDek(priv, PB.unb64u(DATA.credential.epk), DATA.credential.linked_account_id);
        body.dek = PB.b64u(dek);
      }

      setStatus("Approving…");
      var r = await postJson(base, body);
      decided(r.message || "Approved.");
    }

    async function deny() {
      var base = "/approve/" + DATA.kind + "/" + encodeURIComponent(DATA.id);
      setStatus("Denying…");
      var r = await postJson(base + "/deny", {});
      decided(r.message || "Denied.");
    }

    // Collapsing Advanced must not leave a hidden provider-wide option selected.
    var advancedEl = document.getElementById("advanced");
    if (advancedEl) {
      advancedEl.addEventListener("toggle", function () {
        var sel = document.querySelector("input[name=opt]:checked");
        if (!advancedEl.open && sel && sel.value.indexOf("window:provider:") === 0) {
          document.querySelector("input[name=opt][value=once]").checked = true;
        }
      });
    }

    document.getElementById("approve").onclick = function () {
      approve().catch(function (e) { setStatus("Failed: " + errorText(e), "error"); });
    };
    document.getElementById("deny").onclick = function () {
      deny().catch(function (e) { setStatus("Failed: " + errorText(e), "error"); });
    };
  `;

  return sendPage(c, {
    title: target.heading,
    body,
    script,
    crypto: true,
    nav: "/app",
  });
});

approveRouter.post("/:kind/:id/challenge", requireSessionJson, async (c) => {
  const parsed = ChallengeSchema.safeParse(
    await c.req.json().catch(() => null)
  );
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);

  const resolved = await resolveTarget(c);
  if (!resolved.ok) return c.json({ error: resolved.error }, 404);
  const target = resolved.target;

  if (target.status !== "PENDING_APPROVAL") {
    return c.json({ error: "not_pending", status: target.status }, 409);
  }
  if (isExpired(target)) {
    await markExpired(target);
    return c.json({ error: "approval_expired" }, 408);
  }

  const options = parseOptions(target, parsed.data.options);
  if (!options) return c.json({ error: "invalid_options" }, 400);

  const nonce = ulid();
  const challenge = await approvalChallenge({
    kind: target.kind,
    id: target.id,
    requestHash: target.requestHash,
    options,
    nonce,
  });
  await storeChallenge({
    userId: target.userId,
    purpose: "approve",
    challenge,
    nonce,
    targetKind: target.kind,
    targetId: target.id,
    options,
  });

  return c.json({ nonce, challenge });
});

// Denying needs no passkey: it can only take access away.
approveRouter.post("/:kind/:id/deny", requireSessionJson, async (c) => {
  const resolved = await resolveTarget(c);
  if (!resolved.ok) return c.json({ error: resolved.error }, 404);
  const target = resolved.target;
  const { sessionId } = c.get("webSession");

  if (target.status === "PENDING_APPROVAL" && isExpired(target)) {
    await markExpired(target);
    return c.json({ error: "approval_expired" }, 408);
  }

  const database = await db();
  const extra = target.kind === "proxy" ? ", error_code = 'DENIED'" : "";
  const res = await database
    .query(
      `UPDATE ${tableFor(target.kind)} SET status = 'DENIED', updated_at = ?${extra} WHERE id = ? AND user_id = ? AND status = 'PENDING_APPROVAL';`
    )
    .run(nowIso(), target.id, target.userId);
  if (res.changes !== 1) {
    return c.json({ error: "not_pending", status: target.status }, 409);
  }

  await auditEvent({
    userId: target.userId,
    requestId: target.kind === "proxy" ? target.id : undefined,
    actorType: "session",
    actorId: sessionId,
    eventType: eventName(target.kind, "denied"),
    event: { target_id: target.id },
  });

  return c.json({ ok: true, message: "Denied." });
});

approveRouter.post("/:kind/:id", requireSessionJson, async (c) => {
  const parsed = ApproveSchema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return c.json({ error: "invalid_request" }, 400);
  const body = parsed.data;

  const resolved = await resolveTarget(c);
  if (!resolved.ok) return c.json({ error: resolved.error }, 404);
  const target = resolved.target;

  const challenge = await consumeChallenge({
    nonce: body.nonce,
    userId: target.userId,
    purpose: "approve",
  });
  if (
    !challenge ||
    challenge.target_kind !== target.kind ||
    challenge.target_id !== target.id
  ) {
    return c.json({ error: "invalid_challenge" }, 400);
  }
  const options = parseOptions(
    target,
    JSON.parse(challenge.options_json ?? "null")
  );
  if (!options) return c.json({ error: "invalid_challenge" }, 400);

  // Recompute: the signed challenge must still describe this exact request.
  const expectedChallenge = await approvalChallenge({
    kind: target.kind,
    id: target.id,
    requestHash: target.requestHash,
    options,
    nonce: body.nonce,
  });
  if (expectedChallenge !== challenge.challenge) {
    return c.json({ error: "request_changed" }, 409);
  }

  const assertion = body.assertion as unknown as AuthenticationResponseJSON;
  const verified = await verifyPasskeyAssertion({
    userId: target.userId,
    response: assertion,
    expectedChallenge,
  });
  if (!verified) return c.json({ error: "passkey_verification_failed" }, 403);

  if (target.status !== "PENDING_APPROVAL") {
    return c.json({ error: "not_pending", status: target.status }, 409);
  }
  if (isExpired(target)) {
    await markExpired(target);
    return c.json({ error: "approval_expired" }, 408);
  }

  const account = target.credentialProvider
    ? await getActiveLinkedAccount({
        userId: target.userId,
        provider: target.credentialProvider,
      })
    : null;

  // A release needs its credential: without one there is nothing to sign with.
  if (target.kind === "release" && !account) {
    return c.json(
      {
        error: "no_linked_apple_release",
        message: "Link an Apple release credential first.",
      },
      409
    );
  }
  const releaseExpiresAt = new Date(
    Date.now() + RELEASE_SESSION_MAX_MS
  ).toISOString();

  let grantId: string | null = null;
  let windowId: string | null = null;
  let windowExpiresAt: string | null = null;

  const proxyWindow =
    target.kind === "proxy" && "mode" in options && options.mode === "window"
      ? options
      : null;
  if (proxyWindow) {
    windowId = ulid();
    windowExpiresAt = new Date(
      Date.now() + proxyWindow.minutes * 60_000
    ).toISOString();
  }

  if (account) {
    if (!body.dek) {
      return c.json(
        { error: "missing_key", message: "approval key is required" },
        400
      );
    }
    // Only kinds with a credential reach here (release policies have none).
    const targetKind = (windowId ? "window" : target.kind) as GrantTargetKind;
    const grantExpiresAt =
      windowExpiresAt ??
      (target.kind === "proxy"
        ? target.approvalExpiresAt
        : target.kind === "release"
          ? releaseExpiresAt
          : new Date(Date.now() + SESSION_GRANT_MAX_MS).toISOString());
    try {
      ({ grantId } = await createGrant({
        userId: target.userId,
        linkedAccountId: account.id,
        targetKind,
        targetId: windowId ?? target.id,
        dek: fromBase64Url(body.dek),
        expiresAt: grantExpiresAt,
      }));
    } catch (err) {
      if (err instanceof CredentialError) {
        return c.json(
          { error: err.code.toLowerCase(), message: err.message },
          400
        );
      }
      throw err;
    }
  }

  const database = await db();
  const now = nowIso();
  let changes = 0;
  if (target.kind === "proxy") {
    const res = await database
      .query(
        "UPDATE proxy_requests SET status = 'APPROVED', grant_id = ?, updated_at = ?, error_code = NULL, error_message = NULL WHERE id = ? AND status = 'PENDING_APPROVAL';"
      )
      .run(grantId, now, target.id);
    changes = res.changes ?? 0;
  } else if (target.kind === "git") {
    const allowDefault =
      "allow_default_branch_push" in options &&
      options.allow_default_branch_push;
    const res = await database
      .query(
        "UPDATE git_sessions SET status = 'APPROVED', allow_default_branch_push = ?, updated_at = ? WHERE id = ? AND status = 'PENDING_APPROVAL';"
      )
      .run(allowDefault ? 1 : 0, now, target.id);
    changes = res.changes ?? 0;
  } else if (target.kind === "release") {
    changes = (await setReleaseSessionStatus({
      id: target.id,
      from: ["PENDING_APPROVAL"],
      status: "APPROVED",
      expiresAt: releaseExpiresAt,
    }))
      ? 1
      : 0;
  } else if (target.kind === "release_policy") {
    changes = (await activateReleasePolicy({
      id: target.id,
      userId: target.userId,
    }))
      ? 1
      : 0;
  } else {
    const res = await database
      .query(
        "UPDATE email_sessions SET status = 'APPROVED', updated_at = ? WHERE id = ? AND status = 'PENDING_APPROVAL';"
      )
      .run(now, target.id);
    changes = res.changes ?? 0;
  }

  if (changes !== 1) {
    if (grantId) await deleteGrant(grantId);
    return c.json({ error: "not_pending" }, 409);
  }

  if (
    windowId &&
    windowExpiresAt &&
    target.requesterIp &&
    target.upstreamUrl &&
    target.method
  ) {
    await createApprovalWindow({
      windowId,
      userId: target.userId,
      apiKeyId: target.apiKeyId,
      requesterIp: target.requesterIp,
      method: target.method,
      url: new URL(target.upstreamUrl),
      scope: proxyWindow?.scope ?? "endpoint",
      providerId: target.credentialProvider,
      grantId,
      expiresAt: windowExpiresAt,
    });
  }

  await auditEvent({
    userId: target.userId,
    requestId: target.kind === "proxy" ? target.id : undefined,
    actorType: "passkey",
    actorId: assertion.id,
    eventType: eventName(target.kind, "approved"),
    event: {
      target_id: target.id,
      request_hash: target.requestHash,
      options,
      nonce: body.nonce,
      approval_window_id: windowId,
      approval_window_expires_at: windowExpiresAt,
      // Signed approval: verifiable later against the stored passkey public key.
      assertion: assertion.response,
    },
  });

  const message = windowExpiresAt
    ? proxyWindow?.scope === "provider"
      ? `Approved. All ${target.credentialProvider} requests from this API key are auto-approved until ${windowExpiresAt}.`
      : `Approved. Matching requests are auto-approved until ${windowExpiresAt}.`
    : "Approved.";
  return c.json({ ok: true, message });
});
