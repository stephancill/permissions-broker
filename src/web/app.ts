import { type Context, Hono } from "hono";
import {
  ApiKeyError,
  ApiKeyLabelSchema,
  createApiKey,
  listApiKeys,
  renameApiKey,
  revokeApiKey,
  rotateApiKey,
} from "../auth/apiKeyAdmin";
import {
  getWebSession,
  requireSessionJson,
  requireSessionPage,
} from "../auth/session";
import {
  ConnectLinkError,
  createConnectUrl,
  disconnectProvider,
  isConnectableProvider,
  listConnectableProviders,
  listLinkedAccountsByProvider,
} from "../connect/links";
import { db } from "../db/client";
import {
  approvalPath,
  expectedRpId,
  getUserPasskey,
  legacyPasskeysExist,
  legacyRpId,
} from "../passkey/webauthn";
import {
  deletePushSubscription,
  notifyUser,
  PushSubscriptionSchema,
  savePushSubscription,
  vapidKeys,
} from "../push/notify";
import {
  createReleasePolicy,
  listReleasePolicies,
  removeReleasePolicy,
} from "../release/store";
import { escapeHtml, POST_JSON_SCRIPT, scriptJson, sendPage } from "./pages";
import { ENROLL_SCRIPT, isSignupAllowed, SIGNIN_SCRIPT } from "./passkey";

// The installable PWA: sign-in, request inbox, API keys, linked accounts and
// notification settings. Approvals themselves live under /approve.

export const appRouter = new Hono();

function fmtTime(iso: string | null): string {
  if (!iso) return "never";
  return `${iso.slice(0, 16).replace("T", " ")} UTC`;
}

// Only same-origin relative paths are valid post-sign-in destinations.
function safeNext(raw: string | undefined): string {
  if (!raw || !raw.startsWith("/") || raw.startsWith("//")) return "/app";
  return raw;
}

// --- Sign-in / sign-up ---

appRouter.get("/signin", async (c) => {
  const next = safeNext(c.req.query("next"));
  if (await getWebSession(c)) return c.redirect(next, 302);

  const signup = await isSignupAllowed();
  // While moving domains, passkeys from the previous domain still sign in
  // (Related Origin Requests); the browser needs that RP ID explicitly.
  const legacy = (await legacyPasskeysExist()) ? legacyRpId() : null;
  const body = `
    <h1>stupid vault</h1>
    <p>Sign in with the passkey that protects your linked accounts.</p>
    <button id="signin" type="button">Sign in with passkey</button>
    ${
      legacy
        ? `<button id="signin-legacy" type="button" data-rp-id="${escapeHtml(legacy)}">Sign in with your ${escapeHtml(legacy)} passkey</button>
      <p class="note">This app moved from ${escapeHtml(legacy)}. Use that button if your passkey was created there.</p>`
        : ""
    }
    ${
      signup
        ? `<h2>New here?</h2>
      <p class="note">Creating an account creates a passkey that encrypts every account you link. Save it in Apple Passwords (or another manager with passkey PRF support).</p>
      <button id="signup" type="button">Create account</button>`
        : ""
    }
    <p id="status"></p>`;

  const script = `
    ${POST_JSON_SCRIPT}
    ${SIGNIN_SCRIPT}
    ${ENROLL_SCRIPT}
    var NEXT = ${scriptJson(next)};
    var statusEl = document.getElementById("status");
    function setStatus(text, cls) { statusEl.textContent = text; statusEl.className = cls || ""; }
    function fail(e) { setStatus("Failed: " + errorText(e), "error"); }

    document.getElementById("signin").onclick = function () {
      setStatus("Confirm with your passkey…");
      signInWithPasskey().then(function () { location.replace(NEXT); }).catch(fail);
    };
    var legacyBtn = document.getElementById("signin-legacy");
    if (legacyBtn) legacyBtn.onclick = function () {
      setStatus("Confirm with your passkey…");
      signInWithPasskey(legacyBtn.dataset.rpId).then(function () { location.replace(NEXT); }).catch(fail);
    };
    var signupBtn = document.getElementById("signup");
    if (signupBtn) signupBtn.onclick = function () {
      (async function () {
        setStatus("Preparing…");
        var o = await postJson("/passkey/signup/options", {});
        var enrollment = await createPasskeyEnrollment(o, "new", setStatus);
        setStatus("Saving…");
        await postJson("/passkey/signup/verify", enrollment);
        location.replace("/app");
      })().catch(fail);
    };
  `;

  return sendPage(c, {
    title: "Sign in",
    body,
    script,
    crypto: true,
    nav: null,
  });
});

// --- Inbox ---

type InboxItem = {
  kind: "proxy" | "git" | "email" | "release" | "release_policy";
  id: string;
  status: string;
  created_at: string;
  approval_expires_at: string;
  label: string;
  summary: string;
};

async function loadInbox(userId: string): Promise<InboxItem[]> {
  const database = await db();
  const proxy = await database
    .query(
      "SELECT id, status, created_at, approval_expires_at, api_key_label_snapshot AS label, method, upstream_url FROM proxy_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT 30;"
    )
    .all<{
      id: string;
      status: string;
      created_at: string;
      approval_expires_at: string;
      label: string;
      method: string;
      upstream_url: string;
    }>(userId);
  const git = await database
    .query(
      "SELECT g.id, g.status, g.created_at, g.approval_expires_at, k.label, g.operation, g.repo_owner, g.repo_name FROM git_sessions g JOIN api_keys k ON k.id = g.api_key_id WHERE g.user_id = ? ORDER BY g.created_at DESC LIMIT 30;"
    )
    .all<{
      id: string;
      status: string;
      created_at: string;
      approval_expires_at: string;
      label: string;
      operation: string;
      repo_owner: string;
      repo_name: string;
    }>(userId);
  const email = await database
    .query(
      "SELECT e.id, e.status, e.created_at, e.approval_expires_at, k.label FROM email_sessions e JOIN api_keys k ON k.id = e.api_key_id WHERE e.user_id = ? ORDER BY e.created_at DESC LIMIT 30;"
    )
    .all<{
      id: string;
      status: string;
      created_at: string;
      approval_expires_at: string;
      label: string;
    }>(userId);

  const releases = await database
    .query(
      "SELECT id, status, created_at, approval_expires_at, repository, actor, bundle_ids_json, version, build_number FROM release_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 30;"
    )
    .all<{
      id: string;
      status: string;
      created_at: string;
      approval_expires_at: string;
      repository: string;
      actor: string;
      bundle_ids_json: string;
      version: string;
      build_number: string;
    }>(userId);

  const items: InboxItem[] = [
    ...releases.map((r) => ({
      kind: "release" as const,
      id: r.id,
      status: r.status,
      created_at: r.created_at,
      approval_expires_at: r.approval_expires_at,
      label: `${r.repository} (${r.actor})`,
      summary: `TestFlight ${(JSON.parse(r.bundle_ids_json) as string[])[0]} ${r.version} (${r.build_number})`,
    })),
    ...proxy.map((r) => {
      let where = r.upstream_url;
      try {
        const u = new URL(r.upstream_url);
        where = `${u.hostname}${u.pathname}`;
      } catch {
        // keep raw
      }
      return {
        kind: "proxy" as const,
        id: r.id,
        status: r.status,
        created_at: r.created_at,
        approval_expires_at: r.approval_expires_at,
        label: r.label,
        summary: `${r.method} ${where}`,
      };
    }),
    ...git.map((r) => ({
      kind: "git" as const,
      id: r.id,
      status: r.status,
      created_at: r.created_at,
      approval_expires_at: r.approval_expires_at,
      label: r.label,
      summary: `git ${r.operation} ${r.repo_owner}/${r.repo_name}`,
    })),
    ...email.map((r) => ({
      kind: "email" as const,
      id: r.id,
      status: r.status,
      created_at: r.created_at,
      approval_expires_at: r.approval_expires_at,
      label: r.label,
      summary: "email read session (read-only)",
    })),
  ];
  return items.sort((a, b) => b.created_at.localeCompare(a.created_at));
}

function isActionable(item: InboxItem): boolean {
  return (
    item.status === "PENDING_APPROVAL" &&
    Date.parse(item.approval_expires_at) > Date.now()
  );
}

function renderInboxItem(item: InboxItem): string {
  const text = `<b>${escapeHtml(item.label)}</b>: ${escapeHtml(item.summary)}`;
  const meta = `<div class="note">${fmtTime(item.created_at)}${
    isActionable(item) ? "" : ` · ${escapeHtml(item.status)}`
  }</div>`;
  return isActionable(item)
    ? `<li><a href="${approvalPath(item)}">${text}</a>${meta}</li>`
    : `<li>${text}${meta}</li>`;
}

// Notification enablement. iOS only exposes Web Push to home-screen apps and
// requires the permission prompt to come from a tap.
const PUSH_SCRIPT = `
  var VAPID_KEY = window.PB_VAPID_KEY;
  var pushEl = document.getElementById("push");
  var pushStatus = document.getElementById("push-status");
  var pushBtn = document.getElementById("push-enable");

  function setPush(text, showButton) {
    pushStatus.textContent = text;
    pushBtn.hidden = !showButton;
  }

  function urlB64ToBytes(s) {
    var b64 = s.replace(/-/g, "+").replace(/_/g, "/");
    while (b64.length % 4) b64 += "=";
    var bin = atob(b64);
    var out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function syncSubscription(sub) {
    await postJson("/app/push/subscribe", sub.toJSON());
  }

  async function initPush() {
    if (!pushEl) return;
    var standalone = window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
    if (!("serviceWorker" in navigator) || !("PushManager" in window) || !("Notification" in window)) {
      setPush(standalone
        ? "This browser doesn't support push notifications."
        : "To get notifications on iPhone, tap Share → Add to Home Screen, then open the app from your home screen.", false);
      return;
    }
    if (!VAPID_KEY) { setPush("Push isn't configured on the server.", false); return; }
    var reg = await navigator.serviceWorker.register("/sw.js");
    await navigator.serviceWorker.ready;
    var sub = await reg.pushManager.getSubscription();
    if (sub && Notification.permission === "granted") {
      await syncSubscription(sub);
      pushEl.hidden = !pushEl.dataset.always;
      setPush("Notifications are on for this device.", false);
      return;
    }
    if (Notification.permission === "denied") {
      setPush("Notifications are blocked. Allow them in Settings → Notifications.", false);
      return;
    }
    setPush("Get a notification when an agent asks for access.", true);
    pushBtn.onclick = function () {
      (async function () {
        var perm = await Notification.requestPermission();
        if (perm !== "granted") { setPush("Notifications were not allowed.", false); return; }
        var s = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlB64ToBytes(VAPID_KEY) });
        await syncSubscription(s);
        setPush("Notifications are on for this device.", false);
      })().catch(function (e) { setPush("Failed: " + errorText(e), true); });
    };
  }

  initPush().catch(function (e) { setPush("Notifications unavailable: " + errorText(e), false); });
`;

function pushSection(always: boolean): string {
  return `<section id="push"${always ? ' data-always="1"' : ""}>
    <h2>Notifications</h2>
    <p id="push-status">Checking…</p>
    <button id="push-enable" type="button" hidden>Enable notifications</button>
  </section>`;
}

function vapidKeyScript(): string {
  return `window.PB_VAPID_KEY = ${scriptJson(vapidKeys()?.publicKey ?? null)};`;
}

// Shown until a passkey from the previous domain has been moved.
async function movePasskeyNotice(userId: string): Promise<string> {
  const passkey = await getUserPasskey(userId);
  if (!passkey || passkey.rp_id === expectedRpId()) return "";
  return `<p class="error">Your passkey still belongs to ${escapeHtml(passkey.rp_id)}. <a href="/passkey/enroll">Move it to ${escapeHtml(expectedRpId())}</a> before the old domain is retired.</p>`;
}

appRouter.get("/", requireSessionPage, async (c) => {
  const { userId } = c.get("webSession");
  const items = await loadInbox(userId);
  const pending = items.filter(isActionable);
  const recent = items.filter((i) => !isActionable(i)).slice(0, 20);

  const body = `
    ${await movePasskeyNotice(userId)}
    ${pushSection(false)}
    <h1>Pending</h1>
    ${
      pending.length
        ? `<ul class="list">${pending.map(renderInboxItem).join("")}</ul>`
        : "<p>Nothing waiting for approval.</p>"
    }
    <h2>Recent</h2>
    ${
      recent.length
        ? `<ul class="list">${recent.map(renderInboxItem).join("")}</ul>`
        : '<p class="note">No requests yet. Create an API key for your agent under API keys.</p>'
    }`;

  const script = `
    ${vapidKeyScript()}
    ${POST_JSON_SCRIPT}
    ${PUSH_SCRIPT}
    // Refresh the inbox when the app comes back to the foreground.
    var hiddenAt = 0;
    document.addEventListener("visibilitychange", function () {
      if (document.hidden) { hiddenAt = Date.now(); return; }
      if (hiddenAt && Date.now() - hiddenAt > 2000) location.reload();
    });
  `;

  return sendPage(c, { title: "Requests", body, script, nav: "/app" });
});

// --- API keys ---

function renderKeysPage(
  c: Context,
  params: {
    keys: Awaited<ReturnType<typeof listApiKeys>>;
    created?: { label: string; keyPlain: string };
    error?: string;
  }
): Response {
  const created = params.created
    ? `<section>
        <h2>New key for ${escapeHtml(params.created.label)}</h2>
        <p>Copy it now; it won't be shown again.</p>
        <pre id="new-key">${escapeHtml(params.created.keyPlain)}</pre>
        <button id="copy-key" type="button">Copy key</button>
      </section>`
    : "";
  const error = params.error
    ? `<p class="error">${escapeHtml(params.error)}</p>`
    : "";

  const rows = params.keys
    .map((k) => {
      const id = escapeHtml(k.id);
      const actions = k.revoked_at
        ? ""
        : `<details><summary>Manage</summary>
            <form method="post" action="/app/keys/${id}/rename">
              <label>New label <input type="text" name="label" value="${escapeHtml(k.label)}" maxlength="64" required /></label>
              <button type="submit">Rename</button>
            </form>
            <form method="post" action="/app/keys/${id}/rotate" data-confirm="Rotate this key? The current key stops working immediately.">
              <button type="submit">Rotate</button>
            </form>
            <form method="post" action="/app/keys/${id}/revoke" data-confirm="Revoke this key? Agents using it lose access.">
              <button type="submit">Revoke</button>
            </form>
          </details>`;
      return `<li><b>${escapeHtml(k.label)}</b>${k.revoked_at ? " (revoked)" : ""}
        <div class="note">Created ${fmtTime(k.created_at)} · last used ${fmtTime(k.last_used_at)}</div>
        ${actions}</li>`;
    })
    .join("");

  const body = `
    <h1>API keys</h1>
    <p class="note">Agents authenticate with an API key. Its label is what you'll see on approval requests.</p>
    ${error}
    ${created}
    <form method="post" action="/app/keys">
      <label>Label <input type="text" name="label" placeholder="e.g. laptop agent" maxlength="64" required /></label>
      <button type="submit">Create API key</button>
    </form>
    <h2>Your keys</h2>
    ${rows ? `<ul class="list">${rows}</ul>` : "<p>No API keys yet.</p>"}`;

  const script = `
    document.querySelectorAll("form[data-confirm]").forEach(function (f) {
      f.addEventListener("submit", function (e) {
        if (!confirm(f.dataset.confirm)) e.preventDefault();
      });
    });
    var copyBtn = document.getElementById("copy-key");
    if (copyBtn) copyBtn.onclick = function () {
      navigator.clipboard.writeText(document.getElementById("new-key").textContent).then(function () {
        copyBtn.textContent = "Copied";
      });
    };
  `;

  return sendPage(c, {
    title: "API keys",
    body,
    script,
    nav: "/app/keys",
    status: params.error ? 400 : 200,
  });
}

async function formLabel(c: Context): Promise<string | null> {
  const form = await c.req.parseBody();
  const parsed = ApiKeyLabelSchema.safeParse(
    typeof form.label === "string" ? form.label : ""
  );
  return parsed.success ? parsed.data : null;
}

appRouter.get("/keys", requireSessionPage, async (c) => {
  const { userId } = c.get("webSession");
  return renderKeysPage(c, { keys: await listApiKeys(userId) });
});

appRouter.post("/keys", requireSessionPage, async (c) => {
  const { userId, sessionId } = c.get("webSession");
  const label = await formLabel(c);
  if (!label) {
    return renderKeysPage(c, {
      keys: await listApiKeys(userId),
      error: "Enter a label (up to 64 characters).",
    });
  }
  try {
    const created = await createApiKey({ userId, sessionId, label });
    return renderKeysPage(c, {
      keys: await listApiKeys(userId),
      created: { label, keyPlain: created.keyPlain },
    });
  } catch (err) {
    if (!(err instanceof ApiKeyError)) throw err;
    return renderKeysPage(c, {
      keys: await listApiKeys(userId),
      error: err.message,
    });
  }
});

appRouter.post("/keys/:id/:action", requireSessionPage, async (c) => {
  const { userId, sessionId } = c.get("webSession");
  const apiKeyId = c.req.param("id");
  const action = c.req.param("action");
  try {
    if (action === "rename") {
      const label = await formLabel(c);
      if (!label) throw new ApiKeyError("Enter a label (up to 64 characters).");
      await renameApiKey({ userId, sessionId, apiKeyId, label });
    } else if (action === "revoke") {
      await revokeApiKey({ userId, sessionId, apiKeyId });
    } else if (action === "rotate") {
      const created = await rotateApiKey({ userId, sessionId, apiKeyId });
      return renderKeysPage(c, {
        keys: await listApiKeys(userId),
        created: { label: created.label, keyPlain: created.keyPlain },
      });
    } else {
      return c.notFound();
    }
  } catch (err) {
    if (!(err instanceof ApiKeyError)) throw err;
    return renderKeysPage(c, {
      keys: await listApiKeys(userId),
      error: err.message,
    });
  }
  return c.redirect("/app/keys", 303);
});

// --- Releases (CI release policies) ---

const RELEASE_REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const RELEASE_WORKFLOW = /^\.github\/workflows\/[A-Za-z0-9_.-]+\.ya?ml$/;
const RELEASE_REF = /^refs\/(heads|tags)\/[A-Za-z0-9_./-]+$/;
const RELEASE_BUNDLE = /^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$/;

async function renderReleasesPage(
  c: Context,
  error?: string
): Promise<Response> {
  const { userId } = c.get("webSession");
  const policies = await listReleasePolicies(userId);
  const rows = policies
    .map((p) => {
      const bundles = (JSON.parse(p.bundle_ids_json) as string[]).join(", ");
      const pending = p.status === "PENDING_APPROVAL";
      const action = pending
        ? `<a href="${approvalPath({ kind: "release_policy", id: p.id })}">Confirm with passkey</a>`
        : "";
      return `<li><b>${escapeHtml(p.repository)}</b> · ${escapeHtml(p.workflow_path)} · ${escapeHtml(p.ref)}
        <div class="note">${escapeHtml(bundles)}${pending ? " · waiting for confirmation" : ""}</div>
        <div>${action}
          <form class="inline" method="post" action="/app/releases/${escapeHtml(p.id)}/remove" data-confirm="Remove this policy? The workflow can no longer ask for releases.">
            <button type="submit">Remove</button>
          </form>
        </div></li>`;
    })
    .join("");

  const body = `
    <h1>Releases</h1>
    <p class="note">A GitHub Actions workflow listed here can ask to sign and upload TestFlight builds of its bundles. It authenticates with GitHub's OIDC token, and each release still needs your approval. Link an apple-release account under Accounts first.</p>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <form method="post" action="/app/releases">
      <label>Repository <input type="text" name="repository" placeholder="owner/repo" required /></label>
      <label>Workflow file <input type="text" name="workflow_path" placeholder=".github/workflows/testflight.yml" required /></label>
      <label>Branch <input type="text" name="ref" value="refs/heads/main" required /></label>
      <label>Bundle IDs (app and extensions, one per line) <textarea name="bundle_ids" rows="3" required></textarea></label>
      <button type="submit">Add policy</button>
    </form>
    <h2>Policies</h2>
    ${rows ? `<ul class="list">${rows}</ul>` : "<p>No release policies yet.</p>"}`;

  const script = `
    document.querySelectorAll("form[data-confirm]").forEach(function (f) {
      f.addEventListener("submit", function (e) {
        if (!confirm(f.dataset.confirm)) e.preventDefault();
      });
    });
  `;
  return sendPage(c, { title: "Releases", body, script, nav: "/app/releases" });
}

appRouter.get("/releases", requireSessionPage, async (c) =>
  renderReleasesPage(c)
);

// Adding a policy widens what CI may do, so it is confirmed with the passkey
// on the approval page; removing one needs only the session.
appRouter.post("/releases", requireSessionPage, async (c) => {
  const { userId } = c.get("webSession");
  const form = await c.req.parseBody();
  const text = (name: string) => {
    const v = form[name];
    return typeof v === "string" ? v.trim() : "";
  };
  const repository = text("repository");
  const workflowPath = text("workflow_path");
  const ref = text("ref");
  const bundleIds = [
    ...new Set(
      text("bundle_ids")
        .split(/[\s,]+/)
        .map((b) => b.trim())
        .filter(Boolean)
    ),
  ];
  if (!RELEASE_REPOSITORY.test(repository)) {
    return renderReleasesPage(c, "Repository must be owner/repo.");
  }
  if (!RELEASE_WORKFLOW.test(workflowPath)) {
    return renderReleasesPage(
      c,
      "Workflow file must be .github/workflows/<name>.yml."
    );
  }
  if (!RELEASE_REF.test(ref)) {
    return renderReleasesPage(
      c,
      "Branch must be a full ref, e.g. refs/heads/main."
    );
  }
  if (
    bundleIds.length === 0 ||
    bundleIds.length > 10 ||
    !bundleIds.every((b) => RELEASE_BUNDLE.test(b))
  ) {
    return renderReleasesPage(
      c,
      "Enter one to ten exact bundle IDs (no wildcards)."
    );
  }
  const id = await createReleasePolicy({
    userId,
    repository,
    workflowPath,
    ref,
    bundleIds,
  });
  return c.redirect(approvalPath({ kind: "release_policy", id }), 303);
});

appRouter.post("/releases/:id/remove", requireSessionPage, async (c) => {
  const { userId } = c.get("webSession");
  await removeReleasePolicy({ id: c.req.param("id"), userId });
  return c.redirect("/app/releases", 303);
});

// --- Linked accounts ---

function describeMetadata(metadataJson: string | null): string {
  if (!metadataJson) return "";
  try {
    const m = JSON.parse(metadataJson) as {
      imap?: { email?: string; host?: string };
      cloudflare_accounts?: Array<{ id: string; name?: string }>;
    };
    if (m.imap?.email) return `${m.imap.email} (${m.imap.host ?? "?"})`;
    if (m.cloudflare_accounts?.length) {
      return m.cloudflare_accounts.map((a) => a.name ?? a.id).join(", ");
    }
  } catch {
    // ignore
  }
  return "";
}

appRouter.get("/accounts", requireSessionPage, async (c) => {
  const { userId } = c.get("webSession");
  const byProvider = await listLinkedAccountsByProvider(userId);
  const error = c.req.query("error");

  const rows = listConnectableProviders()
    .map((p) => {
      const r = byProvider.get(p);
      const active = r?.status === "active";
      const detail = active
        ? `<div class="note">Connected ${fmtTime(r.created_at)}${
            r.scopes ? ` · scopes: ${escapeHtml(r.scopes)}` : ""
          }${
            describeMetadata(r.metadata_json)
              ? ` · ${escapeHtml(describeMetadata(r.metadata_json))}`
              : ""
          }</div>`
        : `<div class="note">${r ? escapeHtml(r.status) : "Not connected"}</div>`;
      const actions = active
        ? `<a href="/app/accounts/connect/${p}">Reconnect</a>
           <form class="inline" method="post" action="/app/accounts/${p}/disconnect" data-confirm="Disconnect ${p}?">
             <button type="submit">Disconnect</button>
           </form>`
        : `<a href="/app/accounts/connect/${p}">Connect</a>`;
      return `<li><b>${escapeHtml(p)}</b>${detail}<div>${actions}</div></li>`;
    })
    .join("");

  const body = `
    <h1>Linked accounts</h1>
    <p class="note">Credentials are encrypted to your passkey. Agents can only use them after you approve a request.</p>
    ${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}
    <ul class="list">${rows}</ul>
    <p class="note">After connecting in the browser sheet, close it and pull down to refresh.</p>`;

  const script = `
    document.querySelectorAll("form[data-confirm]").forEach(function (f) {
      f.addEventListener("submit", function (e) {
        if (!confirm(f.dataset.confirm)) e.preventDefault();
      });
    });
  `;

  return sendPage(c, {
    title: "Accounts",
    body,
    script,
    nav: "/app/accounts",
  });
});

appRouter.get("/accounts/connect/:provider", requireSessionPage, async (c) => {
  const { userId } = c.get("webSession");
  const provider = c.req.param("provider");
  if (!isConnectableProvider(provider)) return c.notFound();
  try {
    return c.redirect(await createConnectUrl({ userId, provider }), 302);
  } catch (err) {
    if (!(err instanceof ConnectLinkError)) throw err;
    return c.redirect(
      `/app/accounts?error=${encodeURIComponent(err.message)}`,
      302
    );
  }
});

appRouter.post(
  "/accounts/:provider/disconnect",
  requireSessionPage,
  async (c) => {
    const { userId } = c.get("webSession");
    const provider = c.req.param("provider");
    if (!isConnectableProvider(provider)) return c.notFound();
    await disconnectProvider({ userId, provider });
    return c.redirect("/app/accounts", 303);
  }
);

// --- Settings ---

appRouter.get("/settings", requireSessionPage, async (c) => {
  const { userId } = c.get("webSession");
  const database = await db();
  const devices = await database
    .query(
      "SELECT id, endpoint, user_agent, created_at, last_success_at FROM push_subscriptions WHERE user_id = ? ORDER BY created_at DESC;"
    )
    .all<{
      id: string;
      endpoint: string;
      user_agent: string | null;
      created_at: string;
      last_success_at: string | null;
    }>(userId);

  const deviceRows = devices
    .map(
      (d) => `<li>${escapeHtml(new URL(d.endpoint).hostname)}
        <div class="note">${escapeHtml(d.user_agent ?? "unknown device")}</div>
        <div class="note">Added ${fmtTime(d.created_at)} · last delivered ${fmtTime(d.last_success_at)}</div>
        <form class="inline" method="post" action="/app/push/devices/${escapeHtml(d.id)}/remove"><button type="submit">Remove</button></form>
      </li>`
    )
    .join("");

  const body = `
    <h1>Settings</h1>
    ${await movePasskeyNotice(userId)}
    ${pushSection(true)}
    <h2>Notification devices</h2>
    ${deviceRows ? `<ul class="list">${deviceRows}</ul>` : "<p>No devices yet.</p>"}
    <button id="push-test" type="button">Send test notification</button>
    <p id="test-status" class="note"></p>
    <h2>Passkey</h2>
    <p><a href="/passkey/enroll">Replace passkey</a></p>
    <h2>Session</h2>
    <form method="post" action="/passkey/signout"><button type="submit">Sign out</button></form>`;

  const script = `
    ${vapidKeyScript()}
    ${POST_JSON_SCRIPT}
    ${PUSH_SCRIPT}
    document.getElementById("push-test").onclick = function () {
      var el = document.getElementById("test-status");
      el.textContent = "Sending…";
      postJson("/app/push/test", {}).then(function (r) {
        el.textContent = "Sent to " + r.sent + " device(s)" + (r.failed ? ", " + r.failed + " failed" : "") + ".";
      }).catch(function (e) { el.textContent = "Failed: " + errorText(e); });
    };
  `;

  return sendPage(c, {
    title: "Settings",
    body,
    script,
    nav: "/app/settings",
  });
});

// --- Push subscriptions ---

appRouter.post("/push/subscribe", requireSessionJson, async (c) => {
  const { userId } = c.get("webSession");
  const parsed = PushSubscriptionSchema.safeParse(
    await c.req.json().catch(() => null)
  );
  if (!parsed.success) {
    return c.json(
      {
        error: "invalid_subscription",
        message: parsed.error.issues[0]?.message,
      },
      400
    );
  }
  await savePushSubscription({
    userId,
    subscription: parsed.data,
    userAgent: c.req.header("user-agent") ?? null,
  });
  return c.json({ ok: true });
});

appRouter.post("/push/devices/:id/remove", requireSessionPage, async (c) => {
  const { userId } = c.get("webSession");
  await deletePushSubscription({ userId, id: c.req.param("id") });
  return c.redirect("/app/settings", 303);
});

appRouter.post("/push/test", requireSessionJson, async (c) => {
  const { userId } = c.get("webSession");
  if (!vapidKeys()) {
    return c.json(
      { error: "push_not_configured", message: "VAPID keys are not set." },
      503
    );
  }
  const res = await notifyUser({
    userId,
    notification: {
      title: "stupid vault",
      body: "Test notification. Approval requests will show up like this.",
      url: "/app",
      tag: "test",
    },
    ttlSeconds: 60,
  });
  return c.json(res);
});

// --- PWA plumbing ---

export const MANIFEST = {
  name: "stupid vault",
  short_name: "stupid vault",
  description: "Approve agent access requests with your passkey.",
  id: "/app",
  start_url: "/app",
  scope: "/",
  display: "standalone",
  background_color: "#ffffff",
  theme_color: "#ffffff",
  icons: [
    { src: "/icon-192.png", sizes: "192x192", type: "image/png" },
    { src: "/icon-512.png", sizes: "512x512", type: "image/png" },
    {
      src: "/icon-512.png",
      sizes: "512x512",
      type: "image/png",
      purpose: "maskable",
    },
  ],
};

// No fetch handler: the worker only shows pushes and routes taps.
export const SERVICE_WORKER_JS = `
self.addEventListener("install", function () { self.skipWaiting(); });
self.addEventListener("activate", function (event) { event.waitUntil(self.clients.claim()); });

self.addEventListener("push", function (event) {
  var data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) { data = {}; }
  // iOS revokes push permission if a push doesn't show a notification.
  event.waitUntil(self.registration.showNotification(data.title || "stupid vault", {
    body: data.body || "",
    tag: data.tag || undefined,
    icon: "/icon-192.png",
    data: { url: data.url || "/app" },
  }));
});

self.addEventListener("notificationclick", function (event) {
  event.notification.close();
  var target = new URL((event.notification.data && event.notification.data.url) || "/app", self.location.origin);
  if (target.origin !== self.location.origin) target = new URL("/app", self.location.origin);
  event.waitUntil((async function () {
    var windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (var i = 0; i < windows.length; i++) {
      var w = windows[i];
      try {
        await w.focus();
        await w.navigate(target.href);
        return;
      } catch (e) {
        // fall through to openWindow
      }
    }
    await self.clients.openWindow(target.href);
  })());
});
`;
