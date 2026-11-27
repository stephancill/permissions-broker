import type { Context } from "hono";

import { randomBase64Url } from "../crypto/random";
import { CLIENT_CRYPTO_JS } from "../passkey/clientCrypto";

export function escapeHtml(s: string): string {
  return s
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

// JSON for embedding inside <script>; escapes "<" so data can't close the tag.
export function scriptJson(value: unknown): string {
  return JSON.stringify(value).replace(/</g, "\\u003c");
}

const STYLE = `
  :root { color-scheme: light dark; }
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 16px; padding-top: max(16px, env(safe-area-inset-top)); padding-bottom: max(16px, env(safe-area-inset-bottom)); max-width: 720px; margin: 0 auto; }
  h1 { font-size: 20px; margin: 8px 0 12px; }
  h2 { font-size: 16px; margin: 20px 0 8px; }
  p, li { line-height: 1.4; }
  header.app { padding: 8px 0 16px; }
  header.app a { font-size: 22px; font-weight: 700; color: inherit; text-decoration: none; }
  nav { display: flex; gap: 16px; flex-wrap: wrap; padding: 6px 0 10px; border-bottom: 1px solid #8884; }
  nav a[aria-current] { font-weight: 600; }
  button { display: block; width: 100%; margin-top: 12px; padding: 12px 14px; font-size: 16px; }
  form.inline { display: inline; }
  form.inline button { display: inline; width: auto; margin: 4px 8px 4px 0; padding: 6px 10px; font-size: 14px; }
  input[type=text], input[type=password], input[type=email], input[type=number] { display: block; width: 100%; box-sizing: border-box; margin-top: 4px; padding: 10px; font-size: 16px; }
  label { display: block; margin: 8px 0; }
  ul.list { list-style: none; padding: 0; margin: 0; }
  ul.list > li { padding: 10px 0; border-bottom: 1px solid #8884; }
  pre { background: #8882; padding: 8px; white-space: pre-wrap; word-break: break-all; }
  code { background: #8882; padding: 2px 4px; word-break: break-all; }
  .note { font-size: 13px; opacity: 0.8; }
  .error { color: #c00; }
  .ok { color: #080; }
  [hidden] { display: none; }
`;

const NAV_ITEMS = [
  ["/app", "Requests"],
  ["/app/keys", "API keys"],
  ["/app/accounts", "Accounts"],
  ["/app/settings", "Settings"],
] as const;

export type NavItem = (typeof NAV_ITEMS)[number][0];

// App title above the nav row: also pushes the nav down from the top edge
// so it's easier to reach on a phone.
function renderNav(current: NavItem | undefined): string {
  return `<header class="app"><a href="/app">stupid vault</a></header><nav>${NAV_ITEMS.map(
    ([href, label]) =>
      `<a href="${href}"${href === current ? ' aria-current="page"' : ""}>${label}</a>`
  ).join("")}</nav>`;
}

// Tapping a push notification while the app is open: the service worker
// posts the target URL (Safari can't navigate a window from the worker).
const OPEN_FROM_NOTIFICATION_SCRIPT = `
  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.addEventListener("message", function (e) {
      var d = e.data;
      if (!d || d.type !== "pb-open" || typeof d.url !== "string") return;
      try {
        var u = new URL(d.url, location.origin);
        if (u.origin === location.origin && u.href !== location.href) location.assign(u.href);
      } catch (err) { /* ignore malformed */ }
    });
  }
`;

// Every page is part of the installable PWA. Pages touching key material use
// inline-only scripts gated by a per-response nonce, no third-party origins,
// and same-origin fetches/forms only.
export function sendPage(
  c: Context,
  params: {
    title: string;
    body: string;
    script?: string;
    // Include the passkey/crypto helpers (window.PB).
    crypto?: boolean;
    nav?: NavItem | null;
    status?: number;
  }
): Response {
  const nonce = randomBase64Url(16);
  c.header(
    "Content-Security-Policy",
    `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; img-src 'self'; manifest-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`
  );
  // same-origin (not no-referrer) so form POSTs carry our Origin, which the
  // session middleware checks; nothing leaks to other origins.
  c.header("Referrer-Policy", "same-origin");
  c.header("Cache-Control", "no-store");

  const scripts = [
    OPEN_FROM_NOTIFICATION_SCRIPT,
    params.crypto ? CLIENT_CRYPTO_JS : "",
    params.script ?? "",
  ]
    .filter(Boolean)
    .map((s) => `<script nonce="${nonce}">${s}</script>`)
    .join("\n    ");

  const nav = params.nav === null ? "" : renderNav(params.nav);

  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover" />
    <meta name="apple-mobile-web-app-capable" content="yes" />
    <meta name="apple-mobile-web-app-title" content="stupid vault" />
    <meta name="theme-color" content="#ffffff" />
    <link rel="manifest" href="/manifest.webmanifest" />
    <link rel="icon" href="/favicon.png" type="image/png" />
    <link rel="apple-touch-icon" href="/apple-touch-icon.png" />
    <title>${escapeHtml(params.title)}</title>
    <style nonce="${nonce}">${STYLE}</style>
  </head>
  <body>
    ${nav}
    ${params.body}
    ${scripts}
  </body>
</html>`;

  return c.html(html, (params.status ?? 200) as 200);
}

export function sendMessagePage(
  c: Context,
  params: {
    title: string;
    message: string;
    status?: number;
    nav?: NavItem | null;
  }
): Response {
  return sendPage(c, {
    title: params.title,
    status: params.status,
    nav: params.nav,
    body: `<h1>${escapeHtml(params.title)}</h1><p>${escapeHtml(params.message)}</p><p><a href="/app">Back to the app</a></p>`,
  });
}

// Shared browser helper for JSON POSTs from our pages.
export const POST_JSON_SCRIPT = `
  async function postJson(path, body) {
    var res = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(body || {}),
    });
    var json = await res.json().catch(function () { return {}; });
    if (!res.ok) throw new Error(json.message || json.error || ("HTTP " + res.status));
    return json;
  }
  function errorText(e) { return e && e.message ? e.message : String(e); }
`;
