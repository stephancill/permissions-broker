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
  body { font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif; padding: 24px; max-width: 720px; margin: 0 auto; }
  h1 { font-size: 20px; margin: 0 0 12px; }
  p, li { color: #333; line-height: 1.4; }
  button { display: block; width: 100%; margin-top: 12px; padding: 12px 14px; font-size: 16px; }
  label { display: block; margin: 8px 0; }
  pre { background: #f3f3f3; padding: 8px; white-space: pre-wrap; word-break: break-all; }
  code { background: #f3f3f3; padding: 2px 4px; }
  .note { font-size: 13px; color: #444; }
  .error { color: #a00; }
  .ok { color: #060; }
  [hidden] { display: none; }
`;

// Pages that touch key material: inline-only scripts gated by a per-response
// nonce, no third-party origins, same-origin fetches only.
export function sendKeyPage(
  c: Context,
  params: { title: string; body: string; script?: string; status?: number }
): Response {
  const nonce = randomBase64Url(16);
  c.header(
    "Content-Security-Policy",
    `default-src 'none'; script-src 'nonce-${nonce}'; style-src 'nonce-${nonce}'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`
  );
  c.header("Referrer-Policy", "no-referrer");
  c.header("Cache-Control", "no-store");

  const scripts = params.script
    ? `<script nonce="${nonce}">${CLIENT_CRYPTO_JS}</script>
    <script nonce="${nonce}">${params.script}</script>`
    : "";

  const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(params.title)}</title>
    <style nonce="${nonce}">${STYLE}</style>
  </head>
  <body>
    ${params.body}
    ${scripts}
  </body>
</html>`;

  return c.html(html, (params.status ?? 200) as 200);
}

export function sendMessagePage(
  c: Context,
  params: { title: string; message: string; status?: number }
): Response {
  return sendKeyPage(c, {
    title: params.title,
    status: params.status,
    body: `<h1>${escapeHtml(params.title)}</h1><p>${escapeHtml(params.message)}</p>`,
  });
}

// Shown in place of passkey UI inside Telegram's in-app browser.
export const TELEGRAM_WEBVIEW_NOTICE = `
  <div id="tg-webview" hidden>
    <p class="error"><b>Open this page in Safari.</b> Telegram's in-app browser can't use passkeys.</p>
    <p>Tap <b>⋯</b> → <b>Open in Safari</b>, or copy the link:</p>
    <button id="copy-link" type="button">Copy link</button>
  </div>`;

export const TELEGRAM_WEBVIEW_SCRIPT = `
  function guardTelegramWebview(mainId) {
    if (!PB.isTelegramWebview()) return false;
    document.getElementById("tg-webview").hidden = false;
    document.getElementById(mainId).hidden = true;
    document.getElementById("copy-link").onclick = function () {
      navigator.clipboard.writeText(location.href).then(function () {
        document.getElementById("copy-link").textContent = "Copied";
      });
    };
    return true;
  }
`;
