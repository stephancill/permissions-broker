import type { Context, MiddlewareHandler } from "hono";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { ulid } from "ulid";

import { randomBase64Url } from "../crypto/random";
import { sha256Hex } from "../crypto/sha256";
import { db } from "../db/client";
import { env } from "../env";

// Sessions are created by a passkey sign-in and slide forward on use. They
// gate the PWA (inbox, keys, accounts, deny); approvals still need a fresh
// passkey assertion on top.
export const SESSION_COOKIE = "pb_session";
const SESSION_TTL_MS = 30 * 24 * 60 * 60_000;
// Avoid a DB write on every request.
const SESSION_TOUCH_INTERVAL_MS = 60 * 60_000;

export type WebSession = {
  sessionId: string;
  userId: string;
};

declare module "hono" {
  interface ContextVariableMap {
    webSession: WebSession;
  }
}

function nowIso(): string {
  return new Date().toISOString();
}

function isSecureOrigin(): boolean {
  return env.APP_BASE_URL?.startsWith("https://") ?? false;
}

export async function createWebSession(params: {
  c: Context;
  userId: string;
}): Promise<WebSession> {
  const token = randomBase64Url(32);
  const id = ulid();
  const now = Date.now();
  const database = await db();
  await database
    .query(
      "INSERT INTO web_sessions (id, user_id, token_hash, created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?);"
    )
    .run(
      id,
      params.userId,
      await sha256Hex(token),
      new Date(now).toISOString(),
      new Date(now).toISOString(),
      new Date(now + SESSION_TTL_MS).toISOString()
    );

  setCookie(params.c, SESSION_COOKIE, token, {
    httpOnly: true,
    secure: isSecureOrigin(),
    sameSite: "Lax",
    path: "/",
    maxAge: Math.floor(SESSION_TTL_MS / 1000),
  });
  return { sessionId: id, userId: params.userId };
}

export async function getWebSession(c: Context): Promise<WebSession | null> {
  const token = getCookie(c, SESSION_COOKIE);
  if (!token) return null;

  const database = await db();
  const row = (await database
    .query(
      "SELECT s.id, s.user_id, s.last_seen_at, s.expires_at FROM web_sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ? AND u.status = 'active' LIMIT 1;"
    )
    .get(await sha256Hex(token))) as {
    id: string;
    user_id: string;
    last_seen_at: string;
    expires_at: string;
  } | null;
  if (!row) return null;

  const now = Date.now();
  if (now > Date.parse(row.expires_at)) return null;

  if (now - Date.parse(row.last_seen_at) > SESSION_TOUCH_INTERVAL_MS) {
    await database
      .query(
        "UPDATE web_sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?;"
      )
      .run(
        new Date(now).toISOString(),
        new Date(now + SESSION_TTL_MS).toISOString(),
        row.id
      );
    setCookie(c, SESSION_COOKIE, token, {
      httpOnly: true,
      secure: isSecureOrigin(),
      sameSite: "Lax",
      path: "/",
      maxAge: Math.floor(SESSION_TTL_MS / 1000),
    });
  }

  return { sessionId: row.id, userId: row.user_id };
}

export async function endWebSession(c: Context): Promise<void> {
  const token = getCookie(c, SESSION_COOKIE);
  if (token) {
    const database = await db();
    await database
      .query("DELETE FROM web_sessions WHERE token_hash = ?;")
      .run(await sha256Hex(token));
  }
  deleteCookie(c, SESSION_COOKIE, { path: "/" });
}

// Cookie-authenticated writes must come from our own pages. SameSite=Lax
// already blocks cross-site POSTs; this is defense in depth.
function isSameOriginWrite(c: Context): boolean {
  const method = c.req.method.toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") {
    return true;
  }
  const origin = c.req.header("origin");
  if (origin && origin !== "null") {
    return (
      env.APP_BASE_URL != null && origin === new URL(env.APP_BASE_URL).origin
    );
  }
  // Some navigations send no (or a "null") Origin; Sec-Fetch-Site is set by
  // the browser and can't be forged by a page.
  return c.req.header("sec-fetch-site") === "same-origin";
}

export const requireSameOrigin: MiddlewareHandler = async (c, next) => {
  if (!isSameOriginWrite(c)) return c.json({ error: "bad_origin" }, 403);
  await next();
};

// JSON endpoints: 401 without a session.
export const requireSessionJson: MiddlewareHandler = async (c, next) => {
  if (!isSameOriginWrite(c)) return c.json({ error: "bad_origin" }, 403);
  const session = await getWebSession(c);
  if (!session) return c.json({ error: "not_signed_in" }, 401);
  c.set("webSession", session);
  await next();
};

// Pages: send the user to sign in, then back here.
export const requireSessionPage: MiddlewareHandler = async (c, next) => {
  if (!isSameOriginWrite(c)) return c.text("Bad origin", 403);
  const session = await getWebSession(c);
  if (!session) {
    const url = new URL(c.req.url);
    const back = `${url.pathname}${url.search}`;
    return c.redirect(`/app/signin?next=${encodeURIComponent(back)}`, 302);
  }
  c.set("webSession", session);
  await next();
};

export async function sweepWebSessions(): Promise<void> {
  const now = nowIso();
  const database = await db();
  await database
    .query("DELETE FROM web_sessions WHERE expires_at < ?;")
    .run(now);
  await database
    .query("DELETE FROM auth_challenges WHERE expires_at < ?;")
    .run(now);
}
