import { ulid } from "ulid";
import { z } from "zod";

import { db } from "../db/client";
import { env } from "../env";
import { sendWebPush, type VapidKeys } from "./webpush";

// The broker POSTs to subscription endpoints, so only accept the browser push
// services (no arbitrary URLs).
const PUSH_SERVICE_HOSTS = [
  "web.push.apple.com",
  "fcm.googleapis.com",
  "updates.push.services.mozilla.com",
];
const PUSH_SERVICE_HOST_SUFFIXES = [".notify.windows.com"];

export function isAllowedPushEndpoint(endpoint: string): boolean {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    return false;
  }
  if (url.protocol !== "https:" || url.port !== "") return false;
  return (
    PUSH_SERVICE_HOSTS.includes(url.hostname) ||
    PUSH_SERVICE_HOST_SUFFIXES.some((s) => url.hostname.endsWith(s))
  );
}

export const PushSubscriptionSchema = z.object({
  endpoint: z.string().url().max(2048).refine(isAllowedPushEndpoint, {
    message: "unsupported push service",
  }),
  keys: z.object({
    p256dh: z.string().regex(/^[A-Za-z0-9_-]{86,88}$/),
    auth: z.string().regex(/^[A-Za-z0-9_-]{21,24}$/),
  }),
});

export type PushNotification = {
  title: string;
  body: string;
  // Same-origin path opened when the notification is tapped.
  url: string;
  // Notifications with the same tag replace each other on the device.
  tag?: string;
};

export function vapidKeys(): VapidKeys | null {
  if (!env.VAPID_PUBLIC_KEY || !env.VAPID_PRIVATE_KEY || !env.VAPID_SUBJECT) {
    return null;
  }
  return {
    publicKey: env.VAPID_PUBLIC_KEY,
    privateKey: env.VAPID_PRIVATE_KEY,
    subject: env.VAPID_SUBJECT,
  };
}

function nowIso(): string {
  return new Date().toISOString();
}

export async function savePushSubscription(params: {
  userId: string;
  subscription: z.infer<typeof PushSubscriptionSchema>;
  userAgent: string | null;
}): Promise<void> {
  const database = await db();
  // An endpoint belongs to one browser; re-subscribing moves it to this user.
  await database
    .query(
      "INSERT INTO push_subscriptions (id, user_id, endpoint, p256dh, auth, user_agent, created_at, last_success_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL) " +
        "ON CONFLICT(endpoint) DO UPDATE SET user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth, user_agent = excluded.user_agent, created_at = excluded.created_at;"
    )
    .run(
      ulid(),
      params.userId,
      params.subscription.endpoint,
      params.subscription.keys.p256dh,
      params.subscription.keys.auth,
      params.userAgent?.slice(0, 300) ?? null,
      nowIso()
    );
}

export async function deletePushSubscription(params: {
  userId: string;
  endpoint?: string;
  id?: string;
}): Promise<void> {
  const database = await db();
  if (params.id) {
    await database
      .query("DELETE FROM push_subscriptions WHERE id = ? AND user_id = ?;")
      .run(params.id, params.userId);
  }
  if (params.endpoint) {
    await database
      .query(
        "DELETE FROM push_subscriptions WHERE endpoint = ? AND user_id = ?;"
      )
      .run(params.endpoint, params.userId);
  }
}

// Best-effort fan-out to every device of the user. Never throws: the request
// that triggered it is already persisted and visible in the PWA inbox.
export async function notifyUser(params: {
  userId: string;
  notification: PushNotification;
  ttlSeconds: number;
  urgency?: "low" | "normal" | "high";
}): Promise<{ sent: number; failed: number }> {
  let sent = 0;
  let failed = 0;
  try {
    const vapid = vapidKeys();
    if (!vapid) {
      console.error("push not sent: VAPID keys are not configured");
      return { sent, failed };
    }
    const database = await db();
    const subs = await database
      .query(
        "SELECT id, endpoint, p256dh, auth FROM push_subscriptions WHERE user_id = ?;"
      )
      .all<{ id: string; endpoint: string; p256dh: string; auth: string }>(
        params.userId
      );

    const payload = {
      ...params.notification,
      body: params.notification.body.slice(0, 1000),
    };
    await Promise.all(
      subs.map(async (sub) => {
        try {
          const res = await sendWebPush({
            subscription: sub,
            payload,
            vapid,
            ttlSeconds: params.ttlSeconds,
            urgency: params.urgency,
            topic: params.notification.tag?.replace(/[^A-Za-z0-9_-]/g, "_"),
          });
          if (res.ok) {
            sent++;
            await database
              .query(
                "UPDATE push_subscriptions SET last_success_at = ? WHERE id = ?;"
              )
              .run(nowIso(), sub.id);
            return;
          }
          failed++;
          if (res.gone) {
            await database
              .query("DELETE FROM push_subscriptions WHERE id = ?;")
              .run(sub.id);
          }
          console.error(
            `push failed (${new URL(sub.endpoint).hostname} ${res.status}): ${res.message}`
          );
        } catch (err) {
          failed++;
          console.error(
            `push failed (${new URL(sub.endpoint).hostname}): ${err instanceof Error ? err.message : String(err)}`
          );
        }
      })
    );
  } catch (err) {
    console.error(
      `push fan-out failed: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  return { sent, failed };
}
