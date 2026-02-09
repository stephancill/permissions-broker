import { ulid } from "ulid";

import { db } from "../db/client";

function nowIso(): string {
  return new Date().toISOString();
}

export function auditEvent(params: {
  userId?: string;
  requestId?: string;
  actorType: "api_key" | "telegram" | "system";
  actorId: string;
  eventType: string;
  event: unknown;
}): void {
  const eventJson = JSON.stringify(params.event ?? {});
  db()
    .query(
      "INSERT INTO audit_events (id, created_at, user_id, request_id, actor_type, actor_id, event_type, event_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?);"
    )
    .run(
      ulid(),
      nowIso(),
      params.userId ?? null,
      params.requestId ?? null,
      params.actorType,
      params.actorId,
      params.eventType,
      eventJson
    );
}
