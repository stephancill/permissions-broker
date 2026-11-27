import { emailRouter } from "../web/email";
import {
  APPROVAL_WAIT_TEXT,
  callRoute,
  consentHintProperty,
  optionalString,
  pollUntil,
  readJson,
  requireString,
  type ToolArgs,
  type ToolContext,
  type ToolDefinition,
  ToolInputError,
  type ToolResult,
  text,
  truncateText,
  waitProperty,
  waitSeconds,
} from "./toolkit";

// Read-only email through /v1/email sessions. One passkey approval opens a
// short-lived session; folder, search and read calls then run without
// further prompts. The IMAP client is read-only by construction.

const READ_ONLY = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: true,
} as const;

const sessionIdProperty = {
  type: "string",
  description: "session_id returned by email_start_session.",
};

function optionalObject(
  args: ToolArgs,
  name: string
): Record<string, unknown> | undefined {
  const v = args[name];
  if (v == null) return undefined;
  if (typeof v !== "object" || Array.isArray(v)) {
    throw new ToolInputError(`${name} must be an object`);
  }
  return v as Record<string, unknown>;
}

function optionalInteger(args: ToolArgs, name: string): number | undefined {
  const v = args[name];
  if (v == null) return undefined;
  if (typeof v !== "number" || !Number.isInteger(v)) {
    throw new ToolInputError(`${name} must be an integer`);
  }
  return v;
}

function pendingResult(sessionId: string, status: unknown): ToolResult {
  return text({
    session_id: sessionId,
    status: status ?? "PENDING_APPROVAL",
    next_step: `${APPROVAL_WAIT_TEXT} Tell the user, then call email_session_status (or retry the same email tool) with this session_id.`,
  });
}

async function awaitSession(
  ctx: ToolContext,
  sessionId: string,
  waitMs: number
): Promise<ToolResult> {
  const id = encodeURIComponent(sessionId);
  let last: unknown;
  return pollUntil(
    waitMs,
    async () => {
      const res = await callRoute(emailRouter, ctx, `/sessions/${id}`);
      const json = await readJson(res);
      if (!res.ok) return text({ session_id: sessionId, ...json }, true);
      last = json.status;
      if (json.status === "PENDING_APPROVAL") return null;
      if (json.status === "APPROVED" || json.status === "ACTIVE") {
        return text({
          ...json,
          next_step:
            "Approved. Use email_list_folders, email_search and email_read with this session_id; the session expires after a few minutes without use.",
        });
      }
      const message =
        json.status === "DENIED"
          ? "The user denied email access."
          : "The session is no longer usable. Start a new one if still needed.";
      return text({ ...json, message }, true);
    },
    () => pendingResult(sessionId, last)
  );
}

// Runs an email operation, waiting while the session is still pending.
async function emailOp(
  ctx: ToolContext,
  args: ToolArgs,
  op: { path: string; method: "GET" | "POST"; body?: unknown }
): Promise<ToolResult> {
  const sessionId = requireString(args, "session_id", 64);
  const id = encodeURIComponent(sessionId);
  return pollUntil(
    waitSeconds(args) * 1000,
    async () => {
      const res = await callRoute(
        emailRouter,
        ctx,
        `/sessions/${id}${op.path}`,
        {
          method: op.method,
          body: op.body,
        }
      );
      if (res.status === 202) return null;
      const json = await readJson(res);
      if (!res.ok) return text({ session_id: sessionId, ...json }, true);
      return text(
        truncateText(
          JSON.stringify(json, null, 2),
          "narrow the search or read fewer parts"
        )
      );
    },
    () => pendingResult(sessionId, "PENDING_APPROVAL")
  );
}

export const EMAIL_TOOLS: ToolDefinition[] = [
  {
    name: "email_start_session",
    title: "Request email access",
    description:
      "Asks the user to approve a short-lived, read-only session on their linked IMAP mailbox (push notification, confirmed with their passkey), then waits for the decision. Returns a session_id for email_list_folders, email_search and email_read. Nothing can be sent, moved, flagged or deleted.",
    inputSchema: {
      type: "object",
      properties: {
        consent_hint: consentHintProperty,
        wait_seconds: waitProperty,
      },
      additionalProperties: false,
    },
    annotations: READ_ONLY,
    async call(args, ctx) {
      const wait = waitSeconds(args);
      const res = await callRoute(emailRouter, ctx, "/sessions", {
        method: "POST",
        body: { consent_hint: optionalString(args, "consent_hint", 500) },
      });
      const json = await readJson(res);
      if (!res.ok || typeof json.session_id !== "string") {
        return text(json, true);
      }
      return awaitSession(ctx, json.session_id, wait * 1000);
    },
  },
  {
    name: "email_session_status",
    title: "Wait for email approval",
    description:
      "Keeps waiting for the user's decision on an email session started with email_start_session and reports its status.",
    inputSchema: {
      type: "object",
      properties: { session_id: sessionIdProperty, wait_seconds: waitProperty },
      required: ["session_id"],
      additionalProperties: false,
    },
    annotations: { ...READ_ONLY, openWorldHint: false },
    async call(args, ctx) {
      return awaitSession(
        ctx,
        requireString(args, "session_id", 64),
        waitSeconds(args) * 1000
      );
    },
  },
  {
    name: "email_list_folders",
    title: "List mail folders",
    description: "Lists the mailbox folders in an approved email session.",
    inputSchema: {
      type: "object",
      properties: { session_id: sessionIdProperty, wait_seconds: waitProperty },
      required: ["session_id"],
      additionalProperties: false,
    },
    annotations: READ_ONLY,
    async call(args, ctx) {
      return emailOp(ctx, args, { path: "/folders", method: "GET" });
    },
  },
  {
    name: "email_search",
    title: "Search email",
    description:
      "Searches one mailbox folder in an approved email session and returns matching messages (uid, envelope summary), newest first. Use email_read with a uid for the content.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: sessionIdProperty,
        mailbox: {
          type: "string",
          description: 'Folder path from email_list_folders, e.g. "INBOX".',
        },
        query: {
          type: "object",
          properties: {
            subject: { type: "string" },
            from: { type: "string" },
            to: { type: "string" },
            since: { type: "string", description: "YYYY-MM-DD" },
            before: { type: "string", description: "YYYY-MM-DD" },
            unseen: { type: "boolean" },
            keyword: { type: "string" },
            body_text: { type: "string" },
          },
          additionalProperties: false,
        },
        results_limit: {
          type: "integer",
          minimum: 1,
          maximum: 200,
          description: "Maximum matches to return (default 50).",
        },
        wait_seconds: waitProperty,
      },
      required: ["session_id", "mailbox"],
      additionalProperties: false,
    },
    annotations: READ_ONLY,
    async call(args, ctx) {
      return emailOp(ctx, args, {
        path: "/search",
        method: "POST",
        body: {
          mailbox: requireString(args, "mailbox", 512),
          query: optionalObject(args, "query"),
          results_limit: optionalInteger(args, "results_limit"),
        },
      });
    },
  },
  {
    name: "email_read",
    title: "Read an email",
    description:
      "Reads one message by uid in an approved email session. By default returns the envelope; ask for text (plain body), html or raw (RFC 822 source) parts as needed.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: sessionIdProperty,
        mailbox: { type: "string", description: "Folder containing the uid." },
        uid: { type: "integer", minimum: 1 },
        parts: {
          type: "object",
          properties: {
            envelope: { type: "boolean" },
            text: { type: "boolean" },
            html: { type: "boolean" },
            raw: { type: "boolean" },
          },
          additionalProperties: false,
        },
        wait_seconds: waitProperty,
      },
      required: ["session_id", "mailbox", "uid"],
      additionalProperties: false,
    },
    annotations: READ_ONLY,
    async call(args, ctx) {
      const uid = optionalInteger(args, "uid");
      if (uid == null) throw new ToolInputError("uid is required");
      return emailOp(ctx, args, {
        path: "/read",
        method: "POST",
        body: {
          mailbox: requireString(args, "mailbox", 512),
          uid,
          parts: optionalObject(args, "parts"),
        },
      });
    },
  },
];
