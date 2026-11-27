import type { Hono } from "hono";

import type { ApiKeyAuth } from "../auth/apiKey";

// Shared plumbing for the MCP tools. Tools call the existing /v1 handlers
// in-process with the caller's own API key (callRoute), so authorization,
// approvals, approval windows, push notifications and limits behave exactly
// as for the HTTP API.

export type ToolContext = {
  auth: ApiKeyAuth;
  // The caller's Authorization header (its API key), passed through.
  authorization: string;
  requesterIp: string | null;
};

export type ToolContent =
  | { type: "text"; text: string }
  | { type: "image"; data: string; mimeType: string }
  | {
      type: "resource";
      resource: { uri: string; mimeType: string; blob: string };
    };

export type ToolResult = {
  content: ToolContent[];
  isError?: boolean;
};

export type ToolArgs = Record<string, unknown>;

export type ToolDefinition = {
  name: string;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: {
    readOnlyHint: boolean;
    destructiveHint: boolean;
    idempotentHint?: boolean;
    openWorldHint: boolean;
  };
  call(args: ToolArgs, ctx: ToolContext): Promise<ToolResult>;
};

// Claude allows 240s per tool call; stay well below and let the model come
// back with a follow-up tool if the user hasn't approved yet.
export const MAX_WAIT_SECONDS = 50;
export const DEFAULT_WAIT_SECONDS = 45;
export const POLL_INTERVAL_MS = 1000;
// Claude caps tool results at ~150k characters.
export const MAX_RESULT_CHARS = 100_000;

export class ToolInputError extends Error {}

export function text(value: unknown, isError = false): ToolResult {
  const t = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: "text", text: t }], ...(isError && { isError }) };
}

export function truncateText(s: string, hint: string): string {
  if (s.length <= MAX_RESULT_CHARS) return s;
  return `${s.slice(0, MAX_RESULT_CHARS)}\n\n[truncated: showing the first ${MAX_RESULT_CHARS} of ${s.length} characters; ${hint}]`;
}

export function requireString(
  args: ToolArgs,
  name: string,
  max = 4096
): string {
  const v = args[name];
  if (typeof v !== "string" || !v.trim()) {
    throw new ToolInputError(`${name} is required`);
  }
  if (v.length > max) throw new ToolInputError(`${name} is too long`);
  return v.trim();
}

export function optionalString(
  args: ToolArgs,
  name: string,
  max: number
): string | undefined {
  const v = args[name];
  if (v == null) return undefined;
  if (typeof v !== "string") {
    throw new ToolInputError(`${name} must be a string`);
  }
  if (v.length > max) throw new ToolInputError(`${name} is too long`);
  return v;
}

export function waitSeconds(args: ToolArgs): number {
  const v = args.wait_seconds;
  if (v == null) return DEFAULT_WAIT_SECONDS;
  if (typeof v !== "number" || !Number.isFinite(v)) {
    throw new ToolInputError("wait_seconds must be a number");
  }
  return Math.min(MAX_WAIT_SECONDS, Math.max(0, Math.floor(v)));
}

export async function callRoute(
  router: Hono,
  ctx: ToolContext,
  path: string,
  init: { method: string; body?: unknown } = { method: "GET" }
): Promise<Response> {
  const headers: Record<string, string> = { authorization: ctx.authorization };
  if (ctx.requesterIp) headers["x-forwarded-for"] = ctx.requesterIp;
  if (init.body !== undefined) headers["content-type"] = "application/json";
  return router.request(`http://internal${path}`, {
    method: init.method,
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body),
  });
}

export async function readJson(
  res: Response
): Promise<Record<string, unknown>> {
  return ((await res.json().catch(() => ({}))) ?? {}) as Record<
    string,
    unknown
  >;
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Repeats `attempt` until it returns a result or the wait runs out; then
// returns `onTimeout()`.
export async function pollUntil(
  waitMs: number,
  attempt: () => Promise<ToolResult | null>,
  onTimeout: () => ToolResult
): Promise<ToolResult> {
  const deadline = Date.now() + waitMs;
  for (;;) {
    const result = await attempt();
    if (result) return result;
    if (Date.now() + POLL_INTERVAL_MS > deadline) return onTimeout();
    await sleep(POLL_INTERVAL_MS);
  }
}

export const consentHintProperty = {
  type: "string",
  maxLength: 500,
  description:
    "Short note shown to the user on the approval prompt explaining why this access is needed.",
};

export const waitProperty = {
  type: "integer",
  minimum: 0,
  maximum: MAX_WAIT_SECONDS,
  description: `Seconds to wait for the user's approval before returning (default ${DEFAULT_WAIT_SECONDS}).`,
};

export const APPROVAL_WAIT_TEXT =
  "Still waiting for the user to approve on their phone (stupid vault push notification, confirmed with their passkey).";
