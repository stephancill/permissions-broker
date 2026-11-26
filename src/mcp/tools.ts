import type { Hono } from "hono";

import type { ApiKeyAuth } from "../auth/apiKey";
import { accountRouter } from "../web/accounts";
import { proxyRouter } from "../web/proxy";

// MCP tools. They call the existing /v1 handlers in-process with the caller's
// own API key, so authorization, approval windows, push notifications and the
// single-use execute behave exactly as for the HTTP API.

export type ToolContext = {
  auth: ApiKeyAuth;
  // The caller's Authorization header (its API key), passed through.
  authorization: string;
  requesterIp: string | null;
};

export type ToolResult = {
  content: { type: "text"; text: string }[];
  isError?: boolean;
};

type ToolDefinition = {
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
  call(args: Record<string, unknown>, ctx: ToolContext): Promise<ToolResult>;
};

// Claude allows 240s per tool call; stay well below and let the model come
// back with proxy_result if the user hasn't approved yet.
export const MAX_WAIT_SECONDS = 50;
const DEFAULT_WAIT_SECONDS = 45;
const POLL_INTERVAL_MS = 1000;
// Claude caps tool results at ~150k characters.
const MAX_BODY_CHARS = 100_000;

const PROVIDERS_TEXT =
  "Supported upstreams: Google APIs (googleapis.com), GitHub (api.github.com), Spotify (api.spotify.com) and Cloudflare (api.cloudflare.com), for accounts the user linked in the app.";

class ToolInputError extends Error {}

function text(value: unknown, isError = false): ToolResult {
  const t = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  return { content: [{ type: "text", text: t }], ...(isError && { isError }) };
}

function requireString(
  args: Record<string, unknown>,
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

function optionalString(
  args: Record<string, unknown>,
  name: string,
  max: number
): string | undefined {
  const v = args[name];
  if (v == null) return undefined;
  if (typeof v !== "string")
    throw new ToolInputError(`${name} must be a string`);
  if (v.length > max) throw new ToolInputError(`${name} is too long`);
  return v;
}

function optionalHeaders(
  args: Record<string, unknown>
): Record<string, string> | undefined {
  const v = args.headers;
  if (v == null) return undefined;
  if (typeof v !== "object" || Array.isArray(v)) {
    throw new ToolInputError("headers must be an object of strings");
  }
  const out: Record<string, string> = {};
  for (const [k, val] of Object.entries(v)) {
    if (typeof val !== "string") {
      throw new ToolInputError("headers must be an object of strings");
    }
    out[k] = val;
  }
  return out;
}

function waitSeconds(args: Record<string, unknown>): number {
  const v = args.wait_seconds;
  if (v == null) return DEFAULT_WAIT_SECONDS;
  if (typeof v !== "number" || !Number.isFinite(v)) {
    throw new ToolInputError("wait_seconds must be a number");
  }
  return Math.min(MAX_WAIT_SECONDS, Math.max(0, Math.floor(v)));
}

async function callRoute(
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

async function readJson(res: Response): Promise<Record<string, unknown>> {
  return ((await res.json().catch(() => ({}))) ?? {}) as Record<
    string,
    unknown
  >;
}

const TEXTUAL_TYPE =
  /^(text\/|application\/([a-z0-9.+-]*\+)?(json|xml)\b|application\/(javascript|x-www-form-urlencoded|graphql))/i;

function describeUpstream(res: Response, bytes: Uint8Array): ToolResult {
  const contentType = res.headers.get("content-type");
  const head = `HTTP ${res.status}${contentType ? ` (${contentType})` : ""}, ${bytes.byteLength} bytes`;
  let body: string | null = null;
  if (!contentType || TEXTUAL_TYPE.test(contentType)) {
    try {
      body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      body = null;
    }
  }
  const isError = res.status >= 400;
  if (body == null) {
    return text(
      `${head}\n\n[binary response body omitted; use the HTTP API for binary content]`,
      isError
    );
  }
  if (body.length > MAX_BODY_CHARS) {
    body = `${body.slice(0, MAX_BODY_CHARS)}\n\n[truncated: showing the first ${MAX_BODY_CHARS} of ${body.length} characters; narrow the request (fields, pagination, ranges) to see more]`;
  }
  return text(`${head}\n\n${body}`, isError);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// Waits for the user's decision, then executes once and returns the upstream
// response.
async function awaitAndExecute(
  ctx: ToolContext,
  requestId: string,
  waitMs: number
): Promise<ToolResult> {
  const deadline = Date.now() + waitMs;
  const id = encodeURIComponent(requestId);
  for (;;) {
    const res = await callRoute(proxyRouter, ctx, `/requests/${id}`);
    const json = await readJson(res);
    const status = json.status;

    if (res.status === 202 && status === "APPROVED") break;
    if (res.status === 202) {
      if (Date.now() + POLL_INTERVAL_MS > deadline) {
        return text({
          request_id: requestId,
          status,
          approval_expires_at: json.approval_expires_at,
          next_step:
            "Still waiting for the user to approve this request on their phone (stupid vault push notification, confirmed with their passkey). Tell the user, then call proxy_result with this request_id to keep waiting.",
        });
      }
      await sleep(POLL_INTERVAL_MS);
      continue;
    }
    if (res.status === 403 && json.error === "denied") {
      return text(
        {
          request_id: requestId,
          status: "DENIED",
          message: "The user denied this request.",
        },
        true
      );
    }
    if (res.status === 408) {
      return text(
        {
          request_id: requestId,
          status: "EXPIRED",
          message:
            "The approval window passed without a decision. Create a new request if it is still needed.",
        },
        true
      );
    }
    if (status === "SUCCEEDED" || status === "FAILED") {
      return text(
        {
          ...json,
          message:
            "This request was already executed; results are returned only once. Create a new request to fetch it again.",
        },
        status === "FAILED"
      );
    }
    return text({ request_id: requestId, ...json }, true);
  }

  const exec = await callRoute(proxyRouter, ctx, `/requests/${id}/execute`, {
    method: "POST",
  });
  // Upstream bytes carry the request id header; anything else is a broker
  // error (credential unavailable, no linked account, ...).
  if (!exec.headers.has("X-Proxy-Request-Id")) {
    return text({ request_id: requestId, ...(await readJson(exec)) }, true);
  }
  return describeUpstream(exec, new Uint8Array(await exec.arrayBuffer()));
}

async function createAndAwait(
  ctx: ToolContext,
  args: Record<string, unknown>,
  method: string
): Promise<ToolResult> {
  const wait = waitSeconds(args);
  const res = await callRoute(proxyRouter, ctx, "/request", {
    method: "POST",
    body: {
      upstream_url: requireString(args, "url"),
      method,
      headers: optionalHeaders(args),
      body: args.body ?? undefined,
      consent_hint: optionalString(args, "consent_hint", 500),
    },
  });
  const json = await readJson(res);
  if (!res.ok || typeof json.request_id !== "string") {
    return text(json, true);
  }
  return awaitAndExecute(ctx, json.request_id, wait * 1000);
}

const urlProperty = {
  type: "string",
  description: `Full https URL of the upstream API endpoint, including query string. ${PROVIDERS_TEXT}`,
};
const headersProperty = {
  type: "object",
  additionalProperties: { type: "string" },
  description:
    "Optional request headers (e.g. accept, content-type). Authorization is injected by the vault and must not be sent.",
};
const consentHintProperty = {
  type: "string",
  maxLength: 500,
  description:
    "Short note shown to the user on the approval prompt explaining why this request is needed.",
};
const waitProperty = {
  type: "integer",
  minimum: 0,
  maximum: MAX_WAIT_SECONDS,
  description: `Seconds to wait for the user's approval before returning (default ${DEFAULT_WAIT_SECONDS}).`,
};

export const TOOLS: ToolDefinition[] = [
  {
    name: "whoami",
    title: "Who am I",
    description:
      "Shows which stupid vault API key this connector uses. The key label is what the user sees on approval prompts.",
    inputSchema: { type: "object", additionalProperties: false },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    async call(_args, ctx) {
      return text({
        user_id: ctx.auth.userId,
        api_key_id: ctx.auth.apiKeyId,
        api_key_label: ctx.auth.apiKeyLabel,
      });
    },
  },
  {
    name: "list_accounts",
    title: "List linked accounts",
    description:
      "Lists the accounts the user linked in stupid vault (Google, GitHub, Spotify, Cloudflare, IMAP email). Use it to see which upstream APIs are available before making requests. No approval needed; credentials are never returned.",
    inputSchema: { type: "object", additionalProperties: false },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: false,
    },
    async call(_args, ctx) {
      const res = await callRoute(accountRouter, ctx, "/");
      return text(await readJson(res), !res.ok);
    },
  },
  {
    name: "proxy_get",
    title: "Read from a linked account",
    description: `Makes an approval-gated GET request to an upstream API using one of the user's linked accounts. The vault sends the user a push notification; the request runs only after they approve with their passkey, and the response is returned once. ${PROVIDERS_TEXT} Prefer narrow requests (fields, page sizes) since large responses are truncated.`,
    inputSchema: {
      type: "object",
      properties: {
        url: urlProperty,
        headers: headersProperty,
        consent_hint: consentHintProperty,
        wait_seconds: waitProperty,
      },
      required: ["url"],
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
    async call(args, ctx) {
      return createAndAwait(ctx, args, "GET");
    },
  },
  {
    name: "proxy_request",
    title: "Call an API with a linked account",
    description: `Makes an approval-gated request with any method (POST, PUT, PATCH, DELETE, ...) to an upstream API using one of the user's linked accounts. The user reviews the exact request on their phone and approves with their passkey before it runs. ${PROVIDERS_TEXT} Use proxy_get for plain reads.`,
    inputSchema: {
      type: "object",
      properties: {
        url: urlProperty,
        method: {
          type: "string",
          description: "HTTP method, e.g. POST, PUT, PATCH or DELETE.",
        },
        headers: headersProperty,
        body: {
          description:
            "Request body: a JSON value (sent as application/json unless content-type says otherwise) or a string for textual content types.",
        },
        consent_hint: consentHintProperty,
        wait_seconds: waitProperty,
      },
      required: ["url", "method"],
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: true,
    },
    async call(args, ctx) {
      const method = requireString(args, "method", 20).toUpperCase();
      return createAndAwait(ctx, args, method);
    },
  },
  {
    name: "proxy_result",
    title: "Wait for an approval",
    description:
      "Keeps waiting for the user's decision on a request made with proxy_get or proxy_request, then returns the upstream response. Use it when an earlier call returned PENDING_APPROVAL. It never creates a new request, and a request's response is returned only once.",
    inputSchema: {
      type: "object",
      properties: {
        request_id: {
          type: "string",
          description: "request_id returned by proxy_get or proxy_request.",
        },
        wait_seconds: waitProperty,
      },
      required: ["request_id"],
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true,
    },
    async call(args, ctx) {
      const requestId = requireString(args, "request_id", 64);
      return awaitAndExecute(ctx, requestId, waitSeconds(args) * 1000);
    },
  },
];

export function listTools() {
  return TOOLS.map(({ call: _call, ...tool }) => tool);
}

export async function callTool(
  name: string,
  args: Record<string, unknown>,
  ctx: ToolContext
): Promise<ToolResult | null> {
  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) return null;
  try {
    return await tool.call(args, ctx);
  } catch (err) {
    if (err instanceof ToolInputError) return text(err.message, true);
    throw err;
  }
}
