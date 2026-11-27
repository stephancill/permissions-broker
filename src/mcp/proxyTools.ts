import { accountRouter } from "../web/accounts";
import { proxyRouter } from "../web/proxy";
import {
  APPROVAL_WAIT_TEXT,
  callRoute,
  consentHintProperty,
  MAX_RESULT_CHARS,
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

// Approval-gated HTTP requests through /v1/proxy, plus account listing.

const PROVIDERS_TEXT =
  "Supported upstreams: Google APIs (googleapis.com), GitHub (api.github.com), Spotify (api.spotify.com) and Cloudflare (api.cloudflare.com), for accounts the user linked in the app.";

function optionalHeaders(args: ToolArgs): Record<string, string> | undefined {
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

const TEXTUAL_TYPE =
  /^(text\/|application\/([a-z0-9.+-]*\+)?(json|xml)\b|application\/(javascript|x-www-form-urlencoded|graphql))/i;
const IMAGE_TYPE = /^image\/(png|jpeg|gif|webp)\b/i;
// Base64 grows by 4/3; keep binary results inside the text budget.
const MAX_BINARY_BYTES = Math.floor((MAX_RESULT_CHARS * 3) / 4);

function describeUpstream(
  requestId: string,
  res: Response,
  bytes: Uint8Array
): ToolResult {
  const contentType = res.headers.get("content-type");
  const head = `HTTP ${res.status}${contentType ? ` (${contentType})` : ""}, ${bytes.byteLength} bytes`;
  const isError = res.status >= 400;

  let body: string | null = null;
  if (!contentType || TEXTUAL_TYPE.test(contentType)) {
    try {
      body = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      body = null;
    }
  }
  if (body != null) {
    const shown = truncateText(
      body,
      "narrow the request (fields, pagination, ranges) to see more"
    );
    return text(`${head}\n\n${shown}`, isError);
  }

  // Binary: images inline, anything else as an embedded resource.
  if (bytes.byteLength > MAX_BINARY_BYTES) {
    return text(
      `${head}\n\n[binary body omitted: larger than ${MAX_BINARY_BYTES} bytes; request a smaller range or size]`,
      isError
    );
  }
  const data = Buffer.from(bytes).toString("base64");
  const mimeType =
    contentType?.split(";", 1)[0]?.trim() || "application/octet-stream";
  return {
    content: [
      { type: "text", text: head },
      IMAGE_TYPE.test(mimeType)
        ? { type: "image", data, mimeType }
        : {
            type: "resource",
            resource: {
              uri: `vault://proxy/${requestId}`,
              mimeType,
              blob: data,
            },
          },
    ],
    ...(isError && { isError }),
  };
}

// Waits for the user's decision, then executes once and returns the upstream
// response.
async function awaitAndExecute(
  ctx: ToolContext,
  requestId: string,
  waitMs: number
): Promise<ToolResult> {
  const id = encodeURIComponent(requestId);
  let lastStatus: Record<string, unknown> = {};
  let approved = false;

  const decided = await pollUntil(
    waitMs,
    async () => {
      const res = await callRoute(proxyRouter, ctx, `/requests/${id}`);
      const json = await readJson(res);
      lastStatus = json;
      if (res.status === 202 && json.status === "APPROVED") {
        approved = true;
        return text("");
      }
      if (res.status === 202) return null;
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
      if (json.status === "SUCCEEDED" || json.status === "FAILED") {
        return text(
          {
            ...json,
            message:
              "This request was already executed; results are returned only once. Create a new request to fetch it again.",
          },
          json.status === "FAILED"
        );
      }
      return text({ request_id: requestId, ...json }, true);
    },
    () =>
      text({
        request_id: requestId,
        status: lastStatus.status,
        approval_expires_at: lastStatus.approval_expires_at,
        next_step: `${APPROVAL_WAIT_TEXT} Tell the user, then call proxy_result with this request_id to keep waiting.`,
      })
  );
  if (!approved) return decided;

  const exec = await callRoute(proxyRouter, ctx, `/requests/${id}/execute`, {
    method: "POST",
  });
  // Upstream bytes carry the request id header; anything else is a broker
  // error (credential unavailable, no linked account, ...).
  if (!exec.headers.has("X-Proxy-Request-Id")) {
    return text({ request_id: requestId, ...(await readJson(exec)) }, true);
  }
  return describeUpstream(
    requestId,
    exec,
    new Uint8Array(await exec.arrayBuffer())
  );
}

async function createAndAwait(
  ctx: ToolContext,
  args: ToolArgs,
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
      idempotency_key: optionalString(args, "idempotency_key", 200),
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
    "Optional request headers (e.g. accept, content-type, range). Authorization is injected by the vault and must not be sent.",
};
const idempotencyKeyProperty = {
  type: "string",
  maxLength: 200,
  description:
    "Optional key that makes retries of the same request reuse the existing request (and its approval) instead of creating a new one.",
};

export const PROXY_TOOLS: ToolDefinition[] = [
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
    description: `Makes an approval-gated GET request to an upstream API using one of the user's linked accounts. The vault sends the user a push notification; the request runs only after they approve with their passkey, and the response is returned once. ${PROVIDERS_TEXT} Prefer narrow requests (fields, page sizes) since large responses are truncated. Images come back inline and other binary bodies as an embedded resource.`,
    inputSchema: {
      type: "object",
      properties: {
        url: urlProperty,
        headers: headersProperty,
        consent_hint: consentHintProperty,
        idempotency_key: idempotencyKeyProperty,
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
            "Request body: a JSON value (sent as application/json unless content-type says otherwise), a string for textual content types, or a base64 string for binary content types.",
        },
        consent_hint: consentHintProperty,
        idempotency_key: idempotencyKeyProperty,
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
    title: "Wait for a request's approval",
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
