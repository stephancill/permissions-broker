import { EMAIL_TOOLS } from "./emailTools";
import { GIT_TOOLS } from "./gitTools";
import { PROXY_TOOLS } from "./proxyTools";
import {
  type ToolContext,
  type ToolDefinition,
  ToolInputError,
  type ToolResult,
  text,
} from "./toolkit";

// MCP tool registry: the same surfaces as the agent skill (proxy, read-only
// email, git sessions). Each tool goes through the /v1 handlers with the
// caller's own API key; see toolkit.ts.

export type { ToolContext, ToolResult } from "./toolkit";

export const TOOLS: ToolDefinition[] = [
  ...PROXY_TOOLS,
  ...EMAIL_TOOLS,
  ...GIT_TOOLS,
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
