import { gitRouter } from "../web/git";
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
  waitProperty,
  waitSeconds,
} from "./toolkit";

// Git smart-HTTP sessions through /v1/git. After approval the tool returns a
// short-lived remote URL for the client's own git CLI, so these tools are for
// clients with a shell (Claude Code, Codex, ...). The URL embeds the session
// secret: like vault_git.py, it should be passed straight to git and not
// saved as a remote.

const READ_OPERATIONS = ["clone", "fetch", "pull"] as const;

function usage(operation: string, repo: string): string {
  switch (operation) {
    case "clone":
      return `git clone <remote_url> [dir], then point origin back at GitHub so the expiring URL isn't kept: git -C <dir> remote set-url origin https://github.com/${repo}.git`;
    case "fetch":
      return "git fetch <remote_url> <refspec> (inside an existing checkout)";
    case "pull":
      return "git pull <remote_url> <branch> (inside an existing checkout)";
    default:
      return "git push <remote_url> <local-branch>:<remote-branch>. Tags and branch deletions are refused, and the default branch only if the user allowed it when approving.";
  }
}

async function awaitRemote(
  ctx: ToolContext,
  sessionId: string,
  waitMs: number
): Promise<ToolResult> {
  const id = encodeURIComponent(sessionId);
  return pollUntil(
    waitMs,
    async () => {
      const res = await callRoute(gitRouter, ctx, `/sessions/${id}/remote`);
      if (res.status === 202) return null;
      const json = await readJson(res);
      if (!res.ok || typeof json.remote_url !== "string") {
        const message =
          json.error === "denied"
            ? "The user denied this git session."
            : json.error === "expired" || json.error === "used"
              ? "This git session is no longer usable. Start a new one if still needed."
              : undefined;
        return text(
          { session_id: sessionId, ...json, ...(message && { message }) },
          true
        );
      }
      const info = await readJson(
        await callRoute(gitRouter, ctx, `/sessions/${id}`)
      );
      const operation = String(info.operation ?? "");
      const repo = String(info.repo ?? "");
      return text({
        session_id: sessionId,
        status: info.status,
        operation,
        repo,
        default_branch_ref: info.default_branch_ref,
        allow_default_branch_push: info.allow_default_branch_push,
        remote_url: json.remote_url,
        usage: usage(operation, repo),
        note: "The remote URL is a short-lived credential for this one repository and operation. Use it directly in the git command; don't print it back to the user or store it in git config.",
      });
    },
    () =>
      text({
        session_id: sessionId,
        status: "PENDING_APPROVAL",
        next_step: `${APPROVAL_WAIT_TEXT} Tell the user, then call git_session_remote with this session_id to keep waiting.`,
      })
  );
}

async function startSession(
  ctx: ToolContext,
  args: ToolArgs,
  operation: string
): Promise<ToolResult> {
  const wait = waitSeconds(args);
  const repo = requireString(args, "repo", 200);
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo)) {
    throw new ToolInputError('repo must look like "owner/name"');
  }
  const res = await callRoute(gitRouter, ctx, "/sessions", {
    method: "POST",
    body: {
      operation,
      repo: repo.replace(/\.git$/, ""),
      consent_hint: optionalString(args, "consent_hint", 500),
    },
  });
  const json = await readJson(res);
  if (!res.ok || typeof json.session_id !== "string") {
    return text(json, true);
  }
  return awaitRemote(ctx, json.session_id, wait * 1000);
}

const repoProperty = {
  type: "string",
  description: 'GitHub repository as "owner/name".',
};

export const GIT_TOOLS: ToolDefinition[] = [
  {
    name: "git_read_session",
    title: "Clone or fetch a GitHub repo",
    description:
      "Asks the user to approve a short-lived git clone, fetch or pull of one GitHub repository (push notification, confirmed with their passkey), then returns a remote URL to use with your local git CLI. Only useful when you can run git commands. Works for private repos when the user linked GitHub; public repos work without it.",
    inputSchema: {
      type: "object",
      properties: {
        repo: repoProperty,
        operation: {
          type: "string",
          enum: [...READ_OPERATIONS],
          description: "Default clone.",
        },
        consent_hint: consentHintProperty,
        wait_seconds: waitProperty,
      },
      required: ["repo"],
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      openWorldHint: true,
    },
    async call(args, ctx) {
      const op = optionalString(args, "operation", 10) ?? "clone";
      if (!(READ_OPERATIONS as readonly string[]).includes(op)) {
        throw new ToolInputError("operation must be clone, fetch or pull");
      }
      return startSession(ctx, args, op);
    },
  },
  {
    name: "git_push_session",
    title: "Push to a GitHub repo",
    description:
      "Asks the user to approve a short-lived git push to one GitHub repository (push notification, confirmed with their passkey), then returns a remote URL to push to with your local git CLI. Tags and branch deletions are always refused; the default branch only if the user allows it when approving. Requires a linked GitHub account.",
    inputSchema: {
      type: "object",
      properties: {
        repo: repoProperty,
        consent_hint: consentHintProperty,
        wait_seconds: waitProperty,
      },
      required: ["repo"],
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: true,
    },
    async call(args, ctx) {
      return startSession(ctx, args, "push");
    },
  },
  {
    name: "git_session_remote",
    title: "Wait for git approval",
    description:
      "Keeps waiting for the user's decision on a session from git_read_session or git_push_session and returns its remote URL once approved.",
    inputSchema: {
      type: "object",
      properties: {
        session_id: {
          type: "string",
          description:
            "session_id returned by git_read_session or git_push_session.",
        },
        wait_seconds: waitProperty,
      },
      required: ["session_id"],
      additionalProperties: false,
    },
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    async call(args, ctx) {
      return awaitRemote(
        ctx,
        requireString(args, "session_id", 64),
        waitSeconds(args) * 1000
      );
    },
  },
];
