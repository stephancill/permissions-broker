import { db } from "../db/client";
import {
  type ApprovalMessageRef,
  editApprovalMessages,
} from "../telegram/approvalMessages";

function nowIso(): string {
  return new Date().toISOString();
}

export async function sweepGitSessions(): Promise<void> {
  const now = nowIso();
  const database = await db();

  // Expire pending approvals.
  const expired = await database
    .query(
      "UPDATE git_sessions SET status = 'EXPIRED', updated_at = ? WHERE status = 'PENDING_APPROVAL' AND approval_expires_at < ?" +
        " RETURNING id, telegram_chat_id, telegram_message_id, telegram_message_html;"
    )
    .all<ApprovalMessageRef>(now, now);
  await editApprovalMessages({
    kind: "git",
    refs: expired,
    decision: "EXPIRED",
  });

  // Expire approved/active sessions after short inactivity window.
  // (Sessions are intended to be short-lived for a single clone/push.)
  const inactiveCutoff = new Date(Date.now() - 2 * 60_000).toISOString();
  await database
    .query(
      "UPDATE git_sessions SET status = 'EXPIRED', updated_at = ? WHERE status IN ('APPROVED', 'ACTIVE') AND COALESCE(last_activity_at, updated_at) < ?;"
    )
    .run(now, inactiveCutoff);
}
