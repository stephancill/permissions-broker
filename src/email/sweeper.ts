import { db } from "../db/client";
import {
  type ApprovalMessageRef,
  editApprovalMessages,
} from "../telegram/approvalMessages";

function nowIso(): string {
  return new Date().toISOString();
}

export async function sweepEmailSessions(): Promise<void> {
  const now = nowIso();
  const database = await db();

  // Expire pending approvals.
  const expired = await database
    .query(
      "UPDATE email_sessions SET status = 'EXPIRED', updated_at = ? WHERE status = 'PENDING_APPROVAL' AND approval_expires_at < ?" +
        " RETURNING id, telegram_chat_id, telegram_message_id, telegram_message_html;"
    )
    .all<ApprovalMessageRef>(now, now);
  await editApprovalMessages({
    kind: "email",
    refs: expired,
    decision: "EXPIRED",
  });

  // Expire approved/active sessions after a short inactivity window.
  // (Sessions authorize a bounded read window; never keep them open.)
  const inactiveCutoff = new Date(Date.now() - 10 * 60_000).toISOString();
  await database
    .query(
      "UPDATE email_sessions SET status = 'EXPIRED', updated_at = ? WHERE status IN ('APPROVED', 'ACTIVE') AND COALESCE(last_activity_at, updated_at) < ?;"
    )
    .run(now, inactiveCutoff);
}
