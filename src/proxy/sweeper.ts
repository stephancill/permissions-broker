import { sweepCredentialGrants } from "../credentials/store";
import { db } from "../db/client";
import { sweepEmailSessions } from "../email/sweeper";
import { sweepGitSessions } from "../git/sweeper";
import {
  type ApprovalMessageRef,
  editApprovalMessages,
} from "../telegram/approvalMessages";

function nowIso(): string {
  return new Date().toISOString();
}

export async function sweepApprovalExpirations(): Promise<number> {
  const database = await db();
  const expired = await database
    .query(
      "UPDATE proxy_requests SET status = 'EXPIRED', updated_at = ?, error_code = 'APPROVAL_EXPIRED' " +
        "WHERE status = 'PENDING_APPROVAL' AND approval_expires_at < ?" +
        " RETURNING id, telegram_chat_id, telegram_message_id, telegram_message_html;"
    )
    .all<ApprovalMessageRef>(nowIso(), nowIso());
  await editApprovalMessages({
    kind: "proxy",
    refs: expired,
    decision: "EXPIRED",
  });
  return expired.length;
}

export async function sweepExpiredState(): Promise<void> {
  await sweepApprovalExpirations();
  await sweepGitSessions();
  await sweepEmailSessions();
  // After session sweeps so keys of just-expired targets are wiped too.
  await sweepCredentialGrants();
}

export async function startSweeperLoop(): Promise<void> {
  for (;;) {
    await sweepExpiredState();
    await new Promise((r) => setTimeout(r, 1000));
  }
}
