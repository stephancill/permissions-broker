import { db } from "../db/client";
import { sweepEmailSessions } from "../email/sweeper";
import { sweepGitSessions } from "../git/sweeper";

function nowIso(): string {
  return new Date().toISOString();
}

export async function sweepApprovalExpirations(): Promise<number> {
  const database = await db();
  const result = await database
    .query(
      "UPDATE proxy_requests SET status = 'EXPIRED', updated_at = ?, error_code = 'APPROVAL_EXPIRED' " +
        "WHERE status = 'PENDING_APPROVAL' AND approval_expires_at < ?;"
    )
    .run(nowIso(), nowIso());
  return result.changes ?? 0;
}

export async function sweepExpiredState(): Promise<void> {
  await sweepApprovalExpirations();
  await sweepGitSessions();
  await sweepEmailSessions();
}

export async function startSweeperLoop(): Promise<void> {
  for (;;) {
    await sweepExpiredState();
    await new Promise((r) => setTimeout(r, 1000));
  }
}
