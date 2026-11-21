import { sweepWebSessions } from "../auth/session";
import { sweepCredentialGrants } from "../credentials/store";
import { db } from "../db/client";
import { sweepEmailSessions } from "../email/sweeper";
import { sweepGitSessions } from "../git/sweeper";
import { sweepReleaseState } from "../release/store";

function nowIso(): string {
  return new Date().toISOString();
}

export async function sweepApprovalExpirations(): Promise<number> {
  const database = await db();
  const expired = await database
    .query(
      "UPDATE proxy_requests SET status = 'EXPIRED', updated_at = ?, error_code = 'APPROVAL_EXPIRED' " +
        "WHERE status = 'PENDING_APPROVAL' AND approval_expires_at < ?;"
    )
    .run(nowIso(), nowIso());
  return expired.changes ?? 0;
}

export async function sweepExpiredState(): Promise<void> {
  await sweepApprovalExpirations();
  await sweepGitSessions();
  await sweepEmailSessions();
  await sweepReleaseState();
  await sweepWebSessions();
  // After session sweeps so keys of just-expired targets are wiped too.
  await sweepCredentialGrants();
}

export async function startSweeperLoop(): Promise<void> {
  for (;;) {
    await sweepExpiredState();
    await new Promise((r) => setTimeout(r, 1000));
  }
}
