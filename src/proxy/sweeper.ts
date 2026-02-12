import { db } from "../db/client";

function nowIso(): string {
  return new Date().toISOString();
}

function sweepApprovalExpirations(): number {
  return db()
    .query(
      "UPDATE proxy_requests SET status = 'EXPIRED', updated_at = ?, error_code = 'APPROVAL_EXPIRED' " +
        "WHERE status = 'PENDING_APPROVAL' AND approval_expires_at < ?;"
    )
    .run(nowIso(), nowIso()).changes;
}

export async function startSweeperLoop(): Promise<void> {
  for (;;) {
    sweepApprovalExpirations();
    await new Promise((r) => setTimeout(r, 1000));
  }
}
