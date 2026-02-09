import { db } from "../db/client";

function nowIso(): string {
  return new Date().toISOString();
}

const RESULT_TTL_MS = 2 * 60_000;

function sweepApprovalExpirations(): number {
  return db()
    .query(
      "UPDATE proxy_requests SET status = 'EXPIRED', updated_at = ?, error_code = 'APPROVAL_EXPIRED' " +
        "WHERE status = 'PENDING_APPROVAL' AND approval_expires_at < ?;"
    )
    .run(nowIso(), nowIso()).changes;
}

function sweepResultExpirations(): number {
  const cutoff = new Date(Date.now() - RESULT_TTL_MS).toISOString();
  return db()
    .query(
      "UPDATE proxy_requests SET result_state = 'EXPIRED', updated_at = ? " +
        "WHERE status = 'SUCCEEDED' AND result_state = 'AVAILABLE' AND updated_at < ?;"
    )
    .run(nowIso(), cutoff).changes;
}

export async function startSweeperLoop(): Promise<void> {
  for (;;) {
    sweepApprovalExpirations();
    sweepResultExpirations();
    await new Promise((r) => setTimeout(r, 1000));
  }
}
