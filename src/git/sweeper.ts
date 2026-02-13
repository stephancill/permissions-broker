import { db } from "../db/client";

function nowIso(): string {
  return new Date().toISOString();
}

export function sweepGitSessions(): void {
  const now = nowIso();

  // Expire pending approvals.
  db()
    .query(
      "UPDATE git_sessions SET status = 'EXPIRED', updated_at = ? WHERE status = 'PENDING_APPROVAL' AND approval_expires_at < ?;"
    )
    .run(now, now);

  // Expire approved/active sessions after short inactivity window.
  // (Sessions are intended to be short-lived for a single clone/push.)
  const inactiveCutoff = new Date(Date.now() - 2 * 60_000).toISOString();
  db()
    .query(
      "UPDATE git_sessions SET status = 'EXPIRED', updated_at = ? WHERE status IN ('APPROVED', 'ACTIVE') AND COALESCE(last_activity_at, updated_at) < ?;"
    )
    .run(now, inactiveCutoff);
}
