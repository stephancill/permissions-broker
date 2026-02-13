import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { openDb } from "./db";

function nowIso(): string {
  return new Date().toISOString();
}

function ensureSchemaMigrations(db: ReturnType<typeof openDb>) {
  db.exec(
    "CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL);"
  );
}

function getApplied(db: ReturnType<typeof openDb>): Set<string> {
  const rows = db
    .query("SELECT id FROM schema_migrations ORDER BY id;")
    .all() as {
    id: string;
  }[];
  return new Set(rows.map((r) => r.id));
}

function isIgnorableMigrationError(err: unknown, file: string): boolean {
  if (!(err instanceof Error)) return false;
  const msg = err.message || "";

  // SQLite does not support `ADD COLUMN IF NOT EXISTS` in older versions.
  // If a migration attempts to add a column that already exists (because the
  // DB was manually patched or a migration was partially applied), treat it as
  // already satisfied.
  if (
    file === "0004_git_sessions_secret_ciphertext.sql" &&
    msg.includes("duplicate column name: session_secret_ciphertext")
  ) {
    return true;
  }

  return false;
}

export function migrate(): void {
  const db = openDb();
  ensureSchemaMigrations(db);

  const applied = getApplied(db);
  const migrationsDir = join(import.meta.dir, "..", "..", "migrations");

  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort((a, b) => a.localeCompare(b));

  for (const file of files) {
    if (applied.has(file)) continue;

    const sql = readFileSync(join(migrationsDir, file), "utf8");

    db.transaction(() => {
      try {
        db.exec(sql);
      } catch (err) {
        if (!isIgnorableMigrationError(err, file)) throw err;
      }

      db.query(
        "INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?);"
      ).run(file, nowIso());
    })();
  }
}

if (import.meta.main) {
  migrate();
  console.log("migrations applied");
}
