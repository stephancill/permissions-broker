import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { type AppDb, setAppDatabase } from "./client";
import { openDb } from "./db";

function nowIso(): string {
  return new Date().toISOString();
}

async function ensureSchemaMigrations(db: AppDb) {
  await db.exec(
    "CREATE TABLE IF NOT EXISTS schema_migrations (id TEXT PRIMARY KEY, applied_at TEXT NOT NULL);"
  );
}

async function getApplied(db: AppDb): Promise<Set<string>> {
  const rows = (await db
    .query("SELECT id FROM schema_migrations ORDER BY id;")
    .all()) as {
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

export async function migrate(): Promise<void> {
  const db = await openDb();
  setAppDatabase(db);
  await ensureSchemaMigrations(db);

  const applied = await getApplied(db);
  const migrationsDir = join(import.meta.dir, "..", "..", "migrations");

  const files = readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort((a, b) => a.localeCompare(b));

  for (const file of files) {
    if (applied.has(file)) continue;

    const sql = readFileSync(join(migrationsDir, file), "utf8");

    await db.transaction(async () => {
      try {
        await db.exec(sql);
      } catch (err) {
        if (!isIgnorableMigrationError(err, file)) throw err;
      }

      await db
        .query("INSERT INTO schema_migrations (id, applied_at) VALUES (?, ?);")
        .run(file, nowIso());
    });
  }
}

if (import.meta.main) {
  await migrate();
  console.log("migrations applied");
}
