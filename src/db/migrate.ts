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
      db.exec(sql);
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
