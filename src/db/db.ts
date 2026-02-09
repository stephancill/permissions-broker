import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { env } from "../env";

export function openDb(): Database {
  mkdirSync(dirname(env.DB_PATH), { recursive: true });

  const db = new Database(env.DB_PATH);
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA journal_mode = WAL;");
  db.exec("PRAGMA synchronous = NORMAL;");
  return db;
}
