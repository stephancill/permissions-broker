import type { Database } from "bun:sqlite";

import { openDb } from "./db";

let _db: Database | undefined;

export function db(): Database {
  if (!_db) {
    _db = openDb();
  }
  return _db;
}
