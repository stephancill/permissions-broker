import { Database } from "bun:sqlite";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { env } from "../env";
import type { AppDb } from "./client";

export async function openDb(): Promise<AppDb> {
  mkdirSync(dirname(env.DB_PATH), { recursive: true });

  const database = new Database(env.DB_PATH);
  database.exec("PRAGMA foreign_keys = ON;");
  database.exec("PRAGMA journal_mode = WAL;");
  database.exec("PRAGMA synchronous = NORMAL;");

  return {
    query(sql) {
      const stmt = database.query(sql);
      return {
        async get<T = unknown>(...params: unknown[]) {
          return stmt.get(...(params as never[])) as T | null;
        },
        async all<T = unknown>(...params: unknown[]) {
          return stmt.all(...(params as never[])) as T[];
        },
        async run(...params: unknown[]) {
          const res = stmt.run(...(params as never[]));
          return { changes: res.changes };
        },
      };
    },
    async exec(sql) {
      database.exec(sql);
    },
    transaction(fn) {
      return database.transaction(fn)();
    },
  };
}
