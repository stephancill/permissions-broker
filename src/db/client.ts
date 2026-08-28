export type DbRunResult = {
  changes?: number;
};

export type DbStatement = {
  get<T = unknown>(...params: unknown[]): Promise<T | null>;
  all<T = unknown>(...params: unknown[]): Promise<T[]>;
  run(...params: unknown[]): Promise<DbRunResult>;
};

export type AppDb = {
  query(sql: string): DbStatement;
  exec(sql: string): Promise<void>;
  transaction<T>(fn: () => Promise<T>): Promise<T>;
};

export type D1DatabaseLike = {
  prepare(sql: string): {
    bind(...params: unknown[]): {
      first<T = unknown>(): Promise<T | null>;
      all<T = unknown>(): Promise<{ results?: T[] }>;
      run(): Promise<{ meta?: { changes?: number } }>;
    };
  };
  exec(sql: string): Promise<unknown>;
};

let _db: AppDb | undefined;

export function setAppDatabase(database: AppDb): void {
  _db = database;
}

export function setD1Database(database: D1DatabaseLike): void {
  setAppDatabase(createD1Adapter(database));
}

export async function db(): Promise<AppDb> {
  if (!_db) {
    throw new Error("database is not configured");
  }
  return _db;
}

function createD1Adapter(database: D1DatabaseLike): AppDb {
  return {
    query(sql) {
      return {
        get<T = unknown>(...params: unknown[]) {
          return database
            .prepare(sql)
            .bind(...params)
            .first<T>();
        },
        async all<T = unknown>(...params: unknown[]) {
          const res = await database
            .prepare(sql)
            .bind(...params)
            .all<T>();
          return res.results ?? [];
        },
        async run(...params: unknown[]) {
          const res = await database
            .prepare(sql)
            .bind(...params)
            .run();
          return { changes: res.meta?.changes };
        },
      };
    },
    async exec(sql) {
      await database.exec(sql);
    },
    async transaction(fn) {
      // D1 does not expose interactive transactions through the Worker binding.
      // Keep transactions small and idempotent at call sites.
      return fn();
    },
  };
}
