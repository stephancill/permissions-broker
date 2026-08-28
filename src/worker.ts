import { createApp } from "./app";
import { type D1DatabaseLike, setD1Database } from "./db/client";
import { configureEnv } from "./env";
import { sweepExpiredState } from "./proxy/sweeper";
import { ensureTelegramBotCommandsRegistered } from "./telegram/commands";

type WorkerEnv = Record<string, unknown> & {
  DB: D1DatabaseLike;
};

type ExecutionContext = {
  waitUntil(promise: Promise<unknown>): void;
};

type ScheduledEvent = {
  cron: string;
  scheduledTime: number;
};

const app = createApp({ includeGit: true, includeTelegramWebhook: true });

function configureWorker(env: WorkerEnv): void {
  setD1Database(env.DB);
  configureEnv({ ...env, NODE_ENV: env.NODE_ENV ?? "production" });
}

export default {
  fetch(request: Request, env: WorkerEnv, _ctx: ExecutionContext) {
    configureWorker(env);
    return app.fetch(request, env);
  },
  scheduled(_event: ScheduledEvent, env: WorkerEnv, ctx: ExecutionContext) {
    configureWorker(env);
    ctx.waitUntil(
      Promise.all([sweepExpiredState(), ensureTelegramBotCommandsRegistered()])
    );
  },
};
