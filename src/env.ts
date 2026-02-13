import { z } from "zod";

const isBunTestRun =
  process.env.NODE_ENV == null &&
  // `bun test` includes the literal "test" argument.
  process.argv.some((a) => a === "test");

const nodeEnvRaw =
  process.env.NODE_ENV ?? (isBunTestRun ? "test" : "development");
const nodeEnvDefault =
  nodeEnvRaw === "development" ||
  nodeEnvRaw === "test" ||
  nodeEnvRaw === "production"
    ? nodeEnvRaw
    : "development";

const dbPathDefault =
  nodeEnvDefault === "test"
    ? (() => {
        const b = new Uint8Array(6);
        crypto.getRandomValues(b);
        const suffix = [...b]
          .map((x) => x.toString(16).padStart(2, "0"))
          .join("");
        return `./data/test-${process.pid}-${suffix}.sqlite3`;
      })()
    : "./data/dev.sqlite3";

const testBypassOauthDefault = nodeEnvDefault === "test";

const EnvSchema = z.object({
  NODE_ENV: z
    .enum(["development", "test", "production"])
    .default(nodeEnvDefault),
  PORT: z.coerce.number().int().positive().default(3000),
  DB_PATH: z.string().min(1).default(dbPathDefault),
  TELEGRAM_BOT_TOKEN: z.string().min(1).optional(),
  APP_BASE_URL: z.string().min(1).optional(),
  APP_SECRET: z.string().min(1).optional(),
  GOOGLE_OAUTH_CLIENT_ID: z.string().min(1).optional(),
  GOOGLE_OAUTH_CLIENT_SECRET: z.string().min(1).optional(),
  GITHUB_OAUTH_CLIENT_ID: z.string().min(1).optional(),
  GITHUB_OAUTH_CLIENT_SECRET: z.string().min(1).optional(),
  PB_TEST_BYPASS_OAUTH: z.coerce
    .boolean()
    .optional()
    .default(testBypassOauthDefault),
});

export type Env = z.infer<typeof EnvSchema>;
export const env: Env = EnvSchema.parse(process.env);
