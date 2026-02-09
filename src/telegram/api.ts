import { Api } from "grammy";

import { env } from "../env";

let _api: Api | undefined;

export function telegramApi(): Api {
  if (_api) return _api;
  if (!env.TELEGRAM_BOT_TOKEN) {
    throw new Error("TELEGRAM_BOT_TOKEN is not configured");
  }
  _api = new Api(env.TELEGRAM_BOT_TOKEN);
  return _api;
}
