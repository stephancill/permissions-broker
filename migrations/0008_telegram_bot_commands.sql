PRAGMA foreign_keys = ON;

ALTER TABLE telegram_state ADD COLUMN bot_commands_registered_at TEXT;
