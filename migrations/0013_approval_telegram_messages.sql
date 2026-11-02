-- Remember the Telegram approval prompt for each request/session so it can be
-- edited (decision + buttons removed) when approved on the passkey page,
-- denied, or expired. The HTML is stored because editMessageText replaces the
-- whole text and the passkey page has no access to the original message.
ALTER TABLE proxy_requests ADD COLUMN telegram_chat_id INTEGER;
ALTER TABLE proxy_requests ADD COLUMN telegram_message_id INTEGER;
ALTER TABLE proxy_requests ADD COLUMN telegram_message_html TEXT;

ALTER TABLE git_sessions ADD COLUMN telegram_chat_id INTEGER;
ALTER TABLE git_sessions ADD COLUMN telegram_message_id INTEGER;
ALTER TABLE git_sessions ADD COLUMN telegram_message_html TEXT;

ALTER TABLE email_sessions ADD COLUMN telegram_chat_id INTEGER;
ALTER TABLE email_sessions ADD COLUMN telegram_message_id INTEGER;
ALTER TABLE email_sessions ADD COLUMN telegram_message_html TEXT;
