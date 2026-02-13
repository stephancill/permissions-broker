PRAGMA foreign_keys = ON;

ALTER TABLE proxy_requests ADD COLUMN method TEXT NOT NULL DEFAULT 'GET';
ALTER TABLE proxy_requests ADD COLUMN request_headers_json TEXT;
ALTER TABLE proxy_requests ADD COLUMN request_body_base64 TEXT;
