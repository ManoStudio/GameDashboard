-- Kept separate from project payloads: webhook URLs contain posting credentials.
CREATE TABLE IF NOT EXISTS project_discord_webhooks (
  project_id TEXT PRIMARY KEY,
  webhook_url TEXT,
  enabled INTEGER NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
  channels_json TEXT NOT NULL DEFAULT '["dev","qa","live","deprecated"]',
  updated_by TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_attempt_at TEXT,
  last_sent_at TEXT,
  last_error TEXT
);
