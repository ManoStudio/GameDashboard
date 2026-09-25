ALTER TABLE users ADD COLUMN google_sub TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_sub ON users(google_sub);

CREATE TABLE IF NOT EXISTS oauth_flows (
  state_hash TEXT PRIMARY KEY,
  nonce TEXT NOT NULL,
  mode TEXT NOT NULL,
  redirect_uri TEXT,
  client_state TEXT,
  code_challenge TEXT,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS desktop_auth_codes (
  code_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
