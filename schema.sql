CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY,
  role TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  google_sub TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  icon TEXT NOT NULL,
  bundle_id TEXT NOT NULL,
  role TEXT NOT NULL,
  banner_title TEXT,
  banner_subtitle TEXT,
  description TEXT,
  cover_url TEXT,
  known_issues TEXT,
  test_instructions TEXT,
  focus_areas TEXT,
  maintenance_notice TEXT,
  save_path_hint TEXT,
  config_path_hint TEXT,
  recommended_profile TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

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

CREATE TABLE IF NOT EXISTS builds (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  version TEXT NOT NULL,
  build_code TEXT,
  platform TEXT NOT NULL DEFAULT 'Windows',
  build_date TEXT,
  channel TEXT NOT NULL,
  tag TEXT,
  changelog TEXT,
  status TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  commit_sha TEXT,
  uploaded_by TEXT,
  uploaded_at TEXT,
  manifest_id TEXT,
  checksum TEXT,
  branch TEXT,
  build_source TEXT,
  known_issues TEXT,
  test_instructions TEXT,
  focus_areas TEXT,
  save_path_hint TEXT,
  config_path_hint TEXT,
  file_count INTEGER NOT NULL,
  total_size INTEGER NOT NULL,
  storage_path TEXT NOT NULL,
  manifest_path TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS logs (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  build_id TEXT NOT NULL,
  version TEXT NOT NULL,
  session_id TEXT NOT NULL,
  machine_name TEXT NOT NULL,
  uploaded_at TEXT NOT NULL,
  size INTEGER NOT NULL DEFAULT 0,
  file_url TEXT,
  metadata_json TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS bug_reports (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  build_id TEXT NOT NULL,
  version TEXT NOT NULL,
  reporter_email TEXT NOT NULL,
  description TEXT NOT NULL,
  unity_version TEXT NOT NULL DEFAULT '',
  scene_name TEXT NOT NULL DEFAULT '',
  session_id TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'new',
  log_object_path TEXT,
  log_size INTEGER NOT NULL DEFAULT 0,
  snapshot_object_path TEXT,
  snapshot_size INTEGER NOT NULL DEFAULT 0,
  snapshot_content_type TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_builds_project_created ON builds(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_project_uploaded ON logs(project_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_build_version ON logs(build_id, version);
CREATE INDEX IF NOT EXISTS idx_bug_reports_project_created ON bug_reports(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bug_reports_build_created ON bug_reports(build_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_bug_reports_status_created ON bug_reports(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);

-- Counters survive build deletion. Abandoned uploads may leave gaps, never reused numbers.
CREATE TABLE IF NOT EXISTS project_build_counters (
  project_id TEXT PRIMARY KEY,
  last_number INTEGER NOT NULL CHECK (last_number > 0)
);

CREATE TABLE IF NOT EXISTS build_upload_versions (
  build_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  version TEXT NOT NULL,
  uploaded_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS project_api_tokens (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  name TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_prefix TEXT NOT NULL,
  channels_json TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  expires_at TEXT,
  last_used_at TEXT,
  revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_project_api_tokens_project ON project_api_tokens(project_id, created_at DESC);

-- Never include this table in public project or Launcher payloads.
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
CREATE TABLE IF NOT EXISTS upload_queue (
  build_id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  version TEXT NOT NULL,
  owner TEXT NOT NULL,
  channel TEXT NOT NULL,
  source TEXT NOT NULL DEFAULT '',
  branch TEXT NOT NULL DEFAULT '',
  files_json TEXT NOT NULL,
  total_bytes INTEGER NOT NULL DEFAULT 0,
  uploaded_bytes INTEGER NOT NULL DEFAULT 0,
  managed INTEGER NOT NULL DEFAULT 1 CHECK (managed IN (0,1)),
  status TEXT NOT NULL CHECK (status IN ('waiting','uploading','finalizing','legacy','completed','failed','expired')),
  phase TEXT NOT NULL DEFAULT 'waiting',
  sort_order INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  lease_expires_at TEXT NOT NULL,
  started_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_upload_queue_project_status ON upload_queue(project_id, status, sort_order, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_upload_queue_single_active ON upload_queue(project_id) WHERE status IN ('uploading','finalizing');
