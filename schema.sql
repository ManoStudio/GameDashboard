CREATE TABLE IF NOT EXISTS users (
  email TEXT PRIMARY KEY,
  role TEXT NOT NULL,
  password_hash TEXT NOT NULL,
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

CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_builds_project_created ON builds(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_project_uploaded ON logs(project_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_build_version ON logs(build_id, version);
CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);
