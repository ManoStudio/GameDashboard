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
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS builds (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  version TEXT NOT NULL,
  channel TEXT NOT NULL,
  tag TEXT,
  changelog TEXT,
  status TEXT NOT NULL,
  file_count INTEGER NOT NULL,
  total_size INTEGER NOT NULL,
  storage_path TEXT NOT NULL,
  manifest_path TEXT NOT NULL,
  manifest_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_projects_created_at ON projects(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_builds_project_created ON builds(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_email ON sessions(email);
