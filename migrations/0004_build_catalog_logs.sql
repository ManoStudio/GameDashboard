ALTER TABLE builds ADD COLUMN build_code TEXT;
ALTER TABLE builds ADD COLUMN platform TEXT NOT NULL DEFAULT 'Windows';
ALTER TABLE builds ADD COLUMN build_date TEXT;
ALTER TABLE builds ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1;

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

CREATE INDEX IF NOT EXISTS idx_logs_project_uploaded ON logs(project_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_build_version ON logs(build_id, version);
