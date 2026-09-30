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
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_bug_reports_project_created
  ON bug_reports(project_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_bug_reports_build_created
  ON bug_reports(build_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_bug_reports_status_created
  ON bug_reports(status, created_at DESC);
