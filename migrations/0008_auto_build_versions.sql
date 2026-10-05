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
