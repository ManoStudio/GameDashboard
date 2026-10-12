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

-- Uploads already holding signed URLs continue through the existing protocol.
INSERT OR IGNORE INTO upload_queue
  (build_id,project_id,version,owner,channel,source,files_json,managed,status,phase,sort_order,created_at,updated_at,lease_expires_at)
SELECT build_id,project_id,version,uploaded_by,'dev','Legacy uploader','[]',0,'legacy','uploading',0,created_at,created_at,
  strftime('%Y-%m-%dT%H:%M:%fZ',created_at,'+30 minutes') FROM build_upload_versions;
