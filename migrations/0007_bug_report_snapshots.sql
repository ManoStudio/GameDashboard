ALTER TABLE bug_reports ADD COLUMN snapshot_object_path TEXT;
ALTER TABLE bug_reports ADD COLUMN snapshot_size INTEGER NOT NULL DEFAULT 0;
ALTER TABLE bug_reports ADD COLUMN snapshot_content_type TEXT;
