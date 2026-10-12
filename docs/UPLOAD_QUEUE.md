# Upload queue

Open **Upload queue** in the selected project's sidebar. Developers and admins can see in-progress builds, their reported percentage and byte counts, package names, channel, source, branch, and waiting position. The page refreshes every three seconds. Drag a waiting build or use its up/down buttons; the saved order determines which build is admitted next. Active transfers finish before another queued build starts. Different projects have independent queues and can upload concurrently.

The Dashboard uploader joins this queue automatically. Keep its tab open, including while waiting. Use **Open upload queue** in the progress panel to monitor or arrange jobs in another tab. **Cancel upload** releases that upload's slot. Closing the uploader tab or stopping a CI job makes its lease expire after five minutes without a heartbeat; a subsequent queue request admits the next connected job. Admission is enforced by an atomic database update and a unique index, rather than by sorting a list in the browser.

## GitHub Actions

Replace the copy of `tools/upload-game.mjs` in each game repository with `examples/github-actions/upload-game.mjs` from this repository. The workflow YAML and secrets stay the same. The new uploader requests `queue: true`, waits for admission, reports progress, and releases its slot on errors. Waiting positions are printed to the Actions log. It waits up to six hours; ensure the workflow's timeout is long enough for your build and queue. Jobs serialized by GitHub's own `concurrency` setting only enter the Dashboard queue when their uploader step starts.

Older scripts that already receive signed URLs still work and appear as **Uploading · legacy script**. They cannot be reordered or serialized retroactively, because their direct R2 transfers have already been authorized. Update every CI uploader to use the managed queue. Legacy transfers do not report live bytes and expire from the queue after 30 minutes. Jobs initialized before deployment are migrated as legacy uploads.

Percentages use client-reported progress, not R2 polling. Node.js reports bytes read into its streaming request; the final build is registered only after PUT succeeds. Expired managed uploads cannot register a build. Expiration does not physically revoke an already-issued R2 URL, and files from failed uploads are not automatically deleted by this queue. Build numbers are reserved at initialization, so manual ordering can change the arrival order of version numbers and failed jobs can leave gaps.

## API

All responses containing upload state or signed URLs have `Cache-Control: private, no-store`. Upload credentials can only poll/report/fail their own sessions in their assigned project. Queue listing and manual ordering are for Dashboard developers/admins; reordering additionally requires a signed-in browser session and same-origin JSON request.

1. `POST /api/projects/{project}/uploads/init` with `{ "queue": true, "channel": "dev", "files": [{ "name": "game.zip", "size": 1234, "content_type": "application/zip" }] }`.
2. `200` with `status: "uploading"` includes signed `uploads`. `202` with `status: "waiting"` includes `build_id`, reserved `version`, `position`, and `poll_after_seconds: 3`, without signed URLs.
3. Poll `GET /api/projects/{project}/uploads/{build}/status` until uploading. This renews a live lease and supplies signed URLs once admitted. A terminal `expired`/`failed` state requires a fresh upload.
4. During hashing/transfer, `POST .../{build}/progress` every ten seconds with `{ "uploaded_bytes": 123, "phase": "uploading" }`. Phases: `preparing`, `hashing`, `uploading`, `finalizing`. Byte counts are bounded and cannot decrease. Heartbeat replies omit signed URLs.
5. PUT each file to its signed R2 URL, then use the existing `POST .../{build}/complete` with the matching files and channel. On failure, `POST .../{build}/fail` with `{}`.
6. Dashboard only: `GET /api/projects/{project}/upload-queue`; `POST .../upload-queue/reorder` with `{ "build_ids": ["build-next", "build-after"] }`, containing every currently waiting ID exactly once. An outdated list returns `409`; refresh before retrying. Up to 200 waiting jobs per project.

Apply D1 migration `0011_upload_queue.sql` before deploying the Worker. It adds the queue table and preserves pre-existing upload reservations.
