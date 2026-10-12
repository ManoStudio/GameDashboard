import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { basename, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Node.js 24; no npm dependencies. Copy to tools/upload-game.mjs in the game repo.
export async function uploadGame(config, fetchImpl = fetch) {
  const { dashboardUrl, token, projectId, filePath, channel = 'dev', metadata = {} } = config;
  if (!dashboardUrl || !token || !projectId || !filePath) {
    throw new Error('Set GAME_DASHBOARD_URL, DASHBOARD_API_TOKEN, GAME_PROJECT_ID, and a ZIP file path.');
  }
  const base = new URL(dashboardUrl);
  if (base.protocol !== 'https:' || base.username || base.password || base.search || base.hash || base.pathname !== '/') {
    throw new Error('GAME_DASHBOARD_URL must be an HTTPS origin, e.g. https://game.manostudio.app');
  }
  if (!['dev', 'qa', 'live', 'deprecated'].includes(channel)) throw new Error('Invalid build channel.');
  if (!filePath.toLowerCase().endsWith('.zip')) throw new Error('Package the complete runnable game as a ZIP.');
  const info = await stat(filePath);
  if (!info.isFile() || !info.size) throw new Error('Build ZIP is missing or empty.');
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(filePath)) hash.update(chunk);
  const file = { name: basename(filePath), size: info.size, content_type: 'application/zip', hash: hash.digest('hex') };
  const apiPath = `/api/projects/${encodeURIComponent(projectId)}/uploads`;
  const release = { ...metadata, channel };

  async function send(url, options, label) {
    let response;
    try {
      response = await fetchImpl(url, { ...options, redirect: 'error' });
    } catch {
      // Do not include credentials or signed URLs in GitHub logs.
      throw new Error(`${label}: connection failed, timed out, or received a redirect.`);
    }
    if (!response.ok) {
      const hints = { 401: 'Check DASHBOARD_API_TOKEN.', 403: 'Check permissions or Cloudflare Access.', 404: 'Check the project ID and URL.', 500: 'Check Worker R2 secrets, D1 migrations, and Worker logs.' };
      throw new Error(`${label}: HTTP ${response.status}. ${hints[response.status] || 'Check Worker logs.'}`);
    }
    return response;
  }

  async function api(path, payload, label) {
    const response = await send(new URL(path, base), {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(60_000),
    }, label);
    try { return await response.json(); }
    catch { throw new Error(`${label}: expected a JSON response. Check the Dashboard URL and Access configuration.`); }
  }

  let session = await api(`${apiPath}/init`, { ...release, queue: true, files: [file] }, 'Initialize upload');
  if (!session.build_id || !session.version) throw new Error('Initialize upload: incomplete session response.');
  const sessionPath = `${apiPath}/${encodeURIComponent(session.build_id)}`;
  const queued = ['waiting', 'uploading'].includes(session.status);
  let heartbeat, reporting, transferred = 0, phase = 'uploading', confirmed = false;
  const controller = new AbortController();
  async function report() {
    if (reporting) return reporting;
    reporting = api(`${sessionPath}/progress`, { uploaded_bytes: transferred, phase }, 'Report upload progress').then(job => {
      if (job.status !== 'uploading') throw new Error('Upload session expired. Initialize a new upload.');
    }).finally(() => { reporting = undefined; });
    return reporting;
  }
  try {
    const waitingSince = Date.now();
    while (session.status === 'waiting') {
      if (Date.now() - waitingSince > 6 * 60 * 60_000) throw new Error('Timed out waiting in the upload queue.');
      config.onQueue?.({ version: session.version, position: session.position });
      await new Promise(resolve => setTimeout(resolve, config.pollIntervalMs ?? 3000));
      const response = await send(new URL(`${sessionPath}/status`, base), { headers: { Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(60_000) }, 'Check upload queue');
      session = await response.json();
    }
    if (session.status && session.status !== 'uploading') throw new Error('Upload session expired. Initialize a new upload.');
    const target = session.uploads?.[0];
    if (session.uploads?.length !== 1 || !target?.object_path || !target?.content_type || !target?.upload_url) {
      throw new Error('Initialize upload: incomplete session response.');
    }
    if (new URL(target.upload_url).protocol !== 'https:') throw new Error('Upload URL must use HTTPS.');
    if (queued) await report();
    const stream = createReadStream(filePath);
    async function* measuredBody() { for await (const chunk of stream) { transferred += chunk.length; yield chunk; } }
    try {
      await once(stream, 'open');
      if (queued) heartbeat = setInterval(() => report().catch(() => controller.abort()), 10000);
      const response = await send(target.upload_url, {
        method: 'PUT',
        headers: { 'Content-Type': target.content_type, 'Content-Length': String(file.size) },
        body: measuredBody(),
        duplex: 'half',
        // Signed URLs expire after 30 minutes; hashing happens before init.
        signal: AbortSignal.any([AbortSignal.timeout(25 * 60_000), controller.signal]),
      }, 'R2 upload');
      if (response.body) await response.body.cancel();
    } finally {
      stream.destroy();
    }
    clearInterval(heartbeat);
    if (reporting) await reporting;
    if (controller.signal.aborted) throw new Error('Upload progress heartbeat failed.');
    if (queued) { transferred = file.size; phase = 'finalizing'; await report(); }
    const build = await api(`${sessionPath}/complete`, {
      ...release,
      version: session.version,
      files: [{ ...file, content_type: target.content_type, object_path: target.object_path }],
    }, 'Complete upload');
    confirmed = true;
    return build;
  } catch (error) {
    clearInterval(heartbeat);
    if (reporting) await reporting.catch(() => {});
    if (queued && !confirmed) await api(`${sessionPath}/fail`, {}, 'Release upload queue slot').catch(() => {});
    throw error;
  } finally { clearInterval(heartbeat); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const build = await uploadGame({
      dashboardUrl: process.env.GAME_DASHBOARD_URL,
      token: process.env.DASHBOARD_API_TOKEN,
      projectId: process.env.GAME_PROJECT_ID,
      filePath: process.argv[2],
      channel: process.env.BUILD_CHANNEL || 'dev',
      metadata: {
        commit_sha: process.env.GITHUB_SHA || '',
        branch: process.env.GITHUB_REF_NAME || '',
        tag: process.env.GITHUB_REF_TYPE === 'tag' ? process.env.GITHUB_REF_NAME : '',
        build_source: 'github-actions',
        uploaded_by: `github-actions/${process.env.GITHUB_ACTOR || 'local'}`,
        changelog: process.env.BUILD_CHANGELOG || `CI build: ${process.env.GITHUB_REPOSITORY || 'game'} run ${process.env.GITHUB_RUN_NUMBER || 'local'}`,
      },
      onQueue: ({ version, position }) => console.log(`Waiting to upload ${version}, queue position #${position}`),
    });
    console.log(`Uploaded build ${build.id}, version ${build.version}, channel ${build.channel}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
