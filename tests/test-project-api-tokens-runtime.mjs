import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createHash } from 'node:crypto';
import * as miniflare from 'miniflare';

const parent = path.resolve('.wrangler');
await fs.mkdir(parent, { recursive: true });
const root = await fs.mkdtemp(path.join(parent, 'project-tokens-test-'));
assert.equal(path.dirname(path.resolve(root)), parent);
const source = (await fs.readFile('src/worker.js', 'utf8')).replace(/^import .*;\r?\n/gm, '');
const discordCall = 'const response = await fetch(url.toString(), {';
assert.ok(source.includes(discordCall));
// Capture outbound Discord requests in the local D1 fixture, never send messages.
const runtimeSource = source.replace(discordCall, 'const response = await captureDiscordWebhook(env, url.toString(), {') + `
async function captureDiscordWebhook(env, url, options) {
  await env.DB.prepare('INSERT INTO discord_test_messages (url, body) VALUES (?, ?)').bind(url, options.body).run();
  return Response.json({ id: 'test-message' });
}
`;
const options = {
  modules: true, script: runtimeSource, compatibilityDate: '2026-04-24', cf: false,
  d1Databases: ['DB'], r2Buckets: ['BUILDS_BUCKET'],
  bindings: { DASHBOARD_API_TOKEN: 'legacy-test-token', R2_ACCOUNT_ID: 'test', R2_ACCESS_KEY_ID: 'test', R2_SECRET_ACCESS_KEY: 'test', R2_BUCKET_NAME: 'test' },
  resourceTmpPath: path.join(root, 'tmp'), resourcePersistencePath: path.join(root, 'persist'),
};
const mf = new miniflare.Miniflare(miniflare.convertV4MiniflareOptions?.(options) ?? options);
try {
  const db = await mf.getD1Database('DB');
  // Exercise the migration against an existing database without the token table.
  const schema = (await fs.readFile('schema.sql', 'utf8')).split('CREATE TABLE IF NOT EXISTS project_api_tokens')[0];
  for (const sql of schema.split(';').map(value => value.trim()).filter(Boolean)) await db.prepare(sql).run();
  const migration = await fs.readFile('migrations/0009_project_api_tokens.sql', 'utf8');
  for (const sql of migration.split(';').map(value => value.trim()).filter(Boolean)) await db.prepare(sql).run();
  const discordMigration = await fs.readFile('migrations/0010_project_discord_webhooks.sql', 'utf8');
  for (const sql of discordMigration.split(';').map(value => value.trim()).filter(Boolean)) await db.prepare(sql).run();
  await db.prepare('CREATE TABLE discord_test_messages (url TEXT, body TEXT)').run();
  await db.prepare("INSERT INTO projects (id,name,icon,bundle_id,role,created_at,updated_at) VALUES ('game','Game','GM','game','viewer','','')").run();
  await db.prepare("INSERT INTO users (email,role,password_hash,created_at,updated_at) VALUES ('admin@test.com','admin','','','')").run();
  await db.prepare("INSERT INTO sessions (token_hash,email,expires_at,created_at) VALUES (?,'admin@test.com','2999-01-01T00:00:00.000Z','')")
    .bind(createHash('sha256').update('admin-session').digest('hex')).run();
  const origin = 'https://dashboard.test';
  const admin = { Cookie: 'sid=admin-session', Origin: origin, 'Content-Type': 'application/json' };
  const configured = await mf.dispatchFetch(origin + '/api/projects/game/discord-webhook', {
    method: 'PUT', headers: admin, body: JSON.stringify({ webhook_url: 'https://discord.com/api/webhooks/1234567890123456789/test-only-fake-posting-credential', enabled: true, channels: ['dev'] }),
  });
  assert.equal(configured.status, 200, await configured.clone().text());
  assert.ok(!(await configured.text()).includes('posting-credential'));
  const created = await mf.dispatchFetch(origin + '/api/projects/game/tokens', {
    method: 'POST', headers: admin, body: JSON.stringify({ name: 'Runtime CI', channels: ['dev'], expires_in_days: 30 }),
  });
  assert.equal(created.status, 201, await created.clone().text());
  assert.equal(created.headers.get('Cache-Control'), 'private, no-store');
  const issued = await created.json();
  const headers = { Authorization: `Bearer ${issued.token}`, 'Content-Type': 'application/json' };
  const files = [{ name: 'game.zip', size: 4, content_type: 'application/zip' }];
  const initialized = await mf.dispatchFetch(origin + '/api/projects/game/uploads/init', {
    method: 'POST', headers, body: JSON.stringify({ channel: 'dev', files }),
  });
  assert.equal(initialized.status, 200, await initialized.clone().text());
  const session = await initialized.json();
  const bucket = await mf.getR2Bucket('BUILDS_BUCKET');
  await bucket.put(session.uploads[0].object_path, 'game');
  const completed = await mf.dispatchFetch(`${origin}/api/projects/game/uploads/${session.build_id}/complete`, {
    method: 'POST', headers, body: JSON.stringify({ channel: 'dev', files: [{ ...files[0], object_path: session.uploads[0].object_path }] }),
  });
  assert.equal(completed.status, 201, await completed.clone().text());
  assert.equal((await completed.json()).version, 'GM-Build-1');
  let delivered = false;
  for (let attempt = 0; attempt < 30; attempt++) {
    const state = await db.prepare("SELECT last_sent_at FROM project_discord_webhooks WHERE project_id = 'game'").first();
    if (state.last_sent_at) { delivered = true; break; }
    await new Promise(resolve => setTimeout(resolve, 30));
  }
  assert.ok(delivered, 'waitUntil must finish notification delivery and persist status');
  const captured = await db.prepare('SELECT * FROM discord_test_messages').all();
  assert.equal(captured.results.length, 1);
  assert.equal(new URL(captured.results[0].url).searchParams.get('wait'), 'true');
  assert.deepEqual(JSON.parse(captured.results[0].body).allowed_mentions, { parse: [] });
  const editUrl = `${origin}/api/builds/${session.build_id}/details`;
  assert.equal((await mf.dispatchFetch(editUrl, { method: 'PATCH', headers, body: JSON.stringify({ focus_areas: ['forbidden'] }) })).status, 403);
  const edited = await mf.dispatchFetch(editUrl, {
    method: 'PATCH', headers: admin, body: JSON.stringify({ focus_areas: ['Later test focus'], test_instructions: 'Test after reconnect' }),
  });
  assert.equal(edited.status, 200, await edited.clone().text());
  const details = await edited.json();
  assert.deepEqual(details.focus_areas, ['Later test focus']);
  assert.ok(details.changelog.includes('## Test Focus\n- Later test focus'));
  assert.equal((await db.prepare('SELECT version FROM builds WHERE id = ?').bind(session.build_id).first()).version, 'GM-Build-1');
  assert.equal((await mf.dispatchFetch(origin + '/api/me', { headers: { Authorization: 'Bearer legacy-test-token' } })).status, 200);
  assert.equal((await mf.dispatchFetch(origin + '/api/projects/other/uploads/init', { method: 'POST', headers, body: JSON.stringify({ files }) })).status, 403);
  const revoked = await mf.dispatchFetch(`${origin}/api/projects/game/tokens/${issued.id}`, { method: 'DELETE', headers: admin });
  assert.equal(revoked.status, 200);
  assert.equal((await mf.dispatchFetch(origin + '/api/me', { headers: { ...headers, Cookie: 'sid=admin-session' } })).status, 401);
  console.log('PASS workerd + real D1/R2: migrations, token creation, upload, captured Discord delivery via waitUntil, build editing, scope denial, revocation.');
} finally {
  await mf.dispose();
  assert.equal(path.dirname(path.resolve(root)), parent);
  await fs.rm(root, { recursive: true, force: true });
}
