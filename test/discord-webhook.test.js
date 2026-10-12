import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { DatabaseSync } from 'node:sqlite';
import { createHash, webcrypto } from 'node:crypto';
import { renderAdmin } from '../src/admin-pages.js';

const origin = 'https://dashboard.test';
const webhook = 'https://discord.com/api/webhooks/1234567890123456789/test-only-fake-posting-credential';
const secondWebhook = 'https://discord.com/api/webhooks/2234567890123456789/second-fake-posting-credential';
const source = fs.readFileSync('src/worker.js', 'utf8').replace(/^import .*;\r?\n/gm, '').replace('export default {', 'const worker = {');

function runtime(t) {
  const db = new DatabaseSync(':memory:');
  db.exec(fs.readFileSync('schema.sql', 'utf8'));
  db.exec(fs.readFileSync('migrations/0010_project_discord_webhooks.sql', 'utf8'));
  t.after(() => db.close());
  for (const id of ['game', 'other']) db.prepare("INSERT INTO projects (id,name,icon,bundle_id,role,created_at,updated_at) VALUES (?,?,'GM',?,'viewer','','')").run(id, id, id);
  for (const role of ['admin', 'dev', 'QA', 'viewer']) {
    db.prepare("INSERT INTO users (email,role,password_hash,created_at,updated_at) VALUES (?,?,'','','')").run(`${role}@test`, role);
    db.prepare("INSERT INTO sessions (token_hash,email,expires_at,created_at) VALUES (?,?,'2999-01-01T00:00:00.000Z','')")
      .run(createHash('sha256').update(role).digest('hex'), `${role}@test`);
  }
  const warnings = [];
  const requests = [];
  let transport = async () => Response.json({ id: 'test-message' });
  const env = { DASHBOARD_API_TOKEN: 'legacy-token', R2_ACCOUNT_ID: 'test', R2_ACCESS_KEY_ID: 'test', R2_SECRET_ACCESS_KEY: 'test', R2_BUCKET_NAME: 'test', DB: { prepare(sql) {
    const query = args => ({ first: async () => db.prepare(sql).get(...args) ?? null, all: async () => ({ results: db.prepare(sql).all(...args) }), run: async () => db.prepare(sql).run(...args) });
    return { ...query([]), bind: (...args) => query(args) };
  } } };
  const context = vm.createContext({ URL, URLSearchParams, Request, Response, Headers, AbortSignal, TextEncoder, TextDecoder, Uint8Array, crypto: webcrypto,
    console: { ...console, warn: value => warnings.push(value) },
    fetch: async (url, options) => { requests.push({ url, options }); return transport(url, options); },
  });
  vm.runInContext(source, context);
  context.rowToBuild = async (_env, row) => row;
  const worker = vm.runInContext('worker', context);
  const tasks = [];
  async function call(path, { method = 'GET', payload, role = 'admin', token, requestOrigin = origin, contentType = 'application/json' } = {}) {
    return worker.fetch(new Request(origin + path, {
      method, headers: { Cookie: `sid=${role}`, ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(requestOrigin === null ? {} : { Origin: requestOrigin }), 'Content-Type': contentType },
      ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
    }), env, { waitUntil(promise) { tasks.push(promise); } });
  }
  const save = (project = 'game', changes = {}) => call(`/api/projects/${project}/discord-webhook`, { method: 'PUT', payload: { webhook_url: project === 'game' ? webhook : secondWebhook, enabled: true, channels: ['dev', 'qa'], ...changes } });
  async function upload(project = 'game', channel = 'dev', token) {
    const files = [{ name: 'game.zip', size: 100, content_type: 'application/zip' }];
    const init = await call(`/api/projects/${project}/uploads/init`, { method: 'POST', token, payload: { channel, files } });
    assert.equal(init.status, 200, await init.clone().text());
    const session = await init.json();
    const body = { channel, changelog: '@everyone [fake link](https://outside.test) ' + 'x'.repeat(3000), files: [{ ...files[0], object_path: session.uploads[0].object_path }] };
    const path = `/api/projects/${project}/uploads/${session.build_id}/complete`;
    return { response: await call(path, { method: 'POST', token, payload: body }), path, body, token };
  }
  const flush = () => Promise.all(tasks.splice(0));
  return { db, env, context, warnings, requests, tasks, call, save, upload, flush, setTransport(value) { transport = value; } };
}

test('webhook settings are project-specific, write-only, preserve blank URLs, and reset status when replaced', async t => {
  const { db, call, save, requests } = runtime(t);
  assert.equal((await save()).status, 200);
  assert.equal((await save('other')).status, 200);
  const state = await call('/api/projects/game/discord-webhook');
  assert.equal(state.headers.get('Cache-Control'), 'private, no-store');
  const text = await state.text();
  assert.ok(!text.includes(webhook));
  assert.ok(!text.includes('posting-credential'));
  assert.equal(JSON.parse(text).configured, true);
  db.prepare("UPDATE project_discord_webhooks SET last_sent_at = 'sent', last_error = 'old-error' WHERE project_id = 'game'").run();
  assert.equal((await save('game', { webhook_url: '', enabled: false, channels: ['live'] })).status, 200);
  let row = db.prepare("SELECT * FROM project_discord_webhooks WHERE project_id = 'game'").get();
  assert.equal(row.webhook_url, webhook);
  assert.equal(row.enabled, 0);
  assert.equal(row.last_sent_at, 'sent');
  assert.equal((await save('game', { webhook_url: secondWebhook })).status, 200);
  row = db.prepare("SELECT * FROM project_discord_webhooks WHERE project_id = 'game'").get();
  assert.equal(row.last_sent_at, null);
  assert.equal(row.last_error, null);
  const projects = await (await call('/api/projects')).json();
  assert.ok(!JSON.stringify(projects).includes('webhook'));
  assert.equal(requests.length, 0, 'Saving settings must not send a message');
  assert.equal((await call('/api/projects/game/discord-webhook', { method: 'DELETE' })).status, 200);
  assert.equal(db.prepare('SELECT count(*) AS n FROM project_discord_webhooks').get().n, 1);
});

test('only signed-in admins configure and test webhooks; origin checks and project scope are enforced', async t => {
  const { call, save, requests } = runtime(t);
  await save();
  for (const role of ['dev', 'QA', 'viewer']) {
    for (const [method, path] of [['GET', '/api/projects/game/discord-webhook'], ['PUT', '/api/projects/game/discord-webhook'], ['POST', '/api/projects/game/discord-webhook/test'], ['DELETE', '/api/projects/game/discord-webhook']]) assert.equal((await call(path, { method, role })).status, 403);
  }
  assert.equal((await call('/api/projects/game/discord-webhook', { token: 'legacy-token' })).status, 403);
  const issued = await (await call('/api/projects/game/tokens', { method: 'POST', payload: { name: 'CI', channels: ['dev'] } })).json();
  assert.equal((await call('/api/projects/game/discord-webhook', { token: issued.token })).status, 403);
  for (const requestOrigin of [null, 'https://attacker.test']) assert.equal((await call('/api/projects/game/discord-webhook/test', { method: 'POST', requestOrigin })).status, 403);
  assert.equal((await call('/api/projects/game/discord-webhook', { method: 'PUT', contentType: 'text/plain' })).status, 415);
  assert.equal((await call('/api/projects/missing/discord-webhook')).status, 404);
  assert.equal(requests.length, 0);
});

test('URL validation rejects off-host/redirect targets, credentials, ports, invalid paths and invalid settings', async t => {
  const { context, save, call, requests } = runtime(t);
  for (const webhook_url of ['http://discord.com/api/webhooks/1234567890123456789/long-enough-credential', 'https://discord.com.evil.test/api/webhooks/1234567890123456789/long-enough-credential', 'https://localhost/api/webhooks/1234567890123456789/long-enough-credential', webhook.replace('discord.com', 'user:password@discord.com'), webhook.replace('discord.com', 'discord.com:8443'), webhook + '?wait=false', webhook + '#secret', webhook.replace('/api/', '/other/'), webhook + '?thread_id=invalid']) {
    assert.equal((await save('game', { webhook_url })).status, 400, webhook_url);
  }
  for (const settings of [{ enabled: 'true' }, { channels: [] }, { channels: ['admin'] }, { webhook_url: null }]) assert.equal((await save('game', settings)).status, 400);
  assert.equal((await call('/api/projects/game/discord-webhook', { method: 'PUT', payload: null })).status, 400);
  assert.equal((await save('game', { webhook_url: '' })).status, 400);
  assert.equal(context.normalizeDiscordWebhook(webhook.replace('discord.com', 'discordapp.com')), webhook);
  assert.equal(context.normalizeDiscordWebhook(webhook + '?thread_id=1234567890123456789'), webhook + '?thread_id=1234567890123456789');
  assert.equal(requests.length, 0);
});

test('successful completion schedules one notification after registration, including CI uploads', async t => {
  const { db, call, save, upload, flush, requests, tasks } = runtime(t);
  await save();
  const issued = await (await call('/api/projects/game/tokens', { method: 'POST', payload: { name: 'CI', channels: ['dev'] } })).json();
  const uploaded = await upload('game', 'dev', issued.token);
  assert.equal(uploaded.response.status, 201);
  const build = await uploaded.response.json();
  assert.equal(db.prepare('SELECT id FROM builds WHERE id = ?').get(build.id).id, build.id);
  assert.equal(tasks.length, 1);
  await flush();
  assert.equal(requests.length, 1);
  const { url, options } = requests[0];
  assert.equal(new URL(url).searchParams.get('wait'), 'true');
  assert.equal(options.method, 'POST');
  assert.equal(options.redirect, 'error');
  const message = JSON.parse(options.body);
  assert.deepEqual(message.allowed_mentions, { parse: [] });
  assert.ok(message.embeds[0].url.includes(`build=${build.id}`));
  assert.ok(!JSON.stringify(message).includes(issued.token));
  assert.ok(!JSON.stringify(message).includes(webhook));
  assert.ok(message.embeds[0].description.length <= 1200);
  assert.ok(message.embeds[0].description.includes('\\[fake link\\]'));
  assert.equal((await call(uploaded.path, { method: 'POST', token: issued.token, payload: uploaded.body })).status, 400);
  await flush();
  assert.equal(requests.length, 1, 'Repeated completion must not notify twice');
  assert.ok(db.prepare("SELECT last_sent_at FROM project_discord_webhooks WHERE project_id = 'game'").get().last_sent_at);
});

test('missing, disabled and filtered webhooks are skipped; one project cannot notify another destination', async t => {
  const { save, upload, flush, requests } = runtime(t);
  assert.equal((await upload()).response.status, 201); await flush();
  await save('game', { enabled: false });
  assert.equal((await upload()).response.status, 201); await flush();
  await save('game', { channels: ['live'] });
  assert.equal((await upload()).response.status, 201); await flush();
  assert.equal(requests.length, 0);
  await save('other');
  assert.equal((await upload('other')).response.status, 201); await flush();
  assert.equal(requests.length, 1);
  assert.ok(requests[0].url.startsWith(secondWebhook));
});

test('Discord errors, connection errors and notification storage failures cannot fail a completed upload', async t => {
  const { db, env, save, upload, flush, setTransport, requests, warnings } = runtime(t);
  await save();
  for (const status of [404, 429, 500]) {
    setTransport(async () => new Response('Secret details must not leak: ' + webhook, { status }));
    assert.equal((await upload()).response.status, 201);
    await flush();
    assert.equal(db.prepare("SELECT last_error FROM project_discord_webhooks WHERE project_id = 'game'").get().last_error, `Discord HTTP ${status}`);
  }
  setTransport(async () => { throw new Error('Sensitive URL: ' + webhook); });
  assert.equal((await upload()).response.status, 201); await flush();
  assert.ok(!warnings.join('\n').includes('posting-credential'));
  assert.equal(requests.length, 4, 'No automatic retries that might duplicate messages');
  const prepare = env.DB.prepare;
  env.DB.prepare = sql => { if (sql.includes('project_discord_webhooks')) throw new Error('Database unavailable'); return prepare(sql); };
  assert.equal((await upload()).response.status, 201); await flush();
});

test('failed initialization or completion sends no notification; explicit tests confirm delivery without creating builds', async t => {
  const { db, call, save, requests, tasks, context } = runtime(t);
  await save();
  assert.equal((await call('/api/projects/missing/uploads/init', { method: 'POST', payload: { files: [{ name: 'game.zip' }] } })).status, 404);
  assert.equal((await call('/api/projects/game/uploads/missing/complete', { method: 'POST', payload: { files: [{ name: 'game.zip' }] } })).status, 400);
  assert.equal(tasks.length, 0);
  const initial = await (await call('/api/projects/game/uploads/init', { method: 'POST', payload: { files: [{ name: 'game.zip' }] } })).json();
  const saveBuild = context.saveBuild;
  context.saveBuild = async () => { throw new Error('Build DB write failed'); };
  assert.equal((await call(`/api/projects/game/uploads/${initial.build_id}/complete`, { method: 'POST', payload: { files: [{ name: 'game.zip', object_path: initial.uploads[0].object_path }] } })).status, 500);
  context.saveBuild = saveBuild;
  assert.equal(tasks.length, 0);
  assert.equal(requests.length, 0);
  assert.equal((await call('/api/projects/game/discord-webhook/test', { method: 'POST' })).status, 200);
  assert.equal(requests.length, 1);
  assert.equal(db.prepare('SELECT count(*) AS n FROM builds').get().n, 0);
});

test('only signed-in admins see the webhook form; HTML and server state contain no posting URL', async t => {
  const { context } = runtime(t);
  const project = { id: 'game', name: 'Game', icon: 'GM', role: 'viewer' };
  const forms = { style: () => '', projectManagement: () => '', userAccess: () => '', discordWebhookPanel: context.discordWebhookPanel };
  const fixture = { user: { role: 'admin', email: 'admin@test', auth_type: 'session' }, projects: [project], selected: project, builds: [], users: [], view: 'settings', discordWebhook: { configured: true, enabled: true, channels: ['dev'], last_error: '<script>bad</script>' } };
  const html = renderAdmin(fixture, forms);
  assert.ok(html.includes('data-discord-settings'));
  assert.ok(html.includes('type="password" name="webhook_url"'));
  assert.ok(html.includes('&lt;script&gt;bad&lt;/script&gt;'));
  assert.ok(!html.includes(webhook));
  for (const user of [{ role: 'dev', email: 'dev@test', auth_type: 'session' }, { role: 'admin', email: 'api-token', auth_type: 'legacy-token' }]) assert.ok(!renderAdmin({ ...fixture, user }, forms).includes('data-discord-settings'));
});
