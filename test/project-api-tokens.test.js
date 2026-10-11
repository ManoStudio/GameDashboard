import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { DatabaseSync } from 'node:sqlite';
import { createHash, webcrypto } from 'node:crypto';
import { renderAdmin } from '../src/admin-pages.js';

const hash = value => createHash('sha256').update(value).digest('hex');
const origin = 'https://dashboard.test';
const adminCookie = 'sid=test-admin-session';
const source = fs.readFileSync('src/worker.js', 'utf8').replace(/^import .*;\r?\n/gm, '').replace('export default {', 'const worker = {');

function runtime(t) {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(fs.readFileSync('schema.sql', 'utf8'));
  sqlite.exec(fs.readFileSync('migrations/0009_project_api_tokens.sql', 'utf8'));
  t.after(() => sqlite.close());
  for (const id of ['game', 'other']) {
    sqlite.prepare("INSERT INTO projects (id, name, icon, bundle_id, role, created_at, updated_at) VALUES (?, ?, 'GM', ?, 'admin', '', '')").run(id, id, id);
  }
  for (const role of ['admin', 'dev', 'QA', 'viewer']) {
    sqlite.prepare("INSERT INTO users (email, role, password_hash, created_at, updated_at) VALUES (?, ?, '', '', '')").run(`${role}@test.com`, role);
    sqlite.prepare("INSERT INTO sessions (token_hash, email, expires_at, created_at) VALUES (?, ?, '2999-01-01T00:00:00.000Z', '')").run(hash(`test-${role}-session`), `${role}@test.com`);
  }
  const env = { DASHBOARD_API_TOKEN: 'old-global-token', R2_ACCOUNT_ID: 'test', R2_ACCESS_KEY_ID: 'test', R2_SECRET_ACCESS_KEY: 'test', R2_BUCKET_NAME: 'test', DB: {
    prepare(sql) {
      const query = args => ({
        first: async () => sqlite.prepare(sql).get(...args) ?? null,
        all: async () => ({ results: sqlite.prepare(sql).all(...args) }),
        run: async () => { const result = sqlite.prepare(sql).run(...args); return { meta: { changes: Number(result.changes) } }; },
      });
      return { ...query([]), bind: (...args) => query(args) };
    },
  } };
  const context = vm.createContext({ TextEncoder, TextDecoder, Uint8Array, URL, URLSearchParams, Request, Response, Headers, atob, crypto: webcrypto, console });
  vm.runInContext(source, context);
  context.rowToBuild = async (_env, row) => row;
  const worker = vm.runInContext('worker', context);
  async function call(path, { method = 'GET', payload, token, cookie = token ? undefined : adminCookie, requestOrigin = origin, contentType = 'application/json' } = {}) {
    return worker.fetch(new Request(origin + path, {
      method,
      headers: {
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...(cookie ? { Cookie: cookie } : {}),
        ...(requestOrigin !== null ? { Origin: requestOrigin } : {}),
        'Content-Type': contentType,
      },
      ...(payload === undefined ? {} : { body: JSON.stringify(payload) }),
    }), env);
  }
  async function issue(project = 'game', settings = {}) {
    const response = await call(`/api/projects/${project}/tokens`, { method: 'POST', payload: { name: 'GitHub Windows', channels: ['dev', 'qa'], ...settings } });
    assert.equal(response.status, 201, await response.clone().text());
    assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
    return response.json();
  }
  return { sqlite, env, context, call, issue };
}

test('admin creates multiple project tokens; only hashes persist and lists never return secrets', async t => {
  const { sqlite, call, issue } = runtime(t);
  const one = await issue(); const two = await issue(); const other = await issue('other');
  assert.match(one.token, /^gd_[0-9a-f]{64}$/);
  assert.notEqual(one.token, two.token);
  assert.notEqual(one.id, two.id);
  assert.deepEqual(one.channels, ['dev', 'qa']);
  const stored = sqlite.prepare('SELECT * FROM project_api_tokens WHERE id = ?').get(one.id);
  assert.equal(stored.token_hash, hash(one.token));
  assert.equal(stored.token_prefix, one.token.slice(0, 11));
  assert.ok(!JSON.stringify(stored).includes(one.token));
  const response = await call('/api/projects/game/tokens');
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(response.headers.get('Cache-Control'), 'private, no-store');
  const listed = await response.json();
  assert.equal(listed.length, 2);
  for (const row of listed) { assert.equal(row.token, undefined); assert.equal(row.token_hash, undefined); assert.notEqual(row.id, other.id); }
  assert.ok(Date.parse(one.expires_at) > Date.now());
});

test('only signed-in admins manage tokens; mutations reject cross-origin and non-JSON requests', async t => {
  const { call, issue } = runtime(t);
  const token = await issue();
  const path = '/api/projects/game/tokens';
  for (const role of ['dev', 'QA', 'viewer']) assert.equal((await call(path, { cookie: `sid=test-${role}-session` })).status, 403);
  assert.equal((await call(path, { cookie: '' })).status, 401);
  assert.equal((await call(path, { token: 'old-global-token' })).status, 403);
  assert.equal((await call(path, { token: token.token })).status, 403);
  const payload = { name: 'Test', channels: ['dev'] };
  for (const requestOrigin of ['https://attacker.test', null]) {
    assert.equal((await call(path, { method: 'POST', payload, requestOrigin })).status, 403);
    assert.equal((await call(`${path}/${token.id}`, { method: 'DELETE', requestOrigin })).status, 403);
  }
  assert.equal((await call(path, { method: 'POST', payload, contentType: 'text/plain' })).status, 415);
  assert.equal((await call('/api/projects/missing/tokens', { method: 'POST', payload })).status, 404);
});

test('token settings reject invalid name, channel, expiry and oversized payload', async t => {
  const { call, issue } = runtime(t);
  for (const invalid of [null, [], { name: '' }, { name: 'x'.repeat(101) }, { channels: [] }, { channels: ['admin'] }, { channels: ['deprecated'] }, { expires_in_days: -1 }, { expires_in_days: '90' }, { name: 'x'.repeat(5000) }]) {
    const payload = invalid === null || Array.isArray(invalid) ? invalid : { name: 'CI', channels: ['dev'], ...invalid };
    assert.equal((await call('/api/projects/game/tokens', { method: 'POST', payload })).status, 400);
  }
  assert.equal((await issue('game', { expires_in_days: 0 })).expires_at, null);
});

test('project tokens upload only their project and selected channels, including explicit live access', async t => {
  const { call, issue, sqlite } = runtime(t);
  const issued = await issue('game', { channels: ['dev'] });
  const files = [{ name: 'game.zip', size: 100, content_type: 'application/zip' }];
  const options = channel => ({ method: 'POST', token: issued.token, payload: { channel, files } });
  assert.equal((await call('/api/projects/other/uploads/init', options('dev'))).status, 403);
  assert.equal((await call('/api/projects/game/uploads/init', options('qa'))).status, 403);
  assert.equal((await call('/api/projects/game/uploads/init', options('live'))).status, 403);
  const response = await call('/api/projects/game/uploads/init', options('dev'));
  assert.equal(response.status, 200);
  const session = await response.json();
  assert.equal(session.version, 'GM-Build-1');
  assert.match(session.uploads[0].upload_url, /^https:\/\/test\.r2\.cloudflarestorage\.com/);
  assert.equal(sqlite.prepare('SELECT count(*) AS n FROM build_upload_versions').get().n, 1);
  assert.ok(sqlite.prepare('SELECT last_used_at FROM project_api_tokens WHERE id = ?').get(issued.id).last_used_at);
  const live = await issue('game', { channels: ['live'] });
  assert.equal((await call('/api/projects/game/uploads/init', { method: 'POST', token: live.token, payload: { channel: 'live', files } })).status, 200);
  const projects = await (await call('/api/projects', { token: issued.token })).json();
  assert.deepEqual(projects.map(project => project.id), ['game']);
});

test('upload completion binds token identity, project, channel and storage paths', async t => {
  const { call, issue, sqlite } = runtime(t);
  const one = await issue('game', { channels: ['dev'] }); const two = await issue();
  const files = [{ name: 'game.zip', size: 100, content_type: 'application/zip' }];
  const session = await (await call('/api/projects/game/uploads/init', { method: 'POST', token: one.token, payload: { channel: 'dev', files } })).json();
  const payload = { version: 'forged', channel: 'dev', files: [{ ...files[0], object_path: session.uploads[0].object_path, hash: 'sha256-test' }] };
  const path = `/api/projects/game/uploads/${session.build_id}/complete`;
  const complete = (token, body = payload) => call(path, { method: 'POST', token, payload: body });
  assert.equal((await complete(two.token)).status, 400);
  assert.equal((await complete(one.token, { ...payload, channel: 'live' })).status, 403);
  assert.equal((await complete(one.token, { ...payload, files: [{ ...payload.files[0], object_path: 'builds/other/private/files/game.zip' }] })).status, 400);
  assert.equal(sqlite.prepare('SELECT count(*) AS n FROM builds').get().n, 0);
  const done = await complete(one.token);
  assert.equal(done.status, 201, await done.clone().text());
  const build = await done.json();
  assert.equal(build.version, 'GM-Build-1');
  assert.equal(build.project_id, 'game');
  assert.equal(build.uploaded_by, `project-token:${one.id}`);
});

test('project token cannot use admin, download, launcher, deletion or promotion routes', async t => {
  const { call, issue, sqlite } = runtime(t);
  const token = (await issue()).token;
  for (const [method, path] of [
    ['GET', '/'], ['GET', '/api/launcher/library'], ['GET', '/api/projects/other/builds'],
    ['GET', '/api/artifacts/builds/other/private/game.zip'], ['HEAD', '/api/artifacts/builds/game/private/game.zip'],
    ['POST', '/projects'], ['POST', '/users'], ['DELETE', '/api/projects/game'],
    ['POST', '/builds/private/rollback'], ['PATCH', '/api/builds/private/channel'], ['PATCH', '/api/builds/private/details'], ['DELETE', '/api/builds/private'],
    ['POST', '/api/projects/other/uploads/private/complete'], ['POST', '/api/projects/game/tokens'],
  ]) assert.equal((await call(path, { method, token })).status, 403, `${method} ${path}`);
  assert.equal(sqlite.prepare('SELECT count(*) AS n FROM projects').get().n, 2);
});

test('revoke, expiry and deleted projects invalidate authentication without falling back to cookies', async t => {
  const { call, issue, sqlite } = runtime(t);
  const one = await issue(); const other = await issue('other');
  assert.equal((await call(`/api/projects/other/tokens/${one.id}`, { method: 'DELETE' })).status, 404);
  const session = await (await call('/api/projects/game/uploads/init', { method: 'POST', token: one.token, payload: { files: [{ name: 'game.zip', size: 1 }] } })).json();
  assert.equal((await call(`/api/projects/game/tokens/${one.id}`, { method: 'DELETE' })).status, 200);
  assert.equal((await call(`/api/projects/game/tokens/${one.id}`, { method: 'DELETE' })).status, 200);
  for (const path of ['/api/me', `/api/projects/game/uploads/${session.build_id}/complete`]) {
    assert.equal((await call(path, { method: path.includes('complete') ? 'POST' : 'GET', token: one.token, cookie: adminCookie, payload: path.includes('complete') ? { files: [] } : undefined })).status, 401);
  }
  assert.equal((await call('/api/me', { token: other.token })).status, 200);
  sqlite.prepare("UPDATE project_api_tokens SET expires_at = '2000-01-01T00:00:00.000Z' WHERE id = ?").run(other.id);
  assert.equal((await call('/api/me', { token: other.token, cookie: adminCookie })).status, 401);
  const deleted = await issue();
  sqlite.prepare("DELETE FROM projects WHERE id = 'game'").run();
  assert.equal((await call('/api/me', { token: deleted.token })).status, 401);
});

test('legacy global Bearer token remains compatible and malformed Bearer never authenticates a cookie', async t => {
  const { call } = runtime(t);
  assert.equal((await call('/api/launcher/library', { token: 'old-global-token' })).status, 200);
  assert.equal((await call('/api/me', { token: 'incorrect', cookie: adminCookie })).status, 401);
  assert.equal((await call('/api/me', { token: 'gd_' + '0'.repeat(64), cookie: adminCookie })).status, 401);
});

test('settings shows escaped token metadata only to signed-in admins', async t => {
  const { context } = runtime(t);
  const project = { id: 'game', name: 'Game', icon: 'GM', role: 'viewer' };
  const tokens = [{ id: 'token-test', name: '<script>bad</script>', token_prefix: 'gd_12345678', channels: ['dev'], created_at: '', expires_at: null, last_used_at: null, revoked_at: null }];
  const forms = { createProjectForm: () => '', projectManagement: () => '', userAccess: () => '', apiTokenPanel: context.apiTokenPanel, style: () => '' };
  const fixture = { user: { role: 'admin', auth_type: 'session', email: 'admin@test' }, projects: [project], selected: project, builds: [], users: [], apiTokens: tokens, view: 'settings' };
  const html = renderAdmin(fixture, forms);
  assert.ok(html.includes('data-token-create'));
  assert.ok(html.includes('data-token-revoke="token-test"'));
  assert.ok(html.includes('&lt;script&gt;bad&lt;/script&gt;'));
  assert.ok(!html.includes('<script>bad</script>'));
  assert.ok(html.includes('data-token-value readonly'));
  for (const user of [{ role: 'dev', auth_type: 'session', email: 'dev@test.com' }, { role: 'admin', auth_type: 'legacy-token', email: 'api-token' }]) {
    assert.ok(!renderAdmin({ ...fixture, user }, forms).includes('data-token-create'));
  }
});
