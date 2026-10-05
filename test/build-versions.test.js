import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { DatabaseSync } from 'node:sqlite';
import { webcrypto } from 'node:crypto';

function runtime() {
  const context = vm.createContext({ TextEncoder, TextDecoder, Uint8Array, URL, Request, Response, Headers, atob, crypto: webcrypto });
  vm.runInContext(fs.readFileSync('src/worker.js', 'utf8').replace(/^import .*;\r?\n/gm, '').replace('export default {', 'const worker = {'), context);
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(fs.readFileSync('schema.sql', 'utf8'));
  sqlite.exec(fs.readFileSync('migrations/0008_auto_build_versions.sql', 'utf8'));
  sqlite.prepare("INSERT INTO projects (id, name, icon, bundle_id, role, created_at, updated_at) VALUES (?, 'Game', ?, 'game', 'viewer', '', '')").run('game', 'GM');
  sqlite.prepare("INSERT INTO projects (id, name, icon, bundle_id, role, created_at, updated_at) VALUES (?, 'Other', ?, 'other', 'viewer', '', '')").run('other', 'OT');
  const env = { R2_ACCOUNT_ID: 'test', R2_ACCESS_KEY_ID: 'test', R2_SECRET_ACCESS_KEY: 'test', R2_BUCKET_NAME: 'test', DB: {
    prepare(sql) { return { bind(...args) { return { first: async () => sqlite.prepare(sql).get(...args) ?? null, run: async () => sqlite.prepare(sql).run(...args) }; } }; },
  } };
  // Network signing is outside the version allocation tests.
  context.presignPut = async () => 'https://upload.test/file';
  context.objectDownloadUrl = async () => 'https://download.test/file';
  context.rowToBuild = async (_env, row) => row;
  return { context, env, sqlite };
}
const user = { role: 'dev', email: 'dev@test' };
const request = payload => new Request('https://dashboard.test/api/upload', { method: 'POST', body: JSON.stringify(payload) });

test('allocates increasing numbers per project with real SQLite UPSERT, including concurrent starts', async () => {
  const { context, env, sqlite } = runtime();
  const values = await Promise.all(Array.from({ length: 12 }, () => context.nextVersion(env, 'game', 'GM')));
  assert.deepEqual(values, Array.from({ length: 12 }, (_, i) => `GM-Build-${i + 1}`));
  assert.equal(await context.nextVersion(env, 'other', 'OT'), 'OT-Build-1');
  sqlite.exec('DELETE FROM builds');
  assert.equal(await context.nextVersion(env, 'game', 'NEW'), 'NEW-Build-13', 'Deletion and icon changes never reset the counter');
  assert.deepEqual([...values].reverse().sort(new Intl.Collator('en', { numeric: true }).compare), values);
  sqlite.close();
});

test('server version overrides client input; completion binds to project and uploader and cannot reuse a deleted build', async () => {
  const { context, env, sqlite } = runtime();
  const payload = { version: 'client-custom-version', channel: 'dev', files: [{ name: 'game.zip', size: 10 }] };
  const init = await context.initUploadSession(request(payload), env, user, 'game');
  assert.equal(init.status, 200);
  const session = await init.json();
  assert.equal(session.version, 'GM-Build-1');
  const completion = { ...payload, files: [{ ...payload.files[0], object_path: session.uploads[0].object_path }] };
  assert.equal((await context.completeUploadSession(request(completion), env, { ...user, email: 'other@test' }, 'game', session.build_id)).status, 400);
  assert.equal((await context.completeUploadSession(request(completion), env, user, 'other', session.build_id)).status, 400);
  const done = await context.completeUploadSession(request(completion), env, user, 'game', session.build_id);
  assert.equal(done.status, 201);
  assert.equal((await done.json()).version, 'GM-Build-1');
  sqlite.exec('DELETE FROM builds');
  assert.equal((await context.completeUploadSession(request(completion), env, user, 'game', session.build_id)).status, 400);
  assert.equal(await context.nextVersion(env, 'game', 'GM'), 'GM-Build-2');
  sqlite.close();
});
