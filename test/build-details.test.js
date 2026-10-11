import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { DatabaseSync } from 'node:sqlite';
import { createHash, webcrypto } from 'node:crypto';

function runtime(t) {
  const db = new DatabaseSync(':memory:');
  db.exec(fs.readFileSync('schema.sql', 'utf8'));
  t.after(() => db.close());
  db.exec("INSERT INTO projects (id,name,icon,bundle_id,role,created_at,updated_at) VALUES ('game','Game','GM','game','viewer','',''), ('private','Private','P','private','admin','',''); INSERT INTO project_build_counters VALUES ('game',77);");
  for (const role of ['admin', 'dev', 'QA', 'viewer']) {
    db.prepare("INSERT INTO users (email,role,password_hash,created_at,updated_at) VALUES (?,?,'','','')").run(`${role}@test`, role);
    db.prepare("INSERT INTO sessions (token_hash,email,expires_at,created_at) VALUES (?,?,'2999-01-01T00:00:00.000Z','')").run(createHash('sha256').update(role).digest('hex'), `${role}@test`);
  }
  for (const id of ['old-build', 'other-build', 'private-build']) {
    db.prepare("INSERT INTO builds (id,project_id,version,channel,status,tag,changelog,test_instructions,file_count,total_size,storage_path,manifest_path,manifest_json,checksum,commit_sha,created_at,updated_at) VALUES (?,?,'GM-Build-1','live','assigned','playtest',?,'Old instructions',1,100,'r2://original','r2://manifest',?,'checksum','commit','2020-01-01T00:00:00.000Z','2020-01-01T00:00:00.000Z')")
      .run(id, id === 'private-build' ? 'private' : 'game', '## Test Focus\n- Original focus\n\n## Fixed\n- Startup crash\n\n## Known Issues\n- Old issue', JSON.stringify({ files: [{ path: 'game.zip', hash: 'original-hash', size: 100 }] }));
  }
  const env = { DASHBOARD_API_TOKEN: 'legacy-token', DB: { prepare(sql) {
    const query = args => ({ first: async () => db.prepare(sql).get(...args) ?? null, all: async () => ({ results: db.prepare(sql).all(...args) }), run: async () => db.prepare(sql).run(...args) });
    return { ...query([]), bind: (...args) => query(args) };
  } } };
  const context = vm.createContext({ URL, URLSearchParams, Request, Response, Headers, TextEncoder, TextDecoder, Uint8Array, crypto: webcrypto, console });
  vm.runInContext(fs.readFileSync('src/worker.js', 'utf8').replace(/^import .*;\r?\n/gm, '').replace('export default {', 'const worker = {'), context);
  const worker = vm.runInContext('worker', context);
  const origin = 'https://dashboard.test';
  const send = (id, payload, { role = 'admin', token, requestOrigin = origin, contentType = 'application/json' } = {}) => worker.fetch(new Request(`${origin}/api/builds/${id}/details`, {
    method: 'PATCH', headers: { Cookie: `sid=${role}`, Origin: requestOrigin, 'Content-Type': contentType, ...(token ? { Authorization: `Bearer ${token}` } : {}) }, body: JSON.stringify(payload),
  }), env);
  return { db, env, context, send };
}

test('old live builds can be edited repeatedly; updates preserve build identity, files, channel and other builds', async t => {
  const { db, send, context, env } = runtime(t);
  const before = db.prepare("SELECT * FROM builds WHERE id = 'old-build'").get();
  const other = db.prepare("SELECT * FROM builds WHERE id = 'other-build'").get();
  const payload = { focus_areas: ['Load old saves', 'Reconnect multiplayer'], test_instructions: '1. Load save\n2. Check inventory', known_issues: ['Visual glitch'], tag: 'playtest-2', save_path_hint: 'Saves/', config_path_hint: 'Config/' };
  const response = await send('old-build', payload);
  assert.equal(response.status, 200, await response.clone().text());
  const details = await response.json();
  assert.deepEqual(details.focus_areas, payload.focus_areas);
  assert.deepEqual(details.known_issues, payload.known_issues);
  assert.ok(details.changelog.includes('## Test Focus\n- Load old saves\n- Reconnect multiplayer'));
  assert.ok(details.changelog.includes('## Fixed\n- Startup crash'));
  assert.ok(!details.changelog.includes('Original focus'));
  assert.ok(!details.changelog.includes('Old issue'));
  const changed = new Set(['focus_areas', 'test_instructions', 'known_issues', 'tag', 'save_path_hint', 'config_path_hint', 'changelog', 'updated_at']);
  const after = db.prepare("SELECT * FROM builds WHERE id = 'old-build'").get();
  for (const key of Object.keys(before)) if (!changed.has(key)) assert.deepEqual(after[key], before[key], key);
  assert.deepEqual(db.prepare("SELECT * FROM builds WHERE id = 'other-build'").get(), other);
  assert.equal(db.prepare("SELECT last_number FROM project_build_counters WHERE project_id = 'game'").get().last_number, 77);
  const again = await send('old-build', { test_instructions: 'Updated after playtest', focus_areas: '' });
  assert.equal(again.status, 200);
  const updated = await again.json();
  assert.deepEqual(updated.focus_areas, []);
  assert.deepEqual(updated.known_issues, ['Visual glitch']);
  assert.ok(!updated.changelog.includes('## Test Focus'));
  assert.equal(updated.test_instructions, 'Updated after playtest');
  const library = await context.launcherLibrary(env, { role: 'dev' });
  const build = library.flatMap(project => project.builds).find(build => build.id === 'old-build');
  assert.equal(build.test_instructions, 'Updated after playtest');
  assert.equal(build.changelog, updated.changelog);
});

test('dev can edit permitted projects; QA/viewer, missing builds and inaccessible projects cannot', async t => {
  const { send } = runtime(t);
  assert.equal((await send('old-build', { focus_areas: 'Dev focus' }, { role: 'dev' })).status, 200);
  for (const role of ['QA', 'viewer']) assert.equal((await send('old-build', { tag: 'bad' }, { role })).status, 403);
  assert.equal((await send('missing', { tag: 'bad' })).status, 404);
  assert.equal((await send('private-build', { tag: 'bad' }, { role: 'dev' })).status, 404);
  assert.equal((await send('old-build', { tag: 'bad' }, { role: 'missing' })).status, 401);
  assert.equal((await send('old-build', { tag: 'bad' }, { requestOrigin: 'https://attacker.test' })).status, 403);
  assert.equal((await send('old-build', { tag: 'bad' }, { contentType: 'text/plain' })).status, 415);
});

test('partial edits preserve unsent fields and reject artifact/identity edits and invalid data without mutation', async t => {
  const { db, send } = runtime(t);
  const original = db.prepare("SELECT * FROM builds WHERE id = 'old-build'").get();
  for (const payload of [{ version: 'forged' }, { channel: 'dev' }, { manifest_json: '{}' }, { project_id: 'private' }, { checksum: 'bad' }, { focus_areas: {} }, { known_issues: [1] }, { test_instructions: null }, { tag: 'x'.repeat(201) }, { changelog: 'x'.repeat(64001) }, null, [], {}]) {
    assert.equal((await send('old-build', payload)).status, 400, JSON.stringify(payload)?.slice(0, 80));
    assert.deepEqual(db.prepare("SELECT * FROM builds WHERE id = 'old-build'").get(), original);
  }
  const response = await send('old-build', { tag: '' });
  assert.equal(response.status, 200);
  const after = db.prepare("SELECT * FROM builds WHERE id = 'old-build'").get();
  assert.equal(after.tag, '');
  assert.equal(after.changelog, original.changelog);
  assert.equal(after.test_instructions, original.test_instructions);
});

test('structured Markdown imports focus and ignores heading-like text inside code fences', async t => {
  const { send, db, context } = runtime(t);
  const changelog = '## Test Focus\n- Imported focus\n\n## Notes\n```text\n## Test Focus\nkeep this code\n```';
  const imported = await (await send('old-build', { changelog })).json();
  assert.deepEqual(imported.focus_areas, ['Imported focus']);
  const changed = await (await send('old-build', { focus_areas: ['Later focus'] })).json();
  assert.ok(changed.changelog.includes('```text\n## Test Focus\nkeep this code\n```'));
  assert.ok(changed.changelog.includes('## Test Focus\n- Later focus'));
  const original = db.prepare("SELECT * FROM builds WHERE id = 'other-build'").get();
  const editor = context.buildDetailsEditor({ role: 'admin' }, original);
  assert.ok(editor.includes('Original focus</textarea>'));
  assert.ok(editor.includes('Old issue</textarea>'));
});

test('editor and testing notes escape stored HTML and remain readable to QA', async t => {
  const { context } = runtime(t);
  const build = { id: 'test', focus_areas: ['<script>bad</script>'], test_instructions: '<img src=x onerror=bad>', changelog: '', known_issues: [], tag: '<bad>' };
  const editor = context.buildDetailsEditor({ role: 'dev' }, build);
  assert.ok(editor.includes('data-build-details'));
  assert.ok(editor.includes('&lt;script&gt;bad&lt;/script&gt;'));
  assert.ok(!editor.includes('<script>bad'));
  assert.equal(context.buildDetailsEditor({ role: 'QA' }, build), '');
  const readonly = context.buildTestingNotes(build);
  assert.ok(readonly.includes('&lt;img src=x onerror=bad&gt;'));
  assert.ok(!readonly.includes('<img src=x'));
});
