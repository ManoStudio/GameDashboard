import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { webcrypto } from 'node:crypto';
import { renderAdmin } from '../src/admin-pages.js';

function runtime() {
  const context = vm.createContext({ TextEncoder, TextDecoder, Uint8Array, URL, Request, Response, Headers, atob, crypto: webcrypto });
  vm.runInContext(fs.readFileSync('src/worker.js', 'utf8').replace(/^import .*;\r?\n/gm, '').replace('export default {', 'const worker = {'), context);
  return context;
}
const project = { id: 'project', name: 'Test game', is_private: 0 };
function environment({ failInsert = false, missingProject = false } = {}) {
  const objects = new Map(), inserted = [], deleted = [];
  return { objects, inserted, deleted, BUILDS_BUCKET: {
    async put(key, value) { objects.set(key, value); },
    async delete(keys) { deleted.push(...keys); keys.forEach(key => objects.delete(key)); },
    async get(key) { return objects.has(key) ? { body: objects.get(key), httpEtag: '"test"', writeHttpMetadata() {} } : null; },
  }, DB: { prepare(sql) { return { bind(...args) { return {
    async first() {
      if (sql.includes('FROM projects')) return missingProject ? null : project;
      if (sql.includes('FROM builds')) return { id: 'build', version: '1.0', channel: 'dev' };
      if (sql.includes('FROM bug_reports')) return { id: 'report', project_id: 'project', log_object_path: 'log', snapshot_object_path: 'snapshot', snapshot_content_type: 'image/png' };
      throw new Error(sql);
    }, async run() { if (failInsert) throw new Error('database unavailable'); inserted.push(args); },
  }; } }; } } };
}
function request(extra = {}) {
  return new Request('https://dashboard.test/api/bug-reports', { method: 'POST', body: JSON.stringify({ project_id: 'project', build_id: 'build', description: 'Reproduction steps', logs: 'hello', ...extra }) });
}
const user = { email: 'dev@example.test', role: 'dev' };
const snapshot = 'data:image/png;base64,' + Buffer.from([137,80,78,71,13,10,26,10,0]).toString('base64');

test('accepts 2 MB UTF-8 logs and snapshot, rejects one byte over', async () => {
  const { createBugReport } = runtime(), env = environment();
  assert.equal((await createBugReport(request({ logs: 'a'.repeat(2 * 1024 * 1024), snapshot }), env, user)).status, 201);
  assert.equal(env.objects.size, 2);
  assert.equal(env.inserted[0][10], 2 * 1024 * 1024);
  assert.equal((await createBugReport(request({ logs: 'a'.repeat(2 * 1024 * 1024 + 1) }), env, user)).status, 413);
  assert.equal((await createBugReport(request({ logs: 'ก'.repeat(700000) }), env, user)).status, 413);
});
test('rejects invalid images, null payload and oversized request before storage', async () => {
  const { createBugReport } = runtime(), env = environment();
  for (const value of ['data:image/svg+xml;base64,PHN2Zz4=', 'data:image/png;base64,aGVsbG8=', 12]) {
    assert.equal((await createBugReport(request({ snapshot: value }), env, user)).status, 400);
  }
  assert.equal((await createBugReport(new Request('https://dashboard.test', { method: 'POST', body: 'null' }), env, user)).status, 400);
  assert.equal((await createBugReport(new Request('https://dashboard.test', { method: 'POST', headers: { 'content-length': String(17 * 1024 * 1024) }, body: '{}' }), env, user)).status, 413);
  assert.equal(env.objects.size, 0);
});
test('cleans both objects when database insert fails; old clients can omit snapshot', async () => {
  const { createBugReport } = runtime(), failed = environment({ failInsert: true });
  await assert.rejects(createBugReport(request({ snapshot }), failed, user), /database unavailable/);
  assert.equal(failed.objects.size, 0); assert.equal(failed.deleted.length, 2);
  assert.equal((await createBugReport(request(), environment(), user)).status, 201);
});
test('previews require role and project access, serve safe content types', async () => {
  const { dispatch, downloadBugReportLog, downloadBugReportSnapshot } = runtime(), env = environment();
  env.objects.set('log', '<script>unsafe()</script>'); env.objects.set('snapshot', new Uint8Array([1]));
  const response = await downloadBugReportLog(env, user, 'report', true);
  assert.equal(response.headers.get('content-disposition').startsWith('inline'), true);
  assert.equal(response.headers.get('content-type'), 'text/plain; charset=utf-8');
  assert.equal((await downloadBugReportSnapshot(env, user, 'report')).headers.get('cache-control'), 'private, no-store');
  assert.equal((await downloadBugReportSnapshot(environment({ missingProject: true }), user, 'report')).status, 404);
  for (const path of ['/api/bug-reports/report/log?preview=1', '/api/bug-reports/report/snapshot']) {
    const req = new Request('https://dashboard.test' + path);
    assert.equal((await dispatch(req, env, new URL(req.url), { ...user, role: 'viewer' })).status, 403);
    assert.equal((await dispatch(req, env, new URL(req.url), null)).status, 401);
  }
});
test('Unity parser preserves multiline stack traces and error types', () => {
  const context = vm.createContext({});
  vm.runInContext(fs.readFileSync('static/admin-ui.js', 'utf8').replace(/^initAdmin\(\);$/m, '').replace(/^initReportConsole\(\);$/m, ''), context);
  const entries = context.parseUnityLog('2026-10-01T00:00:00.123Z [Exception] Missing object\r\nGame.Update() at Game.cs:42\r\n2026-10-01T00:00:01Z [Warning] Retry\n2026-10-01T00:00:02Z [Log] Ready');
  assert.equal(entries.length, 3); assert.equal(entries[0].level, 'error'); assert.match(entries[0].raw, /Game.cs:42/);
  assert.equal(entries[1].level, 'warning'); assert.equal(entries[2].level, 'log');
  assert.equal(context.parseUnityLog('legacy player log\nwithout headers')[0].raw, 'legacy player log\nwithout headers');
});
test('table links to Full Detail and download appears only inside detail; content escaped', () => {
  const report = { id: 'BUG-1', description: '<script>alert(1)</script>', log_object_path: 'log', snapshot_object_path: 'image' };
  const fixture = { user, projects: [project], selected: project, builds: [], users: [], bugReports: [report] };
  const forms = { style: () => '' };
  const table = renderAdmin({ ...fixture, view: 'logs' }, forms);
  assert.match(table, /Full Detail/); assert.ok(!table.includes('Download log'));
  const detail = renderAdmin({ ...fixture, view: 'report', reportId: report.id }, forms);
  assert.match(detail, /Download log/); assert.match(detail, /Game snapshot/); assert.ok(!detail.includes('<script>alert(1)</script>'));
});
