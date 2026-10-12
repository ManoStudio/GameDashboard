import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import * as miniflare from 'miniflare';

// Exercise native workerd fetch, not a mocked fetch implementation. The Discord
// destination is replaced only in this test, and all requests stay on localhost.
let redirectedRequests = 0;
const server = http.createServer((req, res) => {
  if (req.url.startsWith('/redirect')) {
    res.writeHead(302, { Location: '/should-not-follow' }); res.end(); return;
  }
  if (req.url.startsWith('/should-not-follow')) redirectedRequests++;
  res.writeHead(req.url.startsWith('/rejected') ? 404 : 200, { 'Content-Type': 'application/json' });
  res.end('{"id":"local-discord-message"}');
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
const parent = path.resolve('.wrangler');
const root = await fs.mkdtemp(path.join(parent, 'discord-transport-test-'));
assert.equal(path.dirname(path.resolve(root)), parent);
const source = (await fs.readFile('src/worker.js', 'utf8')).replace(/^import .*;\r?\n/gm, '').replace('export default {', 'const originalWorker = {');
const urlStatement = 'const url = new URL(normalizeDiscordWebhook(webhookUrl));';
assert.ok(source.includes(urlStatement));
const script = source.replace(urlStatement, 'const url = new URL(env.TEST_DISCORD_URL);') + `
export default { async fetch(request) {
  const destination = 'http://127.0.0.1:${server.address().port}' + new URL(request.url).pathname;
  const env = { TEST_DISCORD_URL: destination, DB: { prepare() { return { bind() { return { run: async () => ({}) }; } }; } } };
  return Response.json(await deliverDiscordWebhook(env, 'test', 'test-credential', { content: 'local-only test' }));
} };`;
const options = { script, modules: true, compatibilityDate: '2026-04-24', cf: false,
  resourceTmpPath: path.join(root, 'tmp'), resourcePersistencePath: path.join(root, 'persist') };
const mf = new miniflare.Miniflare(miniflare.convertV4MiniflareOptions?.(options) ?? options);
try {
  const ok = await (await mf.dispatchFetch('https://test.local/ok')).json();
  assert.deepEqual(ok, { ok: true, error: null });
  const redirect = await (await mf.dispatchFetch('https://test.local/redirect')).json();
  assert.deepEqual(redirect, { ok: false, error: 'Discord HTTP 302' });
  assert.equal(redirectedRequests, 0, 'Redirect destinations must never receive credentials/messages');
  const rejected = await (await mf.dispatchFetch('https://test.local/rejected')).json();
  assert.deepEqual(rejected, { ok: false, error: 'Discord HTTP 404' });
  console.log('PASS native workerd fetch: successful delivery, explicit 302 rejection without following, and Discord 404 diagnostics.');
} finally {
  await mf.dispose();
  await new Promise(resolve => server.close(resolve));
  assert.equal(path.dirname(path.resolve(root)), parent);
  await fs.rm(root, { recursive: true, force: true });
}
