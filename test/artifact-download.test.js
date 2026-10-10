import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';
import { createHmac, webcrypto } from 'node:crypto';
import * as miniflare from 'miniflare';

const source = fs.readFileSync('src/worker.js', 'utf8').replace(/^import .*;\r?\n/gm, '');
const key = 'builds/game/build/files/game.zip';
const secret = 'test-artifact-signing-secret';
const bytes = Buffer.from('0123456789abcdefghijklmnopqrstuvwxyz');
function signedUrl(objectKey = key, expires = Math.floor(Date.now() / 1000) + 3600) {
  const signature = createHmac('sha256', secret).update(`${objectKey}.${expires}`).digest('hex');
  return `https://dashboard.test/api/artifacts/${objectKey}?expires=${expires}&signature=${signature}`;
}

async function workerdRuntime(t) {
  const testParent = path.resolve('.wrangler');
  await fsp.mkdir(testParent, { recursive: true });
  const testRoot = await fsp.mkdtemp(path.join(testParent, 'artifact-test-'));
  const options = { modules: true, script: source, compatibilityDate: '2026-04-24',
    r2Buckets: ['BUILDS_BUCKET'], bindings: { R2_SECRET_ACCESS_KEY: secret }, cf: false,
    resourceTmpPath: path.join(testRoot, 'tmp'), resourcePersistencePath: path.join(testRoot, 'persist') };
  // Wrangler's bundled Miniflare 5 exposes the v4 options converter; Miniflare 4
  // accepts these options directly. Use the runtime installed with the project.
  const mf = new miniflare.Miniflare(miniflare.convertV4MiniflareOptions?.(options) ?? options);
  t.after(async () => {
    await mf.dispose();
    assert.equal(path.dirname(testRoot), testParent);
    await fsp.rm(testRoot, { recursive: true, force: true });
  });
  return { mf, bucket: await mf.getR2Bucket('BUILDS_BUCKET') };
}

function fixtureRuntime() {
  const { worker } = runtime();
  const stored = new Map();
  const bucket = {
    async put(objectKey, content, options = {}) {
      stored.set(objectKey, { content: Buffer.from(content), options });
    },
    async head(objectKey) {
      const entry = stored.get(objectKey);
      return entry ? { ...object(entry.content), body: undefined } : null;
    },
    async get(objectKey, options) {
      const entry = stored.get(objectKey);
      if (!entry) return null;
      const metadata = object(entry.content);
      if (options?.onlyIf && options.onlyIf.etagMatches !== metadata.etag) return { ...metadata, body: undefined };
      const content = options?.range
        ? entry.content.subarray(options.range.offset, options.range.offset + options.range.length) : entry.content;
      return { ...metadata, writeHttpMetadata(headers) {
        if (entry.options.httpMetadata?.contentType) headers.set('Content-Type', entry.options.httpMetadata.contentType);
      }, body: new ReadableStream({ start(controller) { controller.enqueue(content); controller.close(); } }) };
    },
  };
  const env = { BUILDS_BUCKET: bucket, R2_SECRET_ACCESS_KEY: secret };
  return { bucket, mf: { dispatchFetch: (url, options) => worker.fetch(new Request(url, options), env) } };
}

async function checkArtifactRequests(t, { mf, bucket }) {
  await bucket.put(key, bytes, { httpMetadata: { contentType: 'application/zip' } });

  await t.test('signed download skips D1 even with a session cookie, streams exact bytes and size', async () => {
    // No DB binding: a session lookup would fail this request.
    const response = await mf.dispatchFetch(signedUrl(), { headers: { Cookie: 'sid=test-cookie' } });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-length'), String(bytes.length));
    assert.equal(response.headers.get('x-artifact-size'), String(bytes.length));
    assert.equal(response.headers.get('accept-ranges'), 'bytes');
    assert.equal(response.headers.get('content-type'), 'application/zip');
    assert.match(response.headers.get('server-timing'), /^r2;dur=\d+$/);
    assert.match(response.headers.get('cache-control'), /private/);
    assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
  });

  await t.test('HEAD reads metadata without returning a body', async () => {
    const response = await mf.dispatchFetch(signedUrl(), { method: 'HEAD', headers: { Range: 'bytes=2-4' } });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('x-artifact-size'), String(bytes.length));
    assert.equal(response.headers.get('content-range'), null);
    assert.equal((await response.arrayBuffer()).byteLength, 0);
  });

  await t.test('closed, open, suffix and clipped ranges return exact byte counts', async () => {
    for (const [range, start, end] of [['bytes=4-9', 4, 9], ['bytes=12-', 12, 35], ['bytes=-5', 31, 35], ['bytes=30-99', 30, 35], ['bytes=-99', 0, 35]]) {
      const response = await mf.dispatchFetch(signedUrl(), { headers: { Range: range } });
      assert.equal(response.status, 206, range);
      assert.equal(response.headers.get('content-length'), String(end - start + 1));
      assert.equal(response.headers.get('content-range'), `bytes ${start}-${end}/${bytes.length}`);
      assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes.subarray(start, end + 1));
    }
  });

  await t.test('If-Range resumes unchanged objects and sends a whole replacement for stale/weak/date validators', async () => {
    const initial = await mf.dispatchFetch(signedUrl(), { method: 'HEAD' });
    const etag = initial.headers.get('etag');
    const matching = await mf.dispatchFetch(signedUrl(), { headers: { Range: 'bytes=10-', 'If-Range': etag } });
    assert.equal(matching.status, 206);
    assert.deepEqual(Buffer.from(await matching.arrayBuffer()), bytes.subarray(10));
    for (const validator of ['"old-version"', `W/${etag}`, initial.headers.get('last-modified')]) {
      const response = await mf.dispatchFetch(signedUrl(), { headers: { Range: 'bytes=10-', 'If-Range': validator } });
      assert.equal(response.status, 200);
      assert.equal(response.headers.get('content-range'), null);
      assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
    }
  });

  await t.test('out-of-bounds ranges return 416; malformed/multiple ranges safely return a whole file', async () => {
    for (const range of ['bytes=36-', 'bytes=99-100', 'bytes=-0']) {
      const response = await mf.dispatchFetch(signedUrl(), { headers: { Range: range } });
      assert.equal(response.status, 416);
      assert.equal(response.headers.get('content-range'), 'bytes */36');
      assert.equal((await response.arrayBuffer()).byteLength, 0);
    }
    for (const range of ['items=1-3', 'bytes=9-2', 'bytes=1-2,4-5', 'bytes=-']) {
      const response = await mf.dispatchFetch(signedUrl(), { headers: { Range: range } });
      assert.equal(response.status, 200);
      assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
    }
  });

  await t.test('unsigned, expired, malformed and object-mismatched tokens cannot read files', async () => {
    for (const url of [signedUrl().split('?')[0], signedUrl(key, Math.floor(Date.now() / 1000) - 5),
      signedUrl().replace('signature=', 'signature=invalid'), signedUrl().replace('/game.zip?', '/other.zip?'),
      signedUrl().replace(/expires=\d+/, 'expires=Infinity')]) {
      const response = await mf.dispatchFetch(url);
      assert.equal(response.status, 401);
      await response.arrayBuffer();
    }
    const missing = await mf.dispatchFetch(signedUrl('builds/game/missing.zip'));
    assert.equal(missing.status, 404);
    await missing.arrayBuffer();
    const outside = await mf.dispatchFetch(signedUrl('logs/private.zip'));
    assert.equal(outside.status, 400);
    await outside.arrayBuffer();
  });

  await t.test('empty objects stream successfully and reject byte ranges', async () => {
    const emptyKey = 'builds/game/empty.zip';
    await bucket.put(emptyKey, new Uint8Array());
    const response = await mf.dispatchFetch(signedUrl(emptyKey));
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('content-length'), '0');
    assert.equal((await response.arrayBuffer()).byteLength, 0);
    const ranged = await mf.dispatchFetch(signedUrl(emptyKey), { headers: { Range: 'bytes=0-' } });
    assert.equal(ranged.status, 416);
    await ranged.arrayBuffer();
  });
}

test('artifact HTTP behavior with a streaming R2 fixture', async t => {
  await checkArtifactRequests(t, fixtureRuntime());
});

// Opt in where workerd can open its internal SQLite files (Windows sandboxing
// can prevent startup). Runs the same HTTP cases against the real Workers runtime.
test('artifact HTTP behavior in workerd with real R2 and FixedLengthStream', {
  skip: process.env.DASHBOARD_RUNTIME_TESTS !== '1',
}, async t => {
  await checkArtifactRequests(t, await workerdRuntime(t));
});

function runtime() {
  const logs = [];
  const context = vm.createContext({ TextEncoder, Uint8Array, URL, Request, Response, Headers, Date, ReadableStream,
    crypto: webcrypto, console: { log: value => logs.push(JSON.parse(value)) } });
  vm.runInContext(source.replace('export default {', 'const worker = {'), context);
  return { context, logs, worker: vm.runInContext('worker', context) };
}
function object(content = bytes, etag = 'old') {
  return { size: content.length, etag, httpEtag: `"${etag}"`, uploaded: new Date('2026-10-01T00:00:00Z'),
    body: content, writeHttpMetadata() {} };
}

test('an object replaced between metadata and range read sends the whole new version', async () => {
  const { context } = runtime();
  const replacement = Buffer.from('replacement-data');
  const calls = [];
  const env = { BUILDS_BUCKET: { head: async () => object(), get: async (_key, options) => {
    calls.push(options);
    return options ? { ...object(replacement, 'new'), body: undefined } : object(replacement, 'new');
  } } };
  const response = await context.downloadArtifact(new Request(signedUrl(), { headers: { Range: 'bytes=5-', 'If-Range': '"old"' } }), env, { email: 'tester' }, key);
  assert.equal(response.status, 200);
  assert.equal(calls[0].onlyIf.etagMatches, 'old');
  assert.equal(calls.length, 2);
  assert.equal(response.headers.get('etag'), '"new"');
  assert.equal(response.headers.get('content-range'), null);
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), replacement);
});

test('session-only downloads retain authorization; diagnostics exclude cookies and signed URLs', async () => {
  const { worker, logs } = runtime();
  let dbCalls = 0;
  const env = { R2_SECRET_ACCESS_KEY: secret, BUILDS_BUCKET: { get: async () => object() }, DB: {
    prepare() { dbCalls++; return { bind: () => ({ first: async () => ({ email: 'tester', role: 'QA' }) }) }; },
  } };
  const response = await worker.fetch(new Request(signedUrl().split('?')[0], { headers: { Cookie: 'sid=private-session-cookie' } }), env);
  assert.equal(response.status, 200);
  assert.equal(dbCalls, 1);
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
  assert.equal(logs[0].auth, 'session');
  assert.equal(JSON.stringify(logs).includes('private-session-cookie'), false);
  assert.equal(JSON.stringify(logs).includes('signature='), false);
});
