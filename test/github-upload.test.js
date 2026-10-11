import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, writeFile, unlink, rmdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { uploadGame } from '../examples/github-actions/upload-game.mjs';

const bytes = Buffer.from('PK-example-game-package');
const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'Content-Type': 'application/json' } });
const session = {
  build_id: 'build-test', version: 'GM-Build-42',
  uploads: [{ object_path: 'builds/game/build-test/files/001-game.zip', content_type: 'application/zip', upload_url: 'https://r2.test/upload?signed=secret' }],
};

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'game-dashboard-uploader-'));
  const filePath = join(directory, 'game.zip');
  await writeFile(filePath, bytes);
  t.after(async () => { await unlink(filePath); await rmdir(directory); });
  return { dashboardUrl: 'https://dashboard.test', token: 'test-dashboard-secret', projectId: 'game', filePath, channel: 'qa', metadata: { commit_sha: 'commit', build_source: 'github-actions' } };
}

test('uploader streams the ZIP, uses signed Content-Type, and completes with reserved version and hash', async t => {
  const config = await fixture(t);
  const calls = [];
  const result = await uploadGame(config, async (url, options) => {
    calls.push({ url: String(url), options });
    if (calls.length === 1) {
      assert.equal(String(url), 'https://dashboard.test/api/projects/game/uploads/init');
      assert.equal(options.headers.Authorization, 'Bearer test-dashboard-secret');
      const payload = JSON.parse(options.body);
      assert.equal(payload.channel, 'qa');
      assert.equal(payload.commit_sha, 'commit');
      assert.equal(payload.files[0].size, bytes.length);
      return json(session);
    }
    if (calls.length === 2) {
      assert.equal(String(url), session.uploads[0].upload_url);
      assert.equal(options.method, 'PUT');
      assert.equal(options.headers.Authorization, undefined, 'Dashboard token must not be sent to R2');
      assert.equal(options.headers['Content-Type'], session.uploads[0].content_type);
      assert.equal(options.headers['Content-Length'], String(bytes.length));
      assert.equal(options.duplex, 'half');
      const chunks = [];
      for await (const chunk of options.body) chunks.push(chunk);
      assert.deepEqual(Buffer.concat(chunks), bytes);
      return new Response(null, { status: 200 });
    }
    assert.equal(String(url), 'https://dashboard.test/api/projects/game/uploads/build-test/complete');
    const payload = JSON.parse(options.body);
    assert.equal(payload.version, 'GM-Build-42');
    assert.equal(payload.files[0].object_path, session.uploads[0].object_path);
    assert.equal(payload.files[0].hash, createHash('sha256').update(bytes).digest('hex'));
    return json({ id: session.build_id, version: session.version, channel: payload.channel }, 201);
  });
  assert.equal(calls.length, 3);
  assert.deepEqual(result, { id: 'build-test', version: 'GM-Build-42', channel: 'qa' });
});

test('failed R2 PUT never completes or retries the session', async t => {
  let calls = 0;
  await assert.rejects(uploadGame(await fixture(t), async () => ++calls === 1 ? json(session) : new Response(null, { status: 403 })), /R2 upload: HTTP 403/);
  assert.equal(calls, 2);
});

test('invalid token fails before R2 upload and omits server response details', async t => {
  let calls = 0;
  await assert.rejects(uploadGame(await fixture(t), async () => { calls++; return json({ error: 'test-dashboard-secret' }, 401); }), error => {
    assert.match(error.message, /Initialize upload: HTTP 401/);
    assert.ok(!error.message.includes('test-dashboard-secret'));
    return true;
  });
  assert.equal(calls, 1);
});

test('incomplete session fails before R2 upload', async t => {
  let calls = 0;
  await assert.rejects(uploadGame(await fixture(t), async () => { calls++; return json({ build_id: 'broken', uploads: [] }); }), /incomplete session/);
  assert.equal(calls, 1);
});
