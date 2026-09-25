import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { renderAdmin } from '../src/admin-pages.js';
import { MODERN_THEME_STYLE } from '../src/modern-theme.js';

const source = fs.readFileSync('src/worker.js', 'utf8')
  .replace(/^import .*;\r?\n/gm, '')
  .replace('export default {', 'const worker = {');
const context = vm.createContext({
  renderAdmin, MODERN_THEME_STYLE, adminStyle: '', adminScript: '',
  URL, URLSearchParams, Request, Response, TextEncoder, crypto: webcrypto, console,
});
vm.runInContext(source, context);
const worker = vm.runInContext('worker', context);
const version = '2026.9.25';
const key = `launcher/releases/${version}/ManoLauncher-Setup-${version}.exe`;
let metadata = {
  version,
  installer_key: key,
  installer_hash: 'installer-hash',
  installer_size: 123,
  full_key: `launcher/releases/${version}/ManoLauncher-${version}.zip`,
  full_hash: 'zip-hash',
  full_size: 456,
};
let headCalls = 0;
const env = {
  R2_ACCOUNT_ID: 'test-account',
  R2_BUCKET_NAME: 'test-bucket',
  R2_ACCESS_KEY_ID: 'test-access-key',
  R2_SECRET_ACCESS_KEY: 'test-secret-key',
  BUILDS_BUCKET: {
    get: async () => ({ json: async () => metadata }),
    head: async () => { headCalls += 1; return { size: 123 }; },
  },
};

const response = await worker.fetch(new Request('https://dashboard.test/api/launcher/installer'), env);
assert.equal(response.status, 302);
assert.equal(response.headers.get('cache-control'), 'no-store');
assert.match(response.headers.get('location'), /\/test-bucket\/launcher\/releases\/2026\.9\.25\/ManoLauncher-Setup-2026\.9\.25\.exe\?/);
assert.equal(headCalls, 1);

const latest = await vm.runInContext('launcherLatestFromR2', context)(env, '2026.09.22.28', 'live');
assert.equal(latest.has_update, true);
assert.match(latest.full_url, /ManoLauncher-Setup-2026\.9\.25\.exe\?/);
assert.equal(latest.release.full_hash, 'installer-hash');
assert.equal(latest.release.full_size, 123);

metadata = { version, installer_key: 'builds/private/game.exe' };
const invalid = await worker.fetch(new Request('https://dashboard.test/api/launcher/installer'), env);
assert.equal(invalid.status, 404);
assert.equal(headCalls, 1);
console.log('PASS: latest installer redirects to signed R2 and existing clients receive the EXE update.');
