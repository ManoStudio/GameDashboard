import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
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
vm.runInContext('presignGet = async (_env, key) => `https://download.test/${key}`', context);

const latest = vm.runInContext('launcherLatestFromHub', context);
const version = '2026.9.27040';
const metadata = {
  tool_slug: 'gamelauncher',
  version,
  full_key: `artifacts/gamelauncher/${version}/12345678-1234-1234-1234-123456789abc/ManoLauncher-${version}.zip`,
  full_hash: 'zip-hash',
  full_size: 456,
  installer_key: `artifacts/gamelauncher/${version}/12345678-1234-1234-1234-123456789abc/ManoLauncher-Setup-${version}.exe`,
  installer_hash: 'installer-hash',
  installer_size: 123,
};
const release = { metadata, credentials: {} };
const update = await latest({}, '2026.9.27039', 'live', release);
assert.equal(update.has_update, true);
assert.match(update.full_url, /ManoLauncher-2026\.9\.27040\.zip$/);
assert.equal(update.release.full_hash, 'zip-hash');
assert.equal(update.release.full_size, 456);

const installerOnly = await latest({}, '2026.9.27039', 'live', {
  metadata: { ...metadata, full_key: '' }, credentials: {},
});
assert.match(installerOnly.full_url, /ManoLauncher-Setup-2026\.9\.27040\.exe$/);
assert.equal(installerOnly.release.full_hash, 'installer-hash');
console.log('PASS: launcher update prefers full ZIP and retains installer fallback.');
