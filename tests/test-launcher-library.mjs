import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { renderAdmin } from '../src/admin-pages.js';
import { MODERN_THEME_STYLE } from '../src/modern-theme.js';
const source = fs.readFileSync('src/worker.js','utf8').replace(/^import .*;\r?\n/gm,'').replace('export default {','const worker = {');
const context = vm.createContext({renderAdmin,MODERN_THEME_STYLE,adminStyle:'',adminScript:'',URL,Request,Response,TextEncoder,crypto:webcrypto,console});
vm.runInContext(source,context);
const projects = [
  {id:'public',name:'Public',icon:'P',role:'viewer',created_at:'2026-01-01'},
  {id:'private',name:'Private',icon:'X',role:'dev',created_at:'2026-01-02'},
];
const builds = [
  {id:'live',project_id:'public',version:'1.0.0',channel:'live',manifest_json:JSON.stringify({files:[{path:'game.zip',hash:'abc',size:42,storage_object:'secret',download_url:'signed-url'}]}),total_size:42},
  {id:'dev',project_id:'public',version:'2.0.0',channel:'dev',manifest_json:'{"files":[]}'},
  {id:'private',project_id:'private',version:'3.0.0',channel:'dev',manifest_json:'{"files":[]}'},
];
let statements = [];
const env = { DASHBOARD_API_TOKEN:'test-token', DB: {prepare(sql) {statements.push(sql); return {all: async () => ({results:sql.includes('FROM projects') ? projects : builds})};}}};
const response = await vm.runInContext("worker",context).fetch(new Request('https://dashboard.test/api/launcher/library',{headers:{Authorization:'Bearer test-token'}}),env);
assert.equal(response.status,200);
const result = await response.json();
assert.equal(result.length,2);
assert.equal(result[0].builds.length,2);
assert.equal(statements.length,2,'No request-time schema or bootstrap queries');
assert.ok(!JSON.stringify(result).includes('signed-url'));
assert.ok(!JSON.stringify(result).includes('secret'));
statements=[];
const viewer = await vm.runInContext('launcherLibrary',context)(env,{role:'viewer'});
assert.equal(viewer.length,1);
assert.equal(viewer[0].builds.length,1);
assert.equal(viewer[0].builds[0].id,'live');
assert.equal(statements.length,2);
console.log('PASS: launcher library uses 2 DB reads, scopes projects and channels, excludes signed URLs and storage keys.');

