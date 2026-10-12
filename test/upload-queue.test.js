import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import { DatabaseSync } from 'node:sqlite';
import { createHash, webcrypto } from 'node:crypto';
import { renderAdmin } from '../src/admin-pages.js';

const origin = 'https://dashboard.test';
const files = [{ name: 'game.zip', size: 100, content_type: 'application/zip' }];
function fixture(t) {
  const db = new DatabaseSync(':memory:'); db.exec(fs.readFileSync('schema.sql', 'utf8')); t.after(() => db.close());
  for (const id of ['game', 'other']) db.prepare("INSERT INTO projects (id,name,icon,bundle_id,role,created_at,updated_at) VALUES (?,?,'GM',?,'viewer','','')").run(id,id,id);
  for (const role of ['admin', 'dev', 'QA', 'viewer']) {
    db.prepare("INSERT INTO users (email,role,password_hash,created_at,updated_at) VALUES (?,?,'','','')").run(role+'@test',role);
    db.prepare("INSERT INTO sessions (token_hash,email,expires_at,created_at) VALUES (?,?,'2999-01-01T00:00:00.000Z','')").run(createHash('sha256').update(role).digest('hex'),role+'@test');
  }
  const env = { R2_ACCOUNT_ID:'test',R2_ACCESS_KEY_ID:'test',R2_SECRET_ACCESS_KEY:'test',R2_BUCKET_NAME:'test', DB: {
    prepare(sql) { const q = args => ({ first: async () => db.prepare(sql).get(...args)??null, all: async () => ({results:db.prepare(sql).all(...args)}), run: async () => db.prepare(sql).run(...args) }); return {...q([]),bind:(...args)=>q(args)}; }
  }};
  const context = vm.createContext({ URL,URLSearchParams,Request,Response,Headers,TextEncoder,TextDecoder,Uint8Array,crypto:webcrypto,atob,renderAdmin,console });
  vm.runInContext(fs.readFileSync('src/worker.js','utf8').replace(/^import .*;\r?\n/gm,'').replace('export default {','const worker = {'),context);
  context.presignPut = async () => 'https://r2.test/signed-secret'; context.objectDownloadUrl = async () => 'https://download.test/file'; context.rowToBuild = async (_env,row) => row;
  const worker = vm.runInContext('worker',context);
  const call = (path, {method='GET',payload,role='admin',token,requestOrigin=origin}={}) => worker.fetch(new Request(origin+path,{method,headers:{...(token?{Authorization:'Bearer '+token}:{Cookie:'sid='+role}),Origin:requestOrigin,'Content-Type':'application/json'},...(payload===undefined?{}:{body:JSON.stringify(payload)})}),env);
  async function init(project='game', options={}) { const response=await call(`/api/projects/${project}/uploads/init`,{method:'POST',payload:{queue:true,files,...options}}); assert.ok([200,202].includes(response.status),await response.clone().text()); return response.json(); }
  const complete = (job, project='game') => call(`/api/projects/${project}/uploads/${job.build_id}/complete`,{method:'POST',payload:{channel:'dev',files:files.map((file,i)=>({...file,object_path:context.objectPathFor(project,job.build_id,file.name,i+1)}))}});
  return {db,env,context,call,init,complete};
}

test('concurrent initialization claims one slot per project; waiting jobs never receive signed URLs', async t => {
  const {init,db,call} = fixture(t);
  const jobs = await Promise.all(Array.from({length:12},()=>init()));
  assert.equal(jobs.filter(job=>job.status==='uploading').length,1);
  assert.equal(jobs.filter(job=>job.status==='waiting').length,11);
  for (const job of jobs.filter(job=>job.status==='waiting')) assert.equal(job.uploads,undefined);
  assert.equal((await init('other')).status,'uploading');
  const response = await call('/api/projects/game/upload-queue'); const data = await response.json();
  assert.equal(data.jobs.length,12); assert.equal(response.headers.get('Cache-Control'),'private, no-store');
  assert.ok(!(JSON.stringify(data).includes('signed-secret'))); assert.ok(!JSON.stringify(data).includes('owner'));
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM upload_queue WHERE project_id='game' AND status='uploading'").get().n,1);
});

test('manual order is persisted; completion admits the chosen next build, never the currently active build', async t => {
  const {init,call,complete,db} = fixture(t); const one=await init(),two=await init(),three=await init();
  const reordered = await call('/api/projects/game/upload-queue/reorder',{method:'POST',payload:{build_ids:[three.build_id,two.build_id]},role:'dev'});
  assert.equal(reordered.status,200,await reordered.clone().text());
  assert.deepEqual((await reordered.json()).jobs.map(job=>job.build_id),[one.build_id,three.build_id,two.build_id]);
  assert.equal((await complete(two)).status,409,'Waiting jobs cannot register a build');
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM builds').get().n,0);
  assert.equal((await complete(one)).status,201);
  const admitted=await (await call(`/api/projects/game/uploads/${three.build_id}/status`)).json(); assert.equal(admitted.status,'uploading'); assert.ok(admitted.uploads[0].upload_url);
  assert.equal((await complete(three)).status,201); assert.equal((await complete(two)).status,201);
  assert.equal(db.prepare("SELECT COUNT(*) AS n FROM upload_queue WHERE status='completed'").get().n,3);
});

test('stale snapshots, duplicate IDs, active IDs and other projects cannot corrupt queue order', async t => {
  const {init,call} = fixture(t); const one=await init(),two=await init(),three=await init(),other=await init('other');
  for (const [ids,status] of [[[two.build_id],409],[[two.build_id,two.build_id],400],[[one.build_id,two.build_id],409],[[other.build_id,three.build_id],409]]) {
    assert.equal((await call('/api/projects/game/upload-queue/reorder',{method:'POST',payload:{build_ids:ids}})).status,status);
  }
  assert.deepEqual((await (await call('/api/projects/game/upload-queue')).json()).jobs.map(job=>job.build_id),[one.build_id,two.build_id,three.build_id]);
});

test('progress is bounded and monotonic; failure and missing heartbeats release the slot', async t => {
  const {init,call,db,complete} = fixture(t); const one=await init(),two=await init(),three=await init();
  const progress = payload => call(`/api/projects/game/uploads/${one.build_id}/progress`,{method:'POST',payload});
  assert.equal((await progress({uploaded_bytes:75,phase:'uploading'})).status,200);
  assert.equal((await (await progress({uploaded_bytes:20,phase:'uploading'})).json()).uploaded_bytes,75);
  assert.equal((await progress({uploaded_bytes:101,phase:'uploading'})).status,400);
  assert.equal((await call(`/api/projects/game/uploads/${one.build_id}/progress`,{method:'POST',role:'dev',payload:{uploaded_bytes:50,phase:'uploading'}})).status,404);
  assert.equal((await call(`/api/projects/game/uploads/${one.build_id}/fail`,{method:'POST',payload:{}})).status,200);
  assert.equal((await complete(one)).status,409);
  db.prepare("UPDATE upload_queue SET lease_expires_at='2000-01-01T00:00:00.000Z' WHERE build_id=?").run(two.build_id);
  const expired=await (await call(`/api/projects/game/uploads/${two.build_id}/status`)).json(); assert.equal(expired.status,'expired'); assert.equal(expired.uploads,undefined);
  assert.equal((await complete(two)).status,409);
  assert.equal((await (await call(`/api/projects/game/uploads/${three.build_id}/status`)).json()).status,'uploading');
});

test('expired waiting jobs cannot complete or resurrect; rejected finalization leaves the next slot usable', async t => {
  const {init,call,db,complete,context} = fixture(t); const one=await init(),two=await init(),three=await init();
  db.prepare("UPDATE upload_queue SET lease_expires_at='2000-01-01T00:00:00.000Z' WHERE build_id=?").run(two.build_id);
  await call('/api/projects/game/upload-queue'); assert.equal((await complete(two)).status,409);
  context.saveBuild=async()=>{throw new Error('fixture write failure');};
  assert.equal((await complete(one)).status,500);
  assert.equal((await (await call(`/api/projects/game/uploads/${three.build_id}/status`)).json()).status,'uploading');
});

test('project tokens can monitor their own uploads but cannot list or reorder the team queue; session writes require same origin', async t => {
  const {call,init} = fixture(t);
  const issued=await (await call('/api/projects/game/tokens',{method:'POST',payload:{name:'CI',channels:['dev']}})).json();
  const queued=await (await call('/api/projects/game/uploads/init',{method:'POST',token:issued.token,payload:{queue:true,files}})).json();
  assert.equal((await call(`/api/projects/game/uploads/${queued.build_id}/status`,{token:issued.token})).status,200);
  for (const path of ['/api/projects/game/upload-queue','/api/projects/other/uploads/'+queued.build_id+'/status']) assert.equal((await call(path,{token:issued.token})).status,403);
  assert.equal((await call('/api/projects/game/upload-queue/reorder',{method:'POST',token:issued.token,payload:{build_ids:[]}})).status,403);
  const own=await init(); assert.equal((await call(`/api/projects/game/uploads/${own.build_id}/status`,{token:issued.token})).status,404);
  for (const role of ['QA','viewer']) assert.equal((await call('/api/projects/game/upload-queue',{role})).status,403);
  assert.equal((await call('/api/projects/game/upload-queue/reorder',{method:'POST',payload:{build_ids:[own.build_id]},requestOrigin:'https://evil.test'})).status,403);
  assert.equal((await call('/api/projects/game/uploads/init',{method:'POST',payload:{queue:true,files},requestOrigin:'https://evil.test'})).status,403);
});

test('legacy clients retain direct upload compatibility and are visible while managed jobs wait', async t => {
  const {init,call,complete,db} = fixture(t); const old=await init('game',{queue:false}); assert.ok(old.uploads[0].upload_url);
  const waiting=await init(); assert.equal(waiting.status,'waiting');
  assert.equal((await (await call('/api/projects/game/upload-queue')).json()).jobs[0].status,'legacy');
  assert.equal((await complete(old)).status,201);
  assert.equal(db.prepare('SELECT status FROM upload_queue WHERE build_id=?').get(waiting.build_id).status,'uploading');
});

test('migration backfills pre-existing upload reservations without blocking their completion', t => {
  const db=new DatabaseSync(':memory:'); t.after(()=>db.close());
  db.exec(fs.readFileSync('schema.sql','utf8').split('CREATE TABLE IF NOT EXISTS upload_queue')[0]);
  db.prepare("INSERT INTO build_upload_versions VALUES ('old','game','GM-Build-8','admin@test',?)").run(new Date().toISOString());
  const sql=fs.readFileSync('migrations/0011_upload_queue.sql','utf8'); db.exec(sql); db.exec(sql);
  const row=db.prepare('SELECT * FROM upload_queue').get(); assert.equal(row.status,'legacy'); assert.equal(row.managed,0); assert.ok(Date.parse(row.lease_expires_at)>Date.now());
});
