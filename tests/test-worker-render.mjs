import fs from 'node:fs';
import vm from 'node:vm';
import assert from 'node:assert/strict';
import {renderAdmin} from '../src/admin-pages.js';
import {MODERN_THEME_STYLE} from '../src/modern-theme.js';
let source=fs.readFileSync('src/worker.js','utf8').replace(/^import .*;\r?\n/gm,'').replace('export default {','const worker = {');
const context=vm.createContext({renderAdmin,MODERN_THEME_STYLE,adminStyle:fs.readFileSync('static/admin.css','utf8'),adminScript:fs.readFileSync('static/admin-ui.js','utf8'),URL,Response,TextEncoder,console});
vm.runInContext(source,context);
const project={id:'test-project',name:'Test <Project>',icon:'TP',bundle_id:'test.game',role:'dev'};
const build={id:'test-build',version:'0.1.25',project_id:project.id,channel:'dev',status:'assigned',created_at:'2026-09-15',total_size:1024,changelog:'<script>alert(1)</script>',manifest:{files:[]}};
context.fixture={user:{email:'test@example.invalid',role:'admin'},projects:[project],selected:project,builds:[build],users:[],buildId:build.id};
for(const view of ['dashboard','projects','builds','upload','build','settings','logs']){
 context.fixture.view=view;
 const html=vm.runInContext('decorateHtml(renderAdmin(fixture,{createProjectForm,projectManagement,uploadPanel,userAccess,buildCard,style}))',context);
 assert.ok(html.includes('Build Manager'));assert.ok(html.includes('initAdmin();'));assert.ok(!html.includes('<script>alert(1)</script>'));
 const scripts=[...html.matchAll(/<script>([\s\S]*?)<\/script>/g)];assert.equal(scripts.length,1);new vm.Script(scripts[0][1]);
 assert.ok(!scripts[0][1].includes('__name('));
 console.log('PASS Worker '+view+' renders and embeds standalone script');
}

