import {test} from 'node:test';import assert from 'node:assert/strict';
import {mkdtemp,readFile,rm} from 'node:fs/promises';import {tmpdir} from 'node:os';import {join,resolve} from 'node:path';
import * as c from '../web/src/lib/crypto.ts';import {sealPrivate,openPrivate} from '../web/src/lib/private.ts';import {terminalFixture} from './terminal-fixture.ts';
const pass='PUBLIC synthetic test passphrase only, never a real credential';
test('native hidden-prompt identity creation produces a browser-compatible recovery file',{skip:process.platform==='win32',timeout:45000},async()=>{
 const dir=await mkdtemp(join(tmpdir(),'nightbuoy-identity-'));try{
  const path=join(dir,'recovery.json');await terminalFixture(resolve('target/debug/nightbuoy'),['identity','create',path],{passwords:[{prompt:'Unique passphrase',value:pass},{prompt:'Repeat passphrase',value:pass}]});
  const vault=JSON.parse(await readFile(path,'utf8'));const owner=await c.unlock(vault,pass);assert.ok(owner.device.discover);assert.ok(await c.verify(owner.device.sign,await c.signed(owner,['browser checks native identity'])));
  const key=c.random();assert.equal(c.b64(await c.openGrant(owner,(await c.grant(owner.device,1,key)).key)),c.b64(key));
  const encrypted=await sealPrivate(owner,'a'.repeat(64),'pending',{text:'Generated native identity can own private data'});assert.equal((await openPrivate(owner,'a'.repeat(64),'pending',encrypted)).text,'Generated native identity can own private data');
  await terminalFixture(resolve('target/debug/nightbuoy'),['identity','inspect',path],{passwords:[{prompt:'Identity passphrase',value:pass}]});
  const original=await readFile(path);const {execFile}=await import('node:child_process');const {promisify}=await import('node:util');await assert.rejects(promisify(execFile)(resolve('target/debug/nightbuoy'),['identity','create',path],{timeout:5000}),/existing files are preserved/);assert.deepEqual(await readFile(path),original);
  const stat=await import('node:fs/promises').then(fs=>fs.stat(path));assert.equal(stat.mode&0o777,0o600);
 }finally{await rm(dir,{recursive:true,force:true});}
});
