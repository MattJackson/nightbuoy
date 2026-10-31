// Execute a packaged binary, verify its embedded UI/API, and prove it writes no app state.
import assert from 'node:assert/strict';
import {spawn,spawnSync} from 'node:child_process';
import {mkdtemp,rm,readdir,chmod} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {tmpdir} from 'node:os';
import {createServer} from 'node:net';
const binary=resolve(process.argv[2]||'');
const emulator=process.env.NIGHTBUOY_SMOKE_EMULATOR;
if(emulator&&!['qemu-arm-static','qemu-aarch64-static'].includes(emulator))throw Error('Unsupported test emulator');
const command=emulator||binary,args=emulator?[binary]:[];
const version=spawnSync(command,[...args,'--version'],{encoding:'utf8',timeout:15000});
assert.equal(version.status,0);assert.match(version.stdout,/^NightBuoy \d+\.\d+\.\d+/);
if(process.argv[3])assert.equal(version.stdout.trim(),'NightBuoy '+process.argv[3]);
const dir=await mkdtemp(join(tmpdir(),'nightbuoy-package-smoke-'));
const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));
const port=probe.address().port;await new Promise(r=>probe.close(r));
const origin=`http://127.0.0.1:${port}`;let child;
try{
 if(process.platform!=='win32')await chmod(dir,0o555);
 child=spawn(command,[...args,'portable'],{cwd:dir,env:{PATH:process.env.PATH,NIGHTBUOY_LISTEN:`127.0.0.1:${port}`,NIGHTBUOY_PUBLIC_URL:origin},stdio:'ignore'});
 let response;for(let i=0;i<200;i++){
  if(child.exitCode!==null)throw Error(`packaged companion exited ${child.exitCode}`);
  try{response=await fetch(origin);if(response.ok)break;}catch{}
  await new Promise(r=>setTimeout(r,50));
 }
 assert.ok(response?.ok,'packaged embedded UI did not start');
 const html=await response.text();assert.match(html,/NightBuoy/);
 const scripts=[...html.matchAll(/(?:src|href)="(\/assets\/[^"\s]+)"/g)].map(m=>m[1]);assert.ok(scripts.length,'embedded UI assets missing');
 for(const asset of scripts){const r=await fetch(origin+asset);assert.ok(r.ok,`missing embedded asset ${asset}`);assert.ok((await r.arrayBuffer()).byteLength>0);}
 const bootstrap=await fetch(origin+'/api/session',{method:'POST',headers:{Origin:origin,'x-nightbuoy-bootstrap':'1'}});
 assert.ok(bootstrap.ok);const cookie=bootstrap.headers.get('set-cookie').split(';')[0];
 const status=await fetch(origin+'/api/status',{headers:{Cookie:cookie,Origin:origin}});
 assert.ok(status.ok);const body=await status.json();assert.equal(body.mode,'portable');assert.equal(body.connected,false);
 assert.deepEqual(await readdir(dir),[],'binary wrote application state into its working directory');
 console.log('Packaged runtime passed: version, embedded assets, portable API and disposable empty working directory.');
}finally{
 if(child?.exitCode===null){child.kill('SIGTERM');await new Promise(r=>child.once('exit',r));}
 await chmod(dir,0o755);await rm(dir,{recursive:true,force:true});
}
