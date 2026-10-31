// Round-trip package payloads in an owned temporary directory. No store/system installation.
import assert from 'node:assert/strict';
import {mkdtemp,readdir,readFile,mkdir,rm,stat} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {createHash,randomUUID} from 'node:crypto';
const out=resolve('dist',process.argv[2]||''),manifest=JSON.parse(await readFile(join(out,'build.json'),'utf8'));
const dir=await mkdtemp(join(tmpdir(),'nightbuoy-package-check-'));
function run(cmd,args,options={}){const result=spawnSync(cmd,args,{stdio:'inherit',timeout:120000,...options});if(result.error)throw result.error;assert.equal(result.status,0,`${cmd} failed`);return result;}
const hash=async path=>createHash('sha256').update(await readFile(path)).digest('hex');
async function smoke(path){assert.ok((await stat(path)).isFile());run(process.execPath,['scripts/smoke-runtime.mjs',path,manifest.version]);}
async function findExecutable(path){for(const d of await readdir(path,{withFileTypes:true})){const file=join(path,d.name);if(d.isFile()&&d.name==='nightbuoy')return file;if(d.isDirectory()){const nested=await findExecutable(file);if(nested)return nested;}}}
try{
 for(const name of manifest.artifacts)assert.match(name,/^[A-Za-z0-9_.-]+$/);
 const sums=(await readFile(join(out,'SHA256SUMS'),'utf8')).trim().split('\n');assert.equal(sums.length,manifest.artifacts.length);
 for(const line of sums){const [sum,name]=line.split('  ');assert.ok(manifest.artifacts.includes(name));assert.equal(await hash(join(out,name)),sum);}
 const stage=join(out,`nightbuoy-${manifest.version}-${manifest.target}`);
 await smoke(join(stage,process.platform==='win32'?'nightbuoy.com':'nightbuoy'));
 if(process.platform==='win32'){
  const zip=manifest.artifacts.find(n=>n.endsWith('.zip')),root=join(dir,'zip');
  run('powershell.exe',['-NoProfile','-Command','Expand-Archive -LiteralPath $env:NB_ZIP -DestinationPath $env:NB_DEST'],{env:{...process.env,NB_ZIP:join(out,zip),NB_DEST:root}});
  const folder=(await readdir(root))[0];await smoke(join(root,folder,'nightbuoy.com'));
  const setup=manifest.artifacts.find(n=>n.endsWith('-setup.exe')),install=join(dir,'installed');
  const rehearsalId='NightBuoy.Rehearsal.'+randomUUID();
  run(join(out,setup),['/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/CURRENTUSER','/NOICONS',`/NightBuoyInstallId=${rehearsalId}`,`/DIR=${install}`]);
  await smoke(join(install,'nightbuoy.com'));
  assert.equal(await hash(join(install,'nightbuoy.exe')),await hash(join(stage,'nightbuoy.exe')));
  run(join(install,'unins000.exe'),['/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART']);
 }else if(process.platform==='darwin'){
  const zip=manifest.artifacts.find(n=>n.endsWith('.zip')),root=join(dir,'zip');await mkdir(root);
  run('ditto',['-x','-k',join(out,zip),root]);const folder=(await readdir(root)).find(n=>n.startsWith('nightbuoy-'));
  await smoke(join(root,folder,'NightBuoy.app/Contents/MacOS/nightbuoy'));
  const pkg=manifest.artifacts.find(n=>n.endsWith('.pkg')),expanded=join(dir,'pkg');
  run('pkgutil',['--expand-full',join(out,pkg),expanded]);const payload=await findExecutable(expanded);assert.ok(payload);await smoke(payload);
  const dmg=manifest.artifacts.find(n=>n.endsWith('.dmg')),mount=join(dir,'dmg');await mkdir(mount);
  run('hdiutil',['attach','-readonly','-nobrowse','-mountpoint',mount,join(out,dmg)]);
  try{await smoke(join(mount,'NightBuoy.app/Contents/MacOS/nightbuoy'));}finally{run('hdiutil',['detach',mount]);}
 }else{
  for(const suffix of ['.tar.gz','.deb','.rpm','.pkg.tar.zst']){
   const file=manifest.artifacts.find(n=>n.endsWith(suffix));assert.ok(file,`missing ${suffix}`);
   const root=join(dir,suffix.replaceAll('.',''));await mkdir(root);
   if(suffix==='.deb')run('dpkg-deb',['--extract',join(out,file),root]);else run('bsdtar',['-xf',join(out,file),'-C',root]);
   const binary=suffix==='.tar.gz'?join(root,`nightbuoy-${manifest.version}-${manifest.target}`,'nightbuoy'):join(root,'usr/bin/nightbuoy');
   assert.equal(await hash(binary),await hash(join(stage,'nightbuoy')));await smoke(binary);
  }
 }
 console.log(`Package round-trips passed for ${manifest.target}.`);
}finally{await rm(dir,{recursive:true,force:true,maxRetries:10,retryDelay:300});}
