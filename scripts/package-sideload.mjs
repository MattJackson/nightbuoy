// Repackage the same-run verified static binary; no stores, releases or registry writes.
import assert from 'node:assert/strict';
import {createHash,randomUUID} from 'node:crypto';
import {cp,mkdir,readFile,writeFile,chmod,mkdtemp,rm} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync,spawn} from 'node:child_process';
import {createServer} from 'node:net';
const specs={
 'x86_64-unknown-linux-musl':{arch:'x86_64',snap:'amd64',docker:'amd64',
  tool:'793fca0ce4bcc309dc65d3f66669f58e3755643e4dadbe03932e7b436128494f',
  runtime:'617aa77314d57c8b8e4fae9c3f0b35af7b30d5529cb69e98f64f92510ed98a46'},
 'aarch64-unknown-linux-musl':{arch:'aarch64',snap:'arm64',docker:'arm64',
  tool:'578b2eac4cac3216bfb26cc19c95a9625b3122b3861a19de1e425e7ae0686281',
  runtime:'9a72a744d221576c9347ec074243acc5c3c7568896b12714e0e82e9f0bf47900'},
};
const target=process.argv[2],spec=specs[target];
assert.equal(process.env.GITHUB_ACTIONS,'true','installation rehearsals require a disposable GitHub Actions runner');
assert.ok(process.platform==='linux'&&spec,'native Linux x86-64/ARM64 target required');
assert.equal(process.arch,spec.docker==='amd64'?'x64':'arm64');
const source=resolve('dist',target),manifest=JSON.parse(await readFile(join(source,'build.json'),'utf8'));
assert.equal(manifest.target,target);assert.equal(manifest.linkage,'static');
assert.match(manifest.version,/^\d+\.\d+\.\d+$/);
if(process.env.GITHUB_SHA)assert.equal(manifest.commit,process.env.GITHUB_SHA,'binary must come from this exact commit');
const digest=bytes=>createHash('sha256').update(bytes).digest('hex');
const sums=(await readFile(join(source,'SHA256SUMS'),'utf8')).trim().split('\n');
assert.equal(sums.length,1);const [sum,archive]=sums[0].split('  ');
assert.match(archive,/^[A-Za-z0-9_.-]+\.tar\.gz$/);assert.deepEqual(manifest.artifacts,[archive]);
assert.equal(digest(await readFile(join(source,archive))),sum);
const out=resolve('dist',target+'-sideload'),temp=await mkdtemp(join(tmpdir(),'nightbuoy-sideload-'));
const name=`nightbuoy-${manifest.version}-${spec.arch}`,artifacts=[];
const id='org.nightbuoy.NightBuoy',image='nightbuoy-rehearsal:'+randomUUID();
const containerName='nightbuoy-rehearsal-'+randomUUID();
let installedSnap=false,installedFlatpak=false,builtImage=false,primaryError;
const runtimeEnv=Object.fromEntries(['PATH','HOME','USER','LOGNAME','XDG_RUNTIME_DIR','XDG_DATA_DIRS','XDG_DATA_HOME','DBUS_SESSION_BUS_ADDRESS'].filter(k=>process.env[k]!==undefined).map(k=>[k,process.env[k]]));
function run(command,args,options={}){
 const r=spawnSync(command,args,{stdio:'inherit',timeout:300000,...options});
 if(r.error)throw r.error;assert.equal(r.status,0,`${command} failed`);return r;
}
async function put(path,value,mode){await mkdir(resolve(path,'..'),{recursive:true});await writeFile(path,value,mode?{mode}:{});}
async function download(url,path,sha){
 const response=await fetch(url,{signal:AbortSignal.timeout(120000)});assert.ok(response.ok,`download failed: ${url}`);
 const chunks=[];let size=0;for await(const chunk of response.body){size+=chunk.length;assert.ok(size<=128*1024*1024,'tool download too large');chunks.push(chunk);}
 const bytes=Buffer.concat(chunks);assert.equal(digest(bytes),sha,'pinned tool checksum mismatch');await writeFile(path,bytes);await chmod(path,0o755);
}
async function smoke(command,args=[],extra={}){
 const version=run(command,[...args,'--version'],{encoding:'utf8',stdio:'pipe',env:{...runtimeEnv,...extra}});
 assert.equal(version.stdout.trim(),'NightBuoy '+manifest.version);
 const transports=run(command,[...args,'check-transports'],{encoding:'utf8',stdio:'pipe',env:{...runtimeEnv,...extra}});
 assert.equal(transports.stdout.trim(),'Provider TLS clients initialized.');
 const probe=createServer();await new Promise(r=>probe.listen(0,'127.0.0.1',r));const port=probe.address().port;await new Promise(r=>probe.close(r));
 const origin=`http://127.0.0.1:${port}`,cwd=join(temp,'readonly-'+randomUUID());await mkdir(cwd);await chmod(cwd,0o555);
 const env={...runtimeEnv,...extra,NIGHTBUOY_LISTEN:`127.0.0.1:${port}`,NIGHTBUOY_PUBLIC_URL:origin};
 // Each sandbox gets the explicit origin/listen values; no provider credentials are passed.
 const expanded=args.map(v=>v.replaceAll('{port}',String(port)).replaceAll('{origin}',origin));
 const child=spawn(command,[...expanded,'portable'],{cwd,env,stdio:'inherit',detached:true});
 let exited=false;const exit=new Promise(r=>child.once('exit',()=>{exited=true;r();}));
 try{
  let response;for(let i=0;i<200;i++){assert.ok(!exited,'packaged process exited');try{response=await fetch(origin);if(response.ok)break;}catch{}await new Promise(r=>setTimeout(r,100));}
  assert.ok(response?.ok,'packaged API did not start');const html=await response.text();assert.match(html,/NightBuoy/);
  const assets=[...html.matchAll(/(?:src|href)="(\/assets\/[^"\s]+)"/g)].map(m=>m[1]);assert.ok(assets.length);
  for(const path of assets)assert.ok((await fetch(origin+path)).ok,'embedded asset missing');
  const r=await fetch(origin+'/api/session',{method:'POST',headers:{Origin:origin,'x-nightbuoy-bootstrap':'1'}});assert.ok(r.ok);
  const cookie=r.headers.get('set-cookie').split(';')[0];
  const status=await fetch(origin+'/api/status',{headers:{Cookie:cookie,Origin:origin}});assert.ok(status.ok);assert.equal((await status.json()).mode,'portable');
 }finally{
  if(!exited){try{process.kill(-child.pid,'SIGTERM');}catch(e){if(e.code!=='ESRCH')throw e;}await Promise.race([exit,new Promise(r=>setTimeout(r,5000))]);if(!exited){try{process.kill(-child.pid,'SIGKILL');}catch(e){if(e.code!=='ESRCH')throw e;}await exit;}}
  await chmod(cwd,0o755);
 }
}
try{
 // Never replace an existing installation, even when this script is run outside CI.
 const flatpakExisting=spawnSync('flatpak',['info','--user',id],{stdio:'pipe'});
 assert.equal(flatpakExisting.status,1,'refusing to replace an existing Flatpak (or tooling failed)');
 const snapExisting=spawnSync('snap',['list','nightbuoy'],{stdio:'pipe'});
 assert.equal(snapExisting.status,1,'refusing to replace an existing Snap (or tooling failed)');
 await mkdir(out,{recursive:true});run('tar',['-xf',join(source,archive),'-C',temp]);
 const payload=join(temp,`nightbuoy-${manifest.version}-${target}`),binary=join(payload,'nightbuoy');
 run(process.execPath,['scripts/smoke-runtime.mjs',binary,manifest.version]);
 const appdir=join(temp,'NightBuoy.AppDir');await mkdir(appdir);await cp(binary,join(appdir,'nightbuoy'));await chmod(join(appdir,'nightbuoy'),0o755);
 await put(join(appdir,'AppRun'),'#!/bin/sh\nexec "$(dirname "$(readlink -f "$0")")/nightbuoy" "$@"\n',0o755);
 await cp('packaging/nightbuoy.desktop',join(appdir,'nightbuoy.desktop'));await cp('web/public/nightbuoy.svg',join(appdir,'nightbuoy.svg'));
 run('rsvg-convert',['--width=256','--height=256','--output='+join(appdir,'nightbuoy.png'),'web/public/nightbuoy.svg']);
 await cp(join(appdir,'nightbuoy.png'),join(appdir,'.DirIcon'));
 for(const file of ['LICENSE','THIRD_PARTY_NOTICES.md','README.md'])await cp(join(payload,file),join(appdir,file));
 await download('https://raw.githubusercontent.com/AppImage/type2-runtime/fedfad51acc2860b2916a1eef32ba4a500ff31ef/LICENSE',join(appdir,'APPIMAGE_RUNTIME_LICENSE'),'aa154fc9070614bbe7921f89db11efd1dba7a1f3a41685958110e2230f9c0ca1');
 const tool=join(temp,'appimagetool'),runtime=join(temp,'runtime');
 await download(`https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${spec.arch}.AppImage`,tool,spec.tool);
 await download(`https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-${spec.arch}`,runtime,spec.runtime);
 run(tool,['--appimage-extract'],{cwd:temp,stdio:'ignore'});
 const appimage=name+'.AppImage';run(join(temp,'squashfs-root/AppRun'),['--runtime-file',runtime,appdir,join(out,appimage)],{env:{...process.env,ARCH:spec.arch}});artifacts.push(appimage);
 // Extraction mode works without FUSE and the AppImage-owned temporary mount is removed on exit.
 await smoke(join(out,appimage),[],{APPIMAGE_EXTRACT_AND_RUN:'1'});

 // A direct sideload bundle. No Flathub enrollment, store upload or automatic updates.
 const flat=join(temp,'flatpak');
 run('flatpak',['build-init','--arch='+spec.arch,flat,id,'org.freedesktop.Sdk','org.freedesktop.Platform','25.08']);
 await mkdir(join(flat,'files/bin'),{recursive:true});await cp(binary,join(flat,'files/bin/nightbuoy'));

 await put(join(flat,`files/share/applications/${id}.desktop`),(await readFile('packaging/nightbuoy.desktop','utf8')).replace('Icon=nightbuoy','Icon='+id));
 await mkdir(join(flat,'files/share/icons/hicolor/scalable/apps'),{recursive:true});await cp('web/public/nightbuoy.svg',join(flat,`files/share/icons/hicolor/scalable/apps/${id}.svg`));
 for(const file of ['LICENSE','THIRD_PARTY_NOTICES.md','README.md'])await put(join(flat,'files/share/doc/nightbuoy',file),await readFile(join(payload,file)));
 run('flatpak',['build-finish','--share=network','--command=nightbuoy',flat]);
 const repository=join(temp,'flatpak-repo'),bundle=name+'.flatpak';
 run('flatpak',['build-export',repository,flat]);run('flatpak',['build-bundle','--arch='+spec.arch,repository,join(out,bundle),id]);artifacts.push(bundle);
 installedFlatpak=true;run('flatpak',['install','--user','--noninteractive',join(out,bundle)]);
 await smoke('flatpak',['run','--env=NIGHTBUOY_LISTEN=127.0.0.1:{port}','--env=NIGHTBUOY_PUBLIC_URL={origin}',id]);

 const snap=join(temp,'snap');await mkdir(join(snap,'bin'),{recursive:true});await cp(binary,join(snap,'bin/nightbuoy'));
 for(const file of ['LICENSE','THIRD_PARTY_NOTICES.md','README.md'])await cp(join(payload,file),join(snap,file));
 await put(join(snap,'meta/snap.yaml'),`name: nightbuoy\nversion: '${manifest.version}'\nsummary: Portable encrypted forum client\ndescription: Local browser and terminal access to encrypted remote forum storage.\nbase: core24\ngrade: devel\nconfinement: strict\narchitectures: [${spec.snap}]\napps:\n  nightbuoy:\n    command: bin/nightbuoy\n    plugs: [network, network-bind, home, removable-media, desktop]\n`);
 await mkdir(join(snap,'meta/gui'),{recursive:true});await cp('web/public/nightbuoy.svg',join(snap,'meta/gui/nightbuoy.svg'));await put(join(snap,'meta/gui/nightbuoy.desktop'),(await readFile('packaging/nightbuoy.desktop','utf8')).replace('Icon=nightbuoy','Icon=${SNAP}/meta/gui/nightbuoy.svg'));
 const snapFile=name+'.snap';run('snap',['pack',snap,out,'--filename='+snapFile]);artifacts.push(snapFile);
 assert.equal(digest(run('unsquashfs',['-cat',join(out,snapFile),'bin/nightbuoy'],{stdio:'pipe',maxBuffer:128*1024*1024}).stdout),digest(await readFile(binary)));
 installedSnap=true;run('sudo',['snap','install','--dangerous',join(out,snapFile)]);
 await smoke('snap',['run','nightbuoy']);

 // Scratch has no shell, mutable data volume, database or root process.
 const context=join(temp,'container');await mkdir(context);await cp(binary,join(context,'nightbuoy'));
 for(const file of ['LICENSE','THIRD_PARTY_NOTICES.md'])await cp(join(payload,file),join(context,file));
 await cp('/etc/ssl/certs/ca-certificates.crt',join(context,'ca-certificates.crt'));
 await cp('/usr/share/doc/ca-certificates/copyright',join(context,'CA_CERTIFICATES_COPYRIGHT'));
 await put(join(context,'Dockerfile'),`FROM scratch\nCOPY nightbuoy /nightbuoy\nCOPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt\nCOPY LICENSE THIRD_PARTY_NOTICES.md CA_CERTIFICATES_COPYRIGHT /licenses/\nUSER 10001:10001\nWORKDIR /\nENV NIGHTBUOY_LISTEN=127.0.0.1:8080 SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt\nEXPOSE 8080\nENTRYPOINT ["/nightbuoy"]\nCMD ["portable"]\n`);
 run('docker',['build','--platform=linux/'+spec.docker,'-t',image,context]);builtImage=true;
 const emptyRoots=spawnSync('docker',['run','--rm','--name='+containerName+'-empty-roots','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges',
  '-e','SSL_CERT_FILE=/absent.pem','-e','SSL_CERT_DIR=/absent-roots',image,'check-transports'],{encoding:'utf8',timeout:30000,env:runtimeEnv});
 assert.notEqual(emptyRoots.status,0);assert.match(emptyRoots.stderr,/No CA certificates were loaded from the system/);
 try{
  await smoke('docker',['run','--name='+containerName,'--rm','--read-only','--cap-drop=ALL','--security-opt=no-new-privileges','--network=host','-e','NIGHTBUOY_LISTEN=127.0.0.1:{port}','-e','NIGHTBUOY_PUBLIC_URL={origin}',image]);
 }finally{
  // The daemon may outlive a killed CLI; never rely on --rm/CLI signal forwarding alone.
  const exists=spawnSync('docker',['container','inspect',containerName],{stdio:'pipe'});
  if(exists.status===0)run('docker',['container','rm','--force',containerName]);
 }
 const container=name+'-container.tar';run('docker',['save','-o',join(out,container),image]);run('docker',['load','-i',join(out,container)]);artifacts.push(container);
 const hashes=[];for(const file of artifacts)hashes.push(digest(await readFile(join(out,file)))+'  '+file);
 await writeFile(join(out,'SHA256SUMS'),hashes.join('\n')+'\n');
 await writeFile(join(out,'build.json'),JSON.stringify({...manifest,formats:'sideload',signing:'unsigned',artifacts,appimageRuntime:'fedfad51acc2860b2916a1eef32ba4a500ff31ef',flatpakRuntime:'25.08'},null,2)+'\n');
 console.log(`Sideload build/runtime rehearsals passed for ${target}.`);
}catch(error){primaryError=error;throw error;}finally{
 const cleanupErrors=[];
 if(builtImage)for(const name of [containerName,containerName+'-empty-roots']){
  try{const exists=spawnSync('docker',['container','inspect',name],{stdio:'pipe'});if(exists.status===0)run('docker',['container','rm','--force',name]);}catch(error){cleanupErrors.push(error);}
 }
 for(const [enabled,command,args] of [
  [installedFlatpak,'flatpak',['uninstall','--user','--noninteractive',id]],
  [installedSnap,'sudo',['snap','remove','nightbuoy','--purge']],
  [builtImage,'docker',['image','rm',image]],
 ])if(enabled){try{run(command,args);}catch(error){cleanupErrors.push(error);}}
 try{await rm(temp,{recursive:true,force:true});}catch(error){cleanupErrors.push(error);}
 if(cleanupErrors.length)throw new AggregateError([...(primaryError?[primaryError]:[]),...cleanupErrors],'rehearsal cleanup failed');
}

