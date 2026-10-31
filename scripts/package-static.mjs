import assert from 'node:assert/strict';
import {mkdir,cp,chmod,writeFile,readFile,rm,mkdtemp} from 'node:fs/promises';
import {resolve,join} from 'node:path';
import {tmpdir} from 'node:os';
import {spawnSync} from 'node:child_process';
import {createHash} from 'node:crypto';
const target=process.argv[2],emulators={
 'x86_64-unknown-linux-musl':'',
 'aarch64-unknown-linux-musl':'qemu-aarch64-static',
 'armv7-unknown-linux-musleabihf':'qemu-arm-static',
};
assert.ok(process.platform==='linux'&&Object.hasOwn(emulators,target),'supported Linux musl target required');
const version=JSON.parse(await readFile('package.json','utf8')).version;assert.match(version,/^\d+\.\d+\.\d+$/);
const out=resolve('dist',target),name=`nightbuoy-${version}-${target}`,stage=join(out,name),archive=name+'.tar.gz';
const binary=resolve('target',target,'release/nightbuoy');
function run(cmd,args,env=process.env){const r=spawnSync(cmd,args,{stdio:'inherit',env,timeout:120000});if(r.error)throw r.error;assert.equal(r.status,0,`${cmd} failed`);}
await mkdir(out,{recursive:true});await rm(stage,{recursive:true,force:true});await mkdir(stage);
await cp(binary,join(stage,'nightbuoy'));await chmod(join(stage,'nightbuoy'),0o755);
for(const file of ['LICENSE','README.md','THIRD_PARTY_NOTICES.md'])await cp(file,join(stage,file));
const elf=spawnSync('readelf',['-l',binary],{encoding:'utf8'});assert.equal(elf.status,0);assert.ok(!elf.stdout.includes('INTERP'),'musl binary must not require a dynamic ELF interpreter');
run('tar',['-czf',join(out,archive),'-C',out,name]);
const sha=createHash('sha256').update(await readFile(join(out,archive))).digest('hex');
await writeFile(join(out,'SHA256SUMS'),`${sha}  ${archive}\n`);
await writeFile(join(out,'build.json'),JSON.stringify({name:'NightBuoy',version,target,commit:process.env.GITHUB_SHA||null,signing:'unsigned',linkage:'static',artifacts:[archive]},null,2)+'\n');
const temp=await mkdtemp(join(tmpdir(),'nightbuoy-static-package-'));
try{
 run('tar',['-xf',join(out,archive),'-C',temp]);
 const extracted=join(temp,name,'nightbuoy');assert.deepEqual(await readFile(extracted),await readFile(binary));
 run(process.execPath,['scripts/smoke-runtime.mjs',extracted,version],{...process.env,NIGHTBUOY_SMOKE_EMULATOR:emulators[target]});
 const emulator=emulators[target];
 const missingRoots=spawnSync(emulator||extracted,[...(emulator?[extracted]:[]),'check-transports'],{
  encoding:'utf8',timeout:15000,env:{...process.env,SSL_CERT_FILE:join(temp,'absent.pem'),SSL_CERT_DIR:join(temp,'absent-roots')},
 });
 assert.notEqual(missingRoots.status,0,'transport check must reject an empty platform trust store');
 assert.match(missingRoots.stderr,/No CA certificates were loaded from the system/);
}finally{await rm(temp,{recursive:true,force:true});}
console.log(`Static package and extracted runtime passed for ${target}.`);
