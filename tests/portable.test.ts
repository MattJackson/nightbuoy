import {terminalFixture} from './terminal-fixture.ts';
import {sealPrivate,openPrivate,privateLocator} from '../web/src/lib/private.ts';
import {test} from 'node:test';import assert from 'node:assert/strict';import {createServer,request} from 'node:http';import {spawn,execFile} from 'node:child_process';import {promisify} from 'node:util';import {mkdtemp,readdir,rm,writeFile,chmod,readFile} from 'node:fs/promises';import {tmpdir} from 'node:os';import {resolve,join} from 'node:path';import * as c from '../web/src/lib/crypto.ts';import {metadataKey,prepareMetadata,unwrapEpoch,wrapEpochForMembers} from '../web/src/lib/metadata.ts';import {verifyArchive,type Archive} from '../web/src/lib/protocol.ts';
const bin=resolve('target/debug/nightbuoy');const headName=await c.hash('nightbuoy-opaque-head-v2');
async function fixture(kind:string){const objects=new Map<string,{bytes:Buffer,sha:string}>();let writes=0;let drop=false;let ambiguous=false;let ambiguousObject=false;let headUnavailable=false;let redirect="";let denied=0;const server=createServer(async(req,res)=>{if(headUnavailable&&req.url?.split('?')[0].endsWith('/'+headName)){res.writeHead(503).end();return;}if(denied){res.writeHead(denied,{'Content-Type':'application/json'}).end('{}');return;}if(drop){res.writeHead(503).end();return;}if(redirect){res.writeHead(302,{Location:redirect}).end();return;}const u=new URL(req.url!,'http://localhost'),key=kind==='s3'?u.pathname:u.pathname.split('/contents/')[1];const old=objects.get(key);const send=(code:number,v:any)=>{res.writeHead(code,{'Content-Type':'application/json'}).end(JSON.stringify(v));};if(req.method==='GET'&&kind!=='s3'&&!u.pathname.includes('/contents/')){send(200,{default_branch:'main',name:'main'});return;}if(req.method==='GET'){if(!old){send(404,{});return;}if(kind==='s3'){res.writeHead(200,{ETag:'"'+old.sha+'"','Content-Length':old.bytes.length}).end(old.bytes);}else send(200,{sha:old.sha,encoding:'base64',content:old.bytes.toString('base64')});return;}const chunks=[];for await(const b of req)chunks.push(b);let bytes:Buffer;if(kind==='s3'){if(req.headers['if-none-match']==='*'&&old){send(412,{});return;}if(req.headers['if-match']&&req.headers['if-match']!=='"'+old?.sha+'"'){send(412,{});return;}assert.ok(req.headers['if-match']||req.headers['if-none-match'],'S3 MUST condition every write');bytes=Buffer.concat(chunks);}else{const body=JSON.parse(Buffer.concat(chunks).toString());for(const field of ['author','committer'])assert.deepEqual(body[field],{name:'NightBuoy',email:'storage@nightbuoy.invalid'},'repository writes must override provider account attribution');if((old&&body.sha!==old.sha)||(!old&&body.sha)){send(409,{});return;}assert.equal(req.method,kind==='forgejo'&&!old?'POST':'PUT');bytes=Buffer.from(body.content,'base64');}const sha=String(++writes).padStart(40,'0');objects.set(key,{bytes,sha});if((ambiguous&&key.endsWith(headName))||ambiguousObject){ambiguous=false;ambiguousObject=false;send(503,{});return;}if(kind==='s3')res.writeHead(200,{ETag:'"'+sha+'"'}).end();else send(201,{content:{sha}});});await new Promise<void>(r=>server.listen(0,'127.0.0.1',r));return {objects,endpoint:`http://127.0.0.1:${(server.address() as any).port}`,stop:()=>new Promise<void>(r=>server.close(()=>r())),offline:(v:boolean)=>drop=v,ambiguous:()=>ambiguous=true,ambiguousObject:()=>ambiguousObject=true,headUnavailable:(v:boolean)=>headUnavailable=v,redirect:(v:string)=>redirect=v,deny:(v:number)=>denied=v};}
async function launcher(){const dir=await mkdtemp(join(tmpdir(),'nightbuoy-portable-'));await chmod(dir,0o555);const probe=createServer();await new Promise<void>(r=>probe.listen(0,'127.0.0.1',r));const port=(probe.address()as any).port;await new Promise<void>(r=>probe.close(()=>r()));const origin=`http://127.0.0.1:${port}`;const child=spawn(bin,['portable'],{cwd:dir,env:{PATH:process.env.PATH,NIGHTBUOY_LISTEN:`127.0.0.1:${port}`,NIGHTBUOY_PUBLIC_URL:origin,NIGHTBUOY_TESTING:'1'},stdio:['ignore','ignore','pipe']});let log='';child.stderr.on('data',b=>log+=b);for(let i=0;i<100;i++){try{if((await fetch(origin)).ok)break;}catch{}await new Promise(r=>setTimeout(r,50));if(i===99)throw Error(log);}return {dir,origin,stop:async()=>{child.kill('SIGINT');await new Promise<void>(r=>child.once('exit',()=>r()));assert.deepEqual(await readdir(dir),[],'read-only application directory must stay empty');await chmod(dir,0o755);await rm(dir,{recursive:true});}};}
async function client(origin:string){const boot=await fetch(origin+'/api/session',{method:'POST',headers:{Origin:origin,'x-nightbuoy-bootstrap':'1'}});const csrf=(await boot.json()).csrf,cookie=boot.headers.get('set-cookie')!.split(';')[0];return {async call(path:string,data?:any,override:any={}){const r=await fetch(origin+'/api/'+path,{method:data===undefined?'GET':'POST',headers:{Cookie:cookie,Origin:origin,'Content-Type':'application/json','x-nightbuoy-csrf':csrf,...override},...(data===undefined?{}:{body:JSON.stringify(data)})});const v=await r.json();if(!r.ok)throw Error(v.error||String(r.status));return v;},cookie,csrf};}
async function authenticate(a:Awaited<ReturnType<typeof client>>,identity:c.Identity){let total=1;for(let source=0;source<total;source++){const bootstrap=await a.call('bootstrap',{source});total=bootstrap.sources;if(!bootstrap.grants.length)continue;try{const key=await unwrapEpoch(identity,bootstrap.ephemeral,bootstrap.grants);await a.call('metadata',{key:await metadataKey(key)});key.fill(0);break;}catch{}}const challenge=await a.call('challenge',{device:identity.device});await a.call('login',{signed:await c.signed(identity,challenge.body)});}

async function prepare(a:Awaited<ReturnType<typeof client>>,i:c.Identity,kind:string,signed:c.Signed,extra:any={}){let verified=null;const keys:Record<number,Uint8Array<ArrayBuffer>>={};if(kind!=='genesis'){verified=await verifyArchive(extra.archive??await a.call('sync'));for(const [epoch,grants] of Object.entries(verified.view.grants)){if(grants[i.device.id])keys[Number(epoch)]=await c.openGrant(i,grants[i.device.id]);}}const metadata=await prepareMetadata(i,kind,signed,verified,keys);return a.call(extra.archive?'recover-prepare':'prepare',{kind,signed,...extra,...metadata});}
async function publish(a:Awaited<ReturnType<typeof client>>,i:c.Identity,kind:string,signed:c.Signed,extra={}){const p=await prepare(a,i,kind,signed,extra);if(p.accepted)return;await a.call('commit',{ticket:p.ticket,header:await c.signed(i,p.body)});}

// GitHub additionally admits the full inline-upload limit without bloating every later snapshot replay.
for(const kind of ['github','forgejo','s3'])test(`portable ${kind}: conditional races, zero frontend restart, corruption, auth and rollback`,{timeout:90000},async()=>{
 const backend=await fixture(kind),backup=await fixture(kind);let app=await launcher();let app2=await launcher();try{
 const primary={kind,endpoint:backend.endpoint,namespace:'forum',salt:c.b64(c.random()),owner:'owner',repository:'repo',branch:'main',bucket:'bucket',region:'us-east-1'};const id=c.b64(Buffer.from(await c.hash(c.canonical(primary)),'hex'));let connection:any={version:2,primary,replicas:[],community:''};const access={backend:id,token:'synthetic-only-token',access_key:'fake',secret_key:'fake'};const a=await client(app.origin),b=await client(app2.origin);
 await assert.rejects(a.call('connect',{connection,access:{...access,backend:c.b64(c.random())}}),/binding/);await a.call('connect',{connection,access});
 assert.equal((await a.call('status')).configured,false);await assert.rejects(a.call('sync'),/sign in|approval/);
 const owner=await c.generate(),key=c.random();const discovery=await wrapEpochForMembers([owner.device],key);await authenticate(a,owner);const genesis=await c.signed(owner,['nightbuoy-genesis',1,owner.device,{name:'Portable test',skin:'nightbuoy',identity:'key',admission:'approval',history:true,portable:{version:1,primary:id,discovery}},id,[await c.grant(owner.device,1,key)]]);const community=await c.hash(genesis.body);await publish(a,owner,'genesis',genesis);connection=await a.call('connection');assert.equal(connection.community,community);assert.ok(connection.checkpoint);assert.ok(!JSON.stringify(connection).includes(access.token));
 const initialHeadKey=[...backend.objects.keys()].find(k=>k.endsWith('/'+headName))!;const initialHead=structuredClone(backend.objects.get(initialHeadKey)!);const gArchive:Archive=await a.call('sync');const initial=await verifyArchive(gArchive);assert.equal(initial.checkpoint,'p:'+connection.checkpoint);
 // Native CLI and independent browser verifier agree.
 const archivePath=join(tmpdir(),`nightbuoy-archive-${crypto.randomUUID()}.json`);await writeFile(archivePath,JSON.stringify(gArchive));try{const native=await promisify(execFile)(bin,['verify-archive',archivePath]);assert.equal(JSON.parse(native.stdout).community,community);}finally{await rm(archivePath);}
 await b.call('connect',{connection,access});await authenticate(b,owner);
 // Owner-private state stays outside the immutable forum chain and survives conditional races.
 const locator=await privateLocator(owner,community,'member-state');assert.equal(await a.call('private-read',{community,branch:community,member:owner.device.id,locator}),null);await assert.rejects(a.call('private-read',{locator,community:'f'.repeat(64),branch:community,member:owner.device.id}),/another identity or forum branch/);
 const privateValue={watched:['synthetic topic'],privateMarker:'private member state',padding:'x'.repeat(220000)},privateFrame=await sealPrivate(owner,community,'member-state',privateValue);backend.ambiguousObject();
 const saved=await a.call('private-write',{community,branch:community,member:owner.device.id,locator,frame:c.b64(privateFrame),version:null});assert.ok(saved.version);
 assert.deepEqual(await openPrivate(owner,community,'member-state',c.un64((await b.call('private-read',{community,branch:community,member:owner.device.id,locator})).frame)),privateValue);
 await assert.rejects(a.call('private-read',{community,branch:community,member:owner.device.id,locator:'../'+headName}),/invalid private locator/);
 await assert.rejects(a.call('private-write',{community,branch:community,member:owner.device.id,locator,frame:c.b64(new Uint8Array(300000)),version:saved.version}),/invalid private state frame|private frame too large|request body too large/);
 const privateCandidates=await Promise.all([1,2].map(i=>sealPrivate(owner,community,'member-state',{choice:i})));
 const privateRace=await Promise.allSettled([a.call('private-write',{community,branch:community,member:owner.device.id,locator,frame:c.b64(privateCandidates[0]),version:saved.version}),b.call('private-write',{community,branch:community,member:owner.device.id,locator,frame:c.b64(privateCandidates[1]),version:saved.version})]);assert.equal(privateRace.filter(r=>r.status==='fulfilled').length,1);
 const winner=privateRace[0].status==='fulfilled'?0:1;const confirmed=await b.call('private-read',{community,branch:community,member:owner.device.id,locator});assert.equal((await openPrivate(owner,community,'member-state',c.un64(confirmed.frame))).choice,winner+1);
 assert.equal((await a.call('private-write',{community,branch:community,member:owner.device.id,locator,frame:c.b64(privateCandidates[winner]),version:saved.version})).version,confirmed.version,'exact candidate retry is idempotent after an ambiguous success');
 await assert.rejects(b.call('private-write',{community,branch:community,member:owner.device.id,locator,frame:c.b64(privateCandidates[1-winner]),version:saved.version}),/private state changed/);
 const stranger=await client(app.origin);await stranger.call('connect',{connection,access});await authenticate(stranger,await c.generate());await assert.rejects(stranger.call('private-read',{community,branch:community,member:owner.device.id,locator}),/membership approval/);
 assert.equal((await a.call('sync')).order.length,0,'private preferences must not append forum history');

 const replicaBackend={...primary,endpoint:backup.endpoint,namespace:'backup',salt:c.b64(c.random())};const replicaId=c.b64(Buffer.from(await c.hash(c.canonical(replicaBackend)),'hex'));
 const board=crypto.randomUUID();const event=await c.encryptEvent(owner,key,[1,community,owner.device.id,community,1,'board',board,'','',1],{title:'Encrypted board',description:'private marker'});backend.ambiguous();await assert.rejects(publish(a,owner,'event',event),/conditional write failed/);await publish(a,owner,'event',event);assert.equal((await a.call('sync')).records.length,1,'ambiguous accepted append retries must deduplicate');await a.call('replica-copy',{backend:replicaBackend,access:{...access,backend:replicaId}});assert.equal((await a.call('replication')).copied,true);
 backend.headUnavailable(true);const forbiddenState=await sealPrivate(owner,community,'member-state',{mustNotPublish:'stale replica membership'});await assert.rejects(a.call('private-write',{community,branch:community,member:owner.device.id,locator,frame:c.b64(forbiddenState),version:confirmed.version}),/backend request failed|Generic S3 error|Generic HTTP error/);backend.headUnavailable(false);assert.equal((await a.call('private-read',{community,branch:community,member:owner.device.id,locator})).frame,confirmed.frame,'private writes require live primary membership even when an up-to-date replica exists');
 if(kind==='s3'){
  const latest=await a.call('connection');const {accessKey}=await import('../web/src/lib/metadata.ts');
  const dir=await mkdtemp(join(tmpdir(),'nightbuoy-native-s3-'));
  try{
   await writeFile(join(dir,'key'),accessKey(c.b64(key),community,community,latest.checkpoint,'forum'),{mode:0o600});
   await writeFile(join(dir,'credentials'),JSON.stringify({access_key:'fake',secret_key:'fake'}),{mode:0o600});
   const native=await promisify(execFile)(bin,['cli','-f',backend.endpoint.replace('http://','s3+http://')+'/bucket/forum','--key-file',join(dir,'key'),'--provider-credentials-file',join(dir,'credentials'),'--print'],{env:{...process.env,NIGHTBUOY_TESTING:'1'}});
   assert.equal(JSON.parse(native.stdout).content.title,'Encrypted board');
  }finally{await rm(dir,{recursive:true,force:true});}
 }
 if(kind==='github'){
  const large=await c.encryptEvent(owner,key,[1,community,owner.device.id,community,1,'topic',crypto.randomUUID(),board,'',2],{title:'Large ingress admission',body:'synthetic request limit',attachments:[{name:'ingress-limit.bin',size:3*1024*1024,data:Buffer.alloc(3*1024*1024,23).toString('base64')}]});
  assert.ok((await prepare(a,owner,'event',large)).ticket,'maximum inline upload must pass authenticated admission and protocol validation');
  assert.equal((await a.call('sync')).order.length,1,'preparation must not publish or change history');
 }
 const getEvent=async(label:string)=>c.encryptEvent(owner,key,[1,community,owner.device.id,community,1,'topic',crypto.randomUUID(),board,'',2],{title:label,body:'secret discussion'});
 const eventA=await getEvent('A'),eventB=await getEvent('B');const poisoned=await prepareMetadata(owner,'event',eventA,await verifyArchive(await a.call('sync')),{1:key});poisoned.metadata_wrapped[owner.device.id]=c.b64(c.random(60));await assert.rejects(a.call('prepare',{kind:'event',signed:eventA,...poisoned}),/unsigned discovery grant/);const [p1,p2]=await Promise.all([prepare(a,owner,'event',eventA),prepare(b,owner,'event',eventB)]);
 const race=await Promise.allSettled([a.call('commit',{ticket:p1.ticket,header:await c.signed(owner,p1.body)}),b.call('commit',{ticket:p2.ticket,header:await c.signed(owner,p2.body)})]);assert.equal(race.filter(x=>x.status==='fulfilled').length,1,'CAS must choose exactly one head');const loser=race[0].status==='rejected'?a:b;await publish(loser,owner,'event',race[0].status==='rejected'?eventA:eventB);
 const archive:Archive=await a.call('sync');assert.equal((await a.call('replication')).copied,false,'a later append invalidates exact backup confirmation');const verified=await verifyArchive(archive,{community,tip:initial.checkpoint});assert.equal(verified.events.length,3);assert.equal((await b.call('sync')).order.length,3);
 // Stripped proofs, changed receipts, swapped contexts, stale signed heads all fail.
 const stripped=structuredClone(archive);delete stripped.portable_proof;await assert.rejects(verifyArchive(stripped),/confirmation/);const altered=structuredClone(archive);altered.portable_proof!.headers[1].signature=c.b64(c.random(64));await assert.rejects(verifyArchive(altered),/certificate/);const duplicate=structuredClone(archive);duplicate.portable_proof!.headers.push(duplicate.portable_proof!.headers[0]);await assert.rejects(verifyArchive(duplicate),/inventory/);
 const reset=await c.signed(owner,['nightbuoy-control',1,community,community,owner.device.id,'a'.repeat(64),'reconstitute',{publisher:id,portable:{version:1,primary:id},epoch:2,exclude:[],grants:[await c.grant(owner.device,2,c.random())]}]);await assert.rejects(publish(a,owner,'control',reset),/explicit recovery/);
 const anon=await client(app.origin);await anon.call('connect',{connection,access:{...access,token:'',access_key:'',secret_key:''}});await assert.rejects(anon.call('sync'),/sign in/);
 const badCsrf=await fetch(app.origin+'/api/logout',{method:'POST',headers:{Cookie:a.cookie,Origin:app.origin,'Content-Type':'application/json'},body:'{}'});assert.equal(badCsrf.ok,false);const getLogout=await fetch(app.origin+'/api/logout',{headers:{Cookie:a.cookie}});assert.equal(getLogout.ok,false);const badHost=await new Promise<number>(resolve=>{request(app.origin+'/api/status',{headers:{Host:'evil.invalid',Cookie:a.cookie}},r=>{r.resume();resolve(r.statusCode!);}).end();});assert.equal(badHost,403);
 // Per-member session reservations cannot consume all global capacity.
 const extra1=await client(app.origin);await extra1.call('connect',{connection:await a.call('connection'),access});await authenticate(extra1,owner);const extra2=await client(app.origin);await extra2.call('connect',{connection:await a.call('connection'),access});await authenticate(extra2,owner);const extra3=await client(app.origin);await extra3.call('connect',{connection:await a.call('connection'),access});await assert.rejects(authenticate(extra3,owner),/two active sessions/);await extra1.call('logout',{});await authenticate(extra3,owner);await extra2.call('logout',{});await extra3.call('logout',{});
 // No remotely stored object can contain plaintext or transport credentials.
 for(const o of backend.objects.values()){for(const secret of ['private marker','private member state','secret discussion','Portable test',owner.device.id,owner.device.sign,JSON.stringify(owner.device.wrap),'nightbuoy-genesis','nightbuoy-control','nightbuoy-storage-head','publisher','grants',access.token,JSON.stringify(owner.privateSign)])assert.ok(!o.bytes.includes(Buffer.from(secret)));}
 await a.call('replica-copy',{backend:replicaBackend,access:{...access,backend:replicaId}});assert.equal((await a.call('replication')).copied,true);
 connection=await a.call('connection');assert.equal(connection.replicas.length,1);await app.stop();await app2.stop();app=await launcher();app2=await launcher();const cold=await client(app.origin);await cold.call('connect',{connection,access});await authenticate(cold,owner);assert.equal((await openPrivate(owner,community,'member-state',c.un64((await cold.call('private-read',{community,branch:community,member:owner.device.id,locator})).frame))).choice,winner+1);const recovered=await verifyArchive(await cold.call('sync'),{community,tip:verified.checkpoint});assert.equal(recovered.events.length,3);assert.deepEqual(await readdir(app.dir),[]);
 // Cold replica-only reads, no write-authority transfer, explicit new-namespace recovery.
 backend.offline(true);const replicaClient=await client(app2.origin);await replicaClient.call('connect',{connection,access});await authenticate(replicaClient,owner);assert.equal((await replicaClient.call('sync')).records.length,3);assert.equal((await replicaClient.call('replication')).from_replica,true);await assert.rejects(publish(replicaClient,owner,'event',await getEvent('must stay pending')),/backend request failed|Generic S3 error/);
 const forkBackend={...replicaBackend,namespace:'separate-branch',salt:c.b64(c.random())},forkId=c.b64(Buffer.from(await c.hash(c.canonical(forkBackend)),'hex'));const fork=await client(app2.origin);await fork.call('connect',{connection:{version:2,primary:forkBackend,replicas:[],community:''},access:{...access,backend:forkId}});await authenticate(fork,owner);const resetKey=c.random();const forkDiscovery=await wrapEpochForMembers([owner.device],resetKey);const forkControl=await c.signed(owner,['nightbuoy-control',1,community,community,owner.device.id,'f'.repeat(64),'reconstitute',{publisher:forkId,portable:{version:1,primary:forkId},epoch:2,exclude:[],discovery:forkDiscovery,grants:[await c.grant(owner.device,2,resetKey)]}]);const recovery=await prepare(fork,owner,'control',forkControl,{archive});await fork.call('commit',{ticket:recovery.ticket,header:await c.signed(owner,recovery.body)});const forkArchive=await fork.call('sync');assert.equal((await verifyArchive(forkArchive)).events.length,3);await assert.rejects(verifyArchive(forkArchive,{community,tip:verified.checkpoint}),/explicit branch reset/);assert.equal((await fork.call('connection')).branch_pin,await c.hash(forkControl.body));
 backend.offline(false);assert.equal((await cold.call('sync')).order.length,3,'fork must preserve old backend discovery head');
 // A provider rollback cannot silently discard the client's pinned checkpoint.
 const headKey=[...backend.objects.keys()].find(k=>k.endsWith('/'+headName))!;const actual=backend.objects.get(headKey)!;backend.objects.set(headKey,{sha:'rollback',bytes:Buffer.from(initialHead.bytes)});assert.equal((await cold.call('sync')).records.length,3,'a verified replica must defeat primary rollback');assert.equal((await cold.call('replication')).from_replica,true);const backupHeadKey=[...backup.objects.keys()].find(k=>k.endsWith('backup/'+headName))!;const backupActual=backup.objects.get(backupHeadKey)!;backup.objects.set(backupHeadKey,{sha:'old',bytes:backend.objects.get(headKey)!.bytes});await assert.rejects(cold.call('sync'),/rollback|checkpoint|older|missing|does not unlock/);backup.objects.set(backupHeadKey,backupActual);backend.objects.set(headKey,actual);
 let contacted=0;const sink=createServer((_req,res)=>{contacted++;res.end('{}');});await new Promise<void>(r=>sink.listen(0,'127.0.0.1',r));backend.redirect(`http://127.0.0.1:${(sink.address() as any).port}/capture`);try{const isolated=await client(app.origin);await assert.rejects(isolated.call('connect',{connection:{...connection,replicas:[]},access}));assert.equal(contacted,0,'provider redirects must not escape approved origin');}finally{backend.redirect('');await new Promise<void>(r=>sink.close(()=>r()));}
 }finally{await app.stop();await app2.stop();await backend.stop();await backup.stop();}
});

test('public HTTPS behind loopback ingress still requires operator-approved connection pins',async()=>{
 await assert.rejects(promisify(execFile)(bin,['portable'],{env:{PATH:process.env.PATH,NIGHTBUOY_LISTEN:'127.0.0.1:0',NIGHTBUOY_PUBLIC_URL:'https://forum.example.org'},timeout:5000}),/operator-approved connection file/);
});

test('opaque root discovery, capability pins, revocation and cold historical-key backup update',{timeout:90000},async()=>{
 const backend=await fixture('forgejo'),backup=await fixture('forgejo'),app=await launcher(),app2=await launcher();
 try {
  const root=backend.endpoint+'/owner/repo/tree/main/opaque-test';
  const a=await client(app.origin),b=await client(app2.origin);
  for(const status of [401,403,404,503]){backend.deny(status);await assert.rejects(a.call('resolve',{url:root}),status===404?/not found or private/:status===503?/backend request failed/:/denied/);}
  backend.deny(0);
  const resolved=await a.call('resolve',{url:root,provider_token:'synthetic-only-token'});
  const connection=resolved.connection,primary=connection.primary,id=resolved.backend;
  const access={backend:id,token:'synthetic-only-token'};
  await a.call('connect',{connection,access});
  const owner=await c.generate(),member=await c.generate(),first=c.random();
  const genesis=await c.signed(owner,['nightbuoy-genesis',1,owner.device,{name:'Opaque membership',skin:'nightbuoy',identity:'key',admission:'approval',history:true,portable:{version:1,primary:id,discovery:await wrapEpochForMembers([owner.device],first)}},id,[await c.grant(owner.device,1,first)]]);
  await authenticate(a,owner);await publish(a,owner,'genesis',genesis);
  const community=await c.hash(genesis.body),initialConnection=await a.call('connection');
  const replica={...primary,endpoint:backup.endpoint,namespace:'cold-backup',salt:c.b64(c.random())},replicaId=c.b64(Buffer.from(await c.hash(c.canonical(replica)),'hex'));
  await a.call('replica-copy',{backend:replica,access:{backend:replicaId,token:'synthetic-only-token'}});
  const board=await c.encryptEvent(owner,first,[1,community,owner.device.id,community,1,'board',crypto.randomUUID(),'','',1],{title:'Native readable board',description:'Portable terminal fixture'});
  await publish(a,owner,'event',board);
  const latestConnection=await a.call('connection');
  const {accessKey}=await import('../web/src/lib/metadata.ts');
  const privateKey=accessKey(c.b64(first),community,community,latestConnection.checkpoint,primary.namespace);
  const keyPath=join(tmpdir(),'nightbuoy-test-key-'+crypto.randomUUID());
  await writeFile(keyPath,privateKey,{mode:0o600});
  try {
   const native=await promisify(execFile)(bin,['cli','-f',root,'--key-file',keyPath,'--print'],{env:{...process.env,NIGHTBUOY_TESTING:'1'}});
   assert.equal(JSON.parse(native.stdout).content.title,'Native readable board');
   if(process.platform!=='win32'){
    const script=`import os,pty,sys,select,time,fcntl,termios,struct
pid,fd=pty.fork()
if pid==0:
 os.execv(sys.argv[1],[sys.argv[1],'cli','-f',sys.argv[2],'--key-file',sys.argv[3]])
fcntl.ioctl(fd,termios.TIOCSWINSZ,struct.pack('HHHH',30,120,0,0))
out=b'';deadline=time.time()+15;sent=False
try:
 while time.time()<deadline:
  if select.select([fd],[],[],0.1)[0]:
   try: chunk=os.read(fd,65536)
   except OSError: break
   if not chunk: break
   out+=chunk
   if b'\x1b[6n' in chunk: os.write(fd,b'\x1b[1;1R')
   if b'\x1b[?u' in chunk: os.write(fd,b'\x1b[?0u')
   if b'Verified' in out and b'content' in out and not sent: time.sleep(0.2);os.write(fd,b'q');sent=True
  done,status=os.waitpid(pid,os.WNOHANG)
  if done: assert os.waitstatus_to_exitcode(status)==0;break
 else: raise Exception('TUI did not exit: '+repr(out[:2000])+repr(out[-500:]))
 assert sent and b'Native readable board' in out,'TUI did not render verified content'
 print('TUI rendered and exited cleanly')
finally:
 try: os.kill(pid,15)
 except ProcessLookupError: pass
 os.close(fd)`;
    const tui=await promisify(execFile)('python3',['-c',script,bin,root,keyPath],{env:{...process.env,NIGHTBUOY_TESTING:'1'},timeout:20000});
    assert.match(tui.stdout,/TUI rendered and exited cleanly/);
   }
  }finally{await rm(keyPath);}
  if(process.platform!=='win32'){
   const dir=await mkdtemp(join(tmpdir(),'nightbuoy-native-pending-'));const password='PUBLIC synthetic recovery passphrase only';
   try{
    const identityFile=join(dir,'identity.json'),pendingFile=join(dir,'incoming.nbp'),exportFile=join(dir,'exported.nbp');
    await writeFile(identityFile,JSON.stringify(await c.lock(owner,password,community,'p:'+latestConnection.checkpoint)),{mode:0o600});
    const event=await c.encryptEvent(owner,first,[1,community,owner.device.id,community,1,'topic',crypto.randomUUID(),JSON.parse(board.body)[6],'',Date.now()],{title:'Private pending topic',body:'Cross-client pending content',attachments:[{name:'note.txt',size:3,data:'YWJj'}]});
    const packet={hash:await c.hash(event.body),owner:owner.device.id,community,event,wrappedKey:(await c.grant(owner.device,1,first)).key,created:Date.now()};
    await writeFile(pendingFile,await sealPrivate(owner,community,'pending',[packet]),{mode:0o600});
    const checkpointFile=join(dir,'updated-identity.json');await terminalFixture(bin,['cli','-f',root,'-i',identityFile,'--pending-file',pendingFile,'--export-identity',checkpointFile],{passwords:[{prompt:'Identity passphrase',value:password},{prompt:'Recovery export passphrase',value:password},{prompt:'Repeat passphrase',value:password}],actions:[{after:'Verified content',keys:'e'+'\x7f'.repeat('nightbuoy-pending.nbp'.length)+exportFile+'\r'},{file:exportFile,keys:'qq'}]});
    const refreshedVault=JSON.parse(await readFile(checkpointFile,'utf8'));assert.equal(refreshedVault.community,community);assert.equal(refreshedVault.checkpoint,'p:'+latestConnection.checkpoint);assert.equal((await c.unlock(refreshedVault,password)).device.id,owner.device.id);
    const frame=new Uint8Array(await readFile(exportFile));
    for(const value of [owner.device.id,community,'Private pending topic','Cross-client pending content','wrappedKey'])assert.ok(!Buffer.from(frame).includes(Buffer.from(value)));
    const packets=await openPrivate(owner,community,'pending',frame);assert.equal(packets.length,1);assert.equal(packets[0].hash,packet.hash);assert.deepEqual(packets[0].event,event);
    const tokenFile=join(dir,'provider-token');await writeFile(tokenFile,'synthetic-only-token',{mode:0o600});
    await terminalFixture(bin,['cli','-f',root,'-i',identityFile,'--provider-token-file',tokenFile,'--pending-file',pendingFile],{passwords:[{prompt:'Identity passphrase',value:password}],actions:[{after:'Verified content',keys:'v'+'\x04\x04\x13'},{after:'Title:Private pending topic',keys:'q'}]});
    const posts=(await verifyArchive(await a.call('sync'))).events.filter(e=>e.id===JSON.parse(event.body)[6]);assert.equal(posts.length,1);assert.notEqual(posts[0].hash,packet.hash);
    assert.deepEqual((await c.decryptEvent(first,posts[0].signed)).attachments,[{name:'note.txt',size:3,data:'YWJj'}]);
    const queue=[];for(const title of ['Queued A','Queued B']){const event=await c.encryptEvent(owner,first,[1,community,owner.device.id,community,1,'topic',crypto.randomUUID(),JSON.parse(board.body)[6],'',Date.now()],{title,body:'Keep this draft identity'});queue.push({hash:await c.hash(event.body),owner:owner.device.id,community,event,wrappedKey:(await c.grant(owner.device,1,first)).key,created:Date.now()});}
    await writeFile(pendingFile,await sealPrivate(owner,community,'pending',queue));
    await terminalFixture(bin,['cli','-f',root,'-i',identityFile,'--provider-token-file',tokenFile,'--pending-file',pendingFile],{passwords:[{prompt:'Identity passphrase',value:password}],actions:[{after:'Verified content',keys:'v'+'\x04\x04\x13\x04\x04\x13q'}]});
    const verified=await verifyArchive(await a.call('sync')),idA=JSON.parse(queue[0].event.body)[6],idB=JSON.parse(queue[1].event.body)[6];assert.equal(verified.events.filter(e=>e.id===idA).length,1);assert.equal(verified.events.filter(e=>e.id===idB).length,0);assert.equal((await c.decryptEvent(first,verified.events.find(e=>e.id===idA)!.signed)).title,'Queued A');


   }finally{await rm(dir,{recursive:true,force:true});}
  }
  let current=await verifyArchive(await a.call('sync'));
  const admit=await c.signed(owner,['nightbuoy-control',1,community,current.authority,owner.device.id,'a'.repeat(64),'admit',{device:member.device,epoch:1,grants:[await c.grant(member.device,1,first)],discovery:await wrapEpochForMembers([owner.device,member.device],first)}]);
  await publish(a,owner,'control',admit);
  // A root plus authorized identity is sufficient: no profile or metadata key is carried over.
  await b.call('connect',{connection:(await b.call('resolve',{url:root})).connection,access:{backend:id,token:''}});
  await authenticate(b,member);assert.equal((await b.call('sync')).controls.length,1);
  const second=c.random();current=await verifyArchive(await a.call('sync'));
  const revoke=await c.signed(owner,['nightbuoy-control',1,community,current.authority,owner.device.id,'b'.repeat(64),'revoke',{member:member.device.id,epoch:2,grants:[await c.grant(owner.device,2,second)],discovery:await wrapEpochForMembers([owner.device],second)}]);
  await publish(a,owner,'control',revoke);
  const freshBootstrap=await b.call('bootstrap',{});
  await assert.rejects(unwrapEpoch(member,freshBootstrap.ephemeral,freshBootstrap.grants),/No metadata key grant/);
  await assert.rejects(b.call('sync'),/does not unlock/);
  const oldGrant=await c.openGrant(member,(await c.grant(member.device,1,first)).key);assert.equal(c.b64(oldGrant),c.b64(first),'revocation cannot erase already delivered history');oldGrant.fill(0);
  await b.call('logout',{});
  const cold=await client(app2.origin);
  await cold.call('connect',{connection:(await cold.call('resolve',{url:root,provider_token:'synthetic-only-token'})).connection,access});
  await authenticate(cold,owner);
  const updated=await cold.call('connection');assert.equal(updated.primary.salt,primary.salt);
  const epochLocator=await privateLocator(owner,community,'epoch-admission-test');
  const epochFrame=c.b64(await sealPrivate(owner,community,'epoch-admission-test',{synthetic:true}));
  const epochBinding={community,branch:community,member:owner.device.id,locator:epochLocator};
  const beforeEpochDenial=new Map([...backend.objects].map(([k,v])=>[k,v.sha]));
  await assert.rejects(cold.call('private-read',{...epochBinding,epoch:1}),/forum epoch changed/);
  await assert.rejects(cold.call('private-write',{...epochBinding,epoch:1,frame:epochFrame}),/forum epoch changed/);
  assert.deepEqual(new Map([...backend.objects].map(([k,v])=>[k,v.sha])),beforeEpochDenial);
  assert.equal(await cold.call('private-read',{...epochBinding,epoch:2}),null);
  await cold.call('private-write',{...epochBinding,epoch:2,frame:epochFrame});
  assert.equal((await cold.call('private-read',{...epochBinding,epoch:2})).frame,epochFrame);

  await assert.rejects(cold.call('replica-copy',{backend:replica,access:{backend:replicaId,token:'synthetic-only-token'}}),/does not unlock/);
  await cold.call('replica-copy',{backend:replica,access:{backend:replicaId,token:'synthetic-only-token'},metadata_keys:[await metadataKey(first)]});
  const backupReader=await client(app.origin);const backupRoot=backup.endpoint+'/owner/repo/tree/main/cold-backup';
  const backupResolved=await backupReader.call('resolve',{url:backupRoot});
  await backupReader.call('connect',{connection:{...backupResolved.connection,community},access:{backend:backupResolved.backend,token:''}});
  await authenticate(backupReader,owner);
  assert.equal((await backupReader.call('sync')).controls.length,2);
  const adopted=await backupReader.call('connection');assert.equal(adopted.primary.endpoint,backend.endpoint);assert.ok(adopted.replicas.some((r:any)=>r.endpoint===backup.endpoint));
  assert.equal((await backupReader.call('status')).read_only,true);
  // Current-epoch read capability does not confer membership, posting or history-key grants.
  const guest=await client(app2.origin),guestId=await c.generate();
  await guest.call('connect',{connection:await cold.call('connection'),access:{backend:id,token:'synthetic-only-token'},metadata_key:await metadataKey(second)});
  await authenticate(guest,guestId);const archive=await guest.call('sync');assert.equal((await verifyArchive(archive)).view.epoch,2);
  const event=await c.encryptEvent(guestId,second,[1,community,guestId.device.id,(await verifyArchive(archive)).authority,2,'board',crypto.randomUUID(),'','',1],{title:'unauthorized'});
  await assert.rejects(guest.call('prepare',{kind:'event',signed:event,...await prepareMetadata(guestId,'event',event,await verifyArchive(archive),{2:second})}),/unknown author|active member|membership|permission|credential/i);
  // A read capability can preserve an independent encrypted copy, without membership approval.
  const guestBackup={...replica,namespace:'capability-backup',salt:c.b64(c.random())};
  const guestBackupId=c.b64(Buffer.from(await c.hash(c.canonical(guestBackup)),'hex'));
  const primaryBeforeCopy=new Map([...backend.objects].map(([k,v])=>[k,v.sha]));
  const guestArchive=await guest.call('export');assert.ok(c.un64(guestArchive.frame).length>4096);
  await guest.call('replica-copy',{backend:guestBackup,access:{backend:guestBackupId,token:'synthetic-only-token'}});
  assert.equal((await guest.call('replication')).copied,true);
  assert.deepEqual(new Map([...backend.objects].map(([k,v])=>[k,v.sha])),primaryBeforeCopy,'copy must not publish an approval or any primary mutation');
  const copyReader=await client(app2.origin);
  const copyResolved=await copyReader.call('resolve',{url:backup.endpoint+'/owner/repo/tree/main/capability-backup'});
  await copyReader.call('connect',{connection:copyResolved.connection,access:{backend:copyResolved.backend,token:''},metadata_key:await metadataKey(second)});
  await authenticate(copyReader,guestId);
  assert.equal((await verifyArchive(await copyReader.call('sync'))).checkpoint,(await verifyArchive(archive)).checkpoint);
  await guest.call('logout',{});
  for(const route of ['export','replication','replica-copy'])await assert.rejects(guest.call(route,route==='replica-copy'?{backend:guestBackup,access:{backend:guestBackupId,token:'synthetic-only-token'}}:undefined),/sign in|unlock/);
  const exported=await cold.call('export');const {openOpaqueArchive}=await import('../web/src/lib/metadata.ts');
  assert.equal((await verifyArchive(await openOpaqueArchive(owner,c.un64(exported.frame)))).view.epoch,2);
  await assert.rejects(openOpaqueArchive(member,c.un64(exported.frame)),/No metadata key grant/);
  assert.notEqual(initialConnection.checkpoint,updated.checkpoint);
 } finally {await app.stop();await app2.stop();await backend.stop();await backup.stop();}
});
