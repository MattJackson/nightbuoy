// Explicit opt-in: temporary branch, synthetic identities/data, no writes to the default branch.
import {execFile,spawn} from 'node:child_process';
import {promisify} from 'node:util';
import {createServer} from 'node:net';
import {resolve} from 'node:path';
import assert from 'node:assert/strict';
import * as c from '../web/src/lib/crypto.ts';
import {prepareMetadata,metadataKey,wrapEpochForMembers} from '../web/src/lib/metadata.ts';
import {verifyArchive} from '../web/src/lib/protocol.ts';

const [flag,owner,repo]=process.argv.slice(2);
if(flag!=='--allow-temporary-branch'||!owner||!repo||![owner,repo].every(v=>/^[A-Za-z0-9_.-]+$/.test(v)))
 throw Error('Usage: node --experimental-strip-types scripts/live-github-acceptance.mjs --allow-temporary-branch OWNER REPO');
const exec=promisify(execFile),branch='nightbuoy-acceptance-'+crypto.randomUUID();
let created=false,child;
async function gh(args){return (await exec('gh',args,{maxBuffer:4*1024*1024})).stdout;}
try{
 const base=JSON.parse(await gh(['api',`repos/${owner}/${repo}`])).default_branch;
 const sha=JSON.parse(await gh(['api',`repos/${owner}/${repo}/git/ref/heads/${base}`])).object.sha;
 await gh(['api',`repos/${owner}/${repo}/git/refs`,'-f',`ref=refs/heads/${branch}`,'-f',`sha=${sha}`]);created=true;
 const token=(await gh(['auth','token'])).trim(); // Memory only; never an argv or an output.
 const server=createServer();await new Promise(r=>server.listen(0,'127.0.0.1',r));
 const port=server.address().port;await new Promise(r=>server.close(r));const origin=`http://127.0.0.1:${port}`;
 child=spawn(resolve('target/debug/nightbuoy'),['portable'],{env:{PATH:process.env.PATH,NIGHTBUOY_LISTEN:`127.0.0.1:${port}`,NIGHTBUOY_PUBLIC_URL:origin},stdio:'ignore'});
 let ready=false;for(let i=0;i<100;i++){try{if((await fetch(origin)).ok){ready=true;break;}}catch{}await new Promise(r=>setTimeout(r,50));}
 assert.ok(ready,'synthetic companion did not start');
 async function session(){
  const r=await fetch(origin+'/api/session',{method:'POST',headers:{Origin:origin,'x-nightbuoy-bootstrap':'1'}});
  const csrf=(await r.json()).csrf,cookie=r.headers.get('set-cookie').split(';')[0];
  return async(path,data)=>{
   const r=await fetch(origin+'/api/'+path,{method:data===undefined?'GET':'POST',headers:{Origin:origin,Cookie:cookie,'x-nightbuoy-csrf':csrf,'Content-Type':'application/json'},...(data===undefined?{}:{body:JSON.stringify(data)})});
   const value=await r.json();if(!r.ok)throw Error(value.error||r.status);return value;
  };
 }
 const a=await session(),b=await session();
 const primary={kind:'github',endpoint:'https://api.github.com',namespace:'synthetic-'+crypto.randomUUID(),salt:c.b64(c.random()),owner,repository:repo,branch,bucket:'',region:'us-east-1'};
 const id=c.b64(Buffer.from(await c.hash(c.canonical(primary)),'hex'));
 const connection={version:2,primary,replicas:[],community:''},access={backend:id,token};
 await a('connect',{connection,access});
 const identity=await c.generate(),key=c.random();
 async function login(call,existing=false){
  if(existing)await call('metadata',{key:await metadataKey(key)});
  const p=await call('challenge',{device:identity.device});await call('login',{signed:await c.signed(identity,p.body)});
 }
 async function prepare(call,kind,signed){
  const v=kind==='genesis'?null:await verifyArchive(await call('sync'));
  return call('prepare',{kind,signed,...await prepareMetadata(identity,kind,signed,v,kind==='genesis'?{}:{1:key})});
 }
 async function commit(call,p){return call('commit',{ticket:p.ticket,header:await c.signed(identity,p.body)});}
 await login(a);
 const discovery=await wrapEpochForMembers([identity.device],key);
 const genesis=await c.signed(identity,['nightbuoy-genesis',1,identity.device,{name:'Synthetic opaque acceptance',skin:'nightbuoy',admission:'approval',history:true,identity:'key',content_version:1,portable:{version:1,primary:id,discovery}},id,[await c.grant(identity.device,1,key)]]);
 await commit(a,await prepare(a,'genesis',genesis));
 await b('connect',{connection:await a('connection'),access});await login(b,true);
 const community=await c.hash(genesis.body),board=crypto.randomUUID();
 const event=await c.encryptEvent(identity,key,[1,community,identity.device.id,community,1,'board',board,'','',1],{title:'Synthetic board',description:'Encrypted test data'});
 await commit(a,await prepare(a,'event',event));
 // A bounded synthetic attachment pushes ciphertext/snapshots above GitHub's inline-content limit.
 const attachment=Buffer.alloc(900*1024,37);
 const events=await Promise.all(['A','B'].map(title=>c.encryptEvent(identity,key,[1,community,identity.device.id,community,1,'topic',crypto.randomUUID(),board,'',2],{title,body:'Synthetic concurrent post',...(title==='A'?{attachments:[{name:'synthetic.bin',size:attachment.length,data:attachment.toString('base64')}]}:{})})));
 const plans=await Promise.all([prepare(a,'event',events[0]),prepare(b,'event',events[1])]);
 const race=await Promise.allSettled([commit(a,plans[0]),commit(b,plans[1])]);
 assert.equal(race.filter(r=>r.status==='fulfilled').length,1,'live CAS must produce exactly one winner');
 const loser=race[0].status==='rejected'?0:1,call=loser===0?a:b;
 await commit(call,await prepare(call,'event',events[loser]));
 const v=await verifyArchive(await a('sync'));assert.equal(v.events.length,3);
 const large=v.events.find(e=>e.signed.body===events[0].body);assert.ok(large);
 const plaintext=await c.decryptEvent(key,large.signed);assert.equal(plaintext.attachments[0].data,attachment.toString('base64'));
 // Cold session reads the large remote snapshot instead of using the publisher's RAM cache.
 await b('logout',{});const cold=await session();await cold('connect',{connection:await a('connection'),access});await login(cold,true);
 assert.equal((await verifyArchive(await cold('sync'))).events.length,3);
 // Inspect only commits generated on this temporary branch, not inherited history.
 const commits=JSON.parse(await gh(['api',`repos/${owner}/${repo}/compare/${sha}...${branch}`])).commits;
 assert.ok(commits.length>0,'no generated commits to inspect');
 for(const entry of commits)for(const field of ['author','committer']){
  assert.equal(entry.commit[field].name,'NightBuoy');
  assert.equal(entry.commit[field].email,'storage@nightbuoy.invalid');
 }
 console.log('Live GitHub passed: opaque v2 create/post, >1 MiB encrypted objects, cold read, conditional race, loser retry and generic Git attribution.');
 key.fill(0);
}finally{
 if(child&&child.exitCode===null){child.kill('SIGINT');await new Promise(r=>child.once('exit',r));}
 if(created){await gh(['api','-X','DELETE',`repos/${owner}/${repo}/git/refs/heads/${branch}`]);console.log('Temporary acceptance branch removed.');}
}
