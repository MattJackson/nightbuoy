import initProof,{verify_consensus} from '../generated-proof/nightbuoy_proof.js';
import {hash,verify,bytes,un64,canonical,type Signed,type Device} from './crypto.ts';
export type Policy={name:string;admission:'automatic'|'approval';history:boolean;identity:'forge'|'key';skin:string;content_version?:1;consensus?:any;portable?:{version:number;primary:string;discovery?:Discovery}};
export type Discovery={ephemeral:string;wrapped:Record<string,string>};
export type Member={device:Device;role:string;status:string;floor:number};
export type View={policy:Policy;epoch:number;members:Record<string,Member>;grants:Record<string,Record<string,string>>;publishers:string[];locked_topics?:string[];discovery?:Discovery};
export type Published={event:Signed;publisher:string;receipt:string};
export type Archive={genesis:Signed;controls:Signed[];records:Published[];order:string[];proof?:any;portable_proof?:{anchor?:Archive;headers:Signed[]}};
export type Verified={checkpoint:string;community:string;branch:string;tip:string;authority:string;view:View;views:Record<string,View>;archive:Archive;events:Event[]};
export type Event={hash:string;author:string;control:string;epoch:number;kind:string;id:string;parent:string;previous:string;created:number;signed:Signed};
function fail(s:string):never{throw Error(s);}
function array(s:Signed,n:number):any[]{const v=JSON.parse(s.body);if(!Array.isArray(v)||v.length!==n||canonical(v)!==s.body)fail('Invalid protocol encoding.');return v;}
function checkPolicy(p:Policy){if(p.content_version!=null&&p.content_version!==1)fail('Unsupported content policy version.');if(p.portable&&(p.portable.version!==1||un64(p.portable.primary).length!==32||p.consensus||p.identity!=='key'))fail('Invalid portable ordering.');if(!['automatic','approval'].includes(p.admission)||!['forge','key'].includes(p.identity)||(typeof p.skin!=='string'||!/^[-a-z0-9]{1,40}$/.test(p.skin))||!p.name||p.name.length>80)fail('Invalid community policy.');}
async function device(d:Device){if(d.discover)await crypto.subtle.importKey('raw',un64(d.discover),{name:'ECDH',namedCurve:'P-256'},false,[]);if(await hash(un64(d.sign))!==d.id||d.wrap.kty!=='RSA'||d.wrap.e!=='AQAB'||d.wrap.n?.length!==512||d.wrap.d)fail('Invalid member public keys.');}
async function discovery(v:View,d:Discovery){if(un64(d.ephemeral).length!==65)fail('Invalid anonymous discovery point.');await crypto.subtle.importKey('raw',un64(d.ephemeral),{name:'ECDH',namedCurve:'P-256'},false,[]);const active=Object.keys(v.members).filter(id=>v.members[id].status==='active').sort();if(canonical(Object.keys(d.wrapped).sort())!==canonical(active)||Object.values(d.wrapped).some(g=>un64(g).length!==60))fail('Invalid signed discovery recipients.');}
function grants(v:View,list:any[]){if(!Array.isArray(list)||list.length>4000)fail('Invalid key grants.');for(const g of list){const m=v.members[g.member];if(!m||m.status!=='active'||g.epoch<m.floor||g.epoch>v.epoch||un64(g.key).length!==384)fail('Invalid key recipient.');v.grants[g.epoch]??={};if(v.grants[g.epoch][g.member]&&v.grants[g.epoch][g.member]!==g.key)fail('Key grant changed.');v.grants[g.epoch][g.member]=g.key;}}
function allKeys(v:View){for(const m of Object.values(v.members))if(m.status==='active'&&!v.grants[v.epoch]?.[m.device.id])fail('Incomplete key rotation.');}
function hasAdmin(v:View){if(!Object.values(v.members).some(m=>m.status==='active'&&m.role==='administrator'))fail('No surviving administrator.');}
export async function verifyArchive(archive:Archive,pin?:{community:string;tip:string}):Promise<Verified>{
 const cert=archive.portable_proof;let sequence=0,parent='',anchorCount=0;
 if(cert?.anchor){if(cert.anchor.portable_proof)fail('Nested migration anchors forbidden.');const old=await verifyArchive(cert.anchor);if(!old.view.policy.consensus||old.view.policy.portable)fail('Invalid migration anchor.');anchorCount=cert.anchor.order.length+1;parent=await hash(canonical({kind:'legacy_anchor',data:cert.anchor}));if(canonical(archive.order.slice(0,anchorCount-1))!==canonical(cert.anchor.order)||canonical(archive.genesis)!==canonical(cert.anchor.genesis)||canonical(archive.controls.slice(0,cert.anchor.controls.length))!==canonical(cert.anchor.controls)||canonical(archive.records.slice(0,cert.anchor.records.length))!==canonical(cert.anchor.records))fail('Migration ancestry changed.');}
 const originalPin=pin?.tip;
 if(originalPin?.startsWith('p:')){let position=-1;for(let i=0;i<(cert?.headers.length||0);i++)if(await hash(canonical(cert!.headers[i]))===originalPin.slice(2))position=i;if(position<0)fail('Signed head fork, rollback or missing checkpoint.');pin={community:pin!.community,tip:JSON.parse(cert!.headers[position].body)[9]};}
 async function append(item:any,key:string,v:View,branch:string){
  const index=sequence++;if(index<anchorCount)return;
  if(!v.policy.portable){if(cert)fail('Portable certificate changed trust mode.');return;}
  const header=cert?.headers[index-anchorCount];if(!header)fail('Portable confirmation pending.');
  const a=JSON.parse(item.data.body??item.data.event.body),actor=item.kind==='genesis'?a[2].id:item.kind==='control'?a[4]:a[2];
  const expected=['nightbuoy-storage-head',1,await hash(archive.genesis.body),branch,v.policy.portable.primary,index,parent,await hash(canonical(item)),item.kind,await hash(item.data.body??item.data.event.body),actor];
  if(header.body!==canonical(expected)||!await verify(key,header))fail('Invalid portable append certificate.');parent=await hash(canonical(header));
 }
 const g=array(archive.genesis,6);if(g[0]!=='nightbuoy-genesis'||g[1]!==1)fail('Unsupported community.');await device(g[2]);if(!await verify(g[2].sign,archive.genesis))fail('Invalid genesis signature.');checkPolicy(g[3]);
 const community=await hash(archive.genesis.body);if(pin?.community&&pin.community!==community)fail('Community fingerprint changed. Refusing to unlock.');
 let tip=community,authority=community;let view:View={policy:g[3],epoch:1,members:{[g[2].id]:{device:g[2],role:'administrator',status:'active',floor:1}},grants:{},publishers:[g[4]],...(g[3].portable?.discovery?{discovery:g[3].portable.discovery}:{})};grants(view,g[5]);allKeys(view);if(view.discovery)await discovery(view,view.discovery);
 if(view.policy.portable&&g[4]!==view.policy.portable.primary)fail('Genesis backend mismatch.');let branch=community;await append({kind:'genesis',data:archive.genesis},g[2].sign,view,branch);
 const views:Record<string,View>={[tip]:view};const events:Event[]=[];const byHash=new Map<string,Event>();
 const controls=new Map<string,Signed>(),records=new Map<string,Published>();
 for(const c of archive.controls)controls.set(await hash(c.body),c);
 for(const r of archive.records)records.set(await hash(r.event.body),r);
 if(controls.size!==archive.controls.length||records.size!==archive.records.length||archive.order.length!==controls.size+records.size||archive.order.length>100000)fail('Invalid chain inventory.');
 const seen=new Set<string>();const prefixControls:Signed[]=[];const prefixRecords:Published[]=[];const prefixOrder:string[]=[];
 for(const id of archive.order){if(seen.has(id))fail('Duplicate chain block.');seen.add(id);
  const c=controls.get(id);
  if(c){const a=array(c,8);if(a[0]!=='nightbuoy-control'||a[1]!==1||a[2]!==community||a[3]!==authority)fail('History diverged or has missing blocks. No merge is possible.');const actor=view.members[a[4]];if(!actor||(actor.role!=='administrator'&&a[6]!=='reconstitute'&&!(actor.role==='moderator'&&a[6]==='thread'))||actor.status!=='active'||!await verify(actor.device.sign,c))fail('Unauthorized governance change.');if(typeof a[5]!=='string'||a[5].length!==64)fail('Invalid control nonce.');const op=a[6],p=a[7];view=structuredClone(view);
   if(op==='reconstitute'){
    if(view.policy.consensus){
     if(!p.checkpoint_proof||(!p.consensus&&!p.portable))fail('A production branch reset requires its old checkpoint proof and new validator trust.');
     await initProof();verify_consensus(JSON.stringify(view.policy.consensus),JSON.stringify(p.checkpoint_proof),await hash(canonical({genesis:archive.genesis,controls:prefixControls,records:prefixRecords,order:prefixOrder})));
    }
    if(view.policy.portable&&!p.portable)fail('Portable branches cannot return to legacy ordering.');
    if((view.policy.consensus||view.policy.portable)&&!p.consensus&&!p.portable)fail('Branch reset cannot remove verified ordering.');
    const pinPosition=pin?.tip===community?-1:archive.order.indexOf(pin?.tip||'');
    if(pin?.tip&&archive.order.indexOf(id)>pinPosition)fail('This history contains an explicit branch reset. Choose this branch before unlocking.');
    if(!Array.isArray(p.exclude)||p.exclude.includes(a[4])||un64(p.publisher).length!==32)fail('Invalid branch reset.');
    for(const m of Object.values(view.members)){m.role=m.device.id===a[4]?'administrator':'member';if(p.exclude.includes(m.device.id))m.status='revoked';}
    if(p.content_version!==undefined){if(p.content_version!==1)fail('Unsupported content policy version.');view.policy.content_version=1;}view.policy.consensus=p.consensus??undefined;view.policy.portable=p.portable??undefined;if(p.portable)view.policy.identity='key';checkPolicy(view.policy);if(p.portable&&p.publisher!==p.portable.primary)fail('Invalid reset backend.');branch=id;view.publishers=[p.publisher];if(p.epoch!==view.epoch+1)fail('Invalid reset epoch.');view.epoch=p.epoch;grants(view,p.grants);allKeys(view);
   }
   else if(op==='policy'){checkPolicy(p);if(canonical(p.consensus??null)!==canonical(view.policy.consensus??null)||canonical(p.portable??null)!==canonical(view.policy.portable??null))fail('Validator trust changes require an explicit branch reset.');if((p.content_version??0)<(view.policy.content_version??0))fail('Content policy cannot be downgraded on this branch.');view.policy=p;}
   else if(op==='admit'){await device(p.device);if(view.members[p.device.id])fail('Duplicate membership.');view.members[p.device.id]={device:p.device,role:'member',status:'active',floor:view.policy.history?1:view.epoch+1};if(!view.policy.history){if(p.epoch!==view.epoch+1)fail('Invalid admission epoch.');view.epoch=p.epoch;}grants(view,p.grants);allKeys(view);}
   else if(op==='role'){const m=view.members[p.member];if(!m||m.status!=='active'||!['member','moderator','administrator'].includes(p.role))fail('Invalid role change.');m.role=p.role;hasAdmin(view);}
   else if(op==='rotate'||op==='revoke'){if(op==='revoke'){const m=view.members[p.member];if(!m||m.status!=='active')fail('Invalid revocation.');m.status='revoked';hasAdmin(view);}if(p.epoch!==view.epoch+1)fail('Invalid epoch.');view.epoch=p.epoch;grants(view,p.grants);allKeys(view);}
   else if(op==='thread'){if(view.policy.content_version!==1)fail('An administrator must enable current moderation tools first.');if(!p||Object.keys(p).length!==2||typeof p.locked!=='boolean'||typeof p.topic!=='string'||events.filter(e=>e.id===p.topic).at(-1)?.kind!=='topic')fail('Thread must be an existing live topic.');view.locked_topics=(view.locked_topics??[]).filter(id=>id!==p.topic);if(p.locked)view.locked_topics.push(p.topic);}
   else if(op==='publisher'){if(un64(p.key).length!==32)fail('Invalid publication key.');view.publishers=view.publishers.filter(k=>k!==p.key);if(p.approved)view.publishers.push(p.key);}
   else fail('Unsupported governance change.');if(['admit','revoke','rotate','reconstitute'].includes(op)){if(p.discovery){await discovery(view,p.discovery);view.discovery=p.discovery;}else if(view.discovery)fail('Signed discovery grants required.');}else if(p.discovery)fail('Unsigned discovery transition.');authority=id;prefixControls.push(c);await append({kind:'control',data:c},actor.device.sign,view,branch);
  }else{
   const r=records.get(id);if(!r)fail('Missing chain block.');const a=array(r.event,12);if(a[0]!==1||a[1]!==community||a[3]!==authority)fail('History diverged or has missing blocks. No merge is possible.');const m=view.members[a[2]];if(!m||m.status!=='active'||!await verify(m.device.sign,r.event))fail('Invalid member event signature.');
   if(!view.publishers.includes(r.publisher))fail('Unapproved publisher.');if(view.policy.portable){if(r.publisher!==view.policy.portable.primary||r.receipt!=='')fail('Wrong write backend.');}else{const pub=await crypto.subtle.importKey('raw',un64(r.publisher),'Ed25519',false,['verify']);if(!await crypto.subtle.verify('Ed25519',pub,un64(r.receipt),bytes(JSON.stringify(['nightbuoy-publication',1,community,id]))))fail('Invalid publication receipt.');}
   if(a[4]!==view.epoch||!view.grants[a[4]]?.[a[2]]||!Number.isSafeInteger(a[9])||a[9]<=0||a[9]>253402300799999||un64(a[10]).length!==12||un64(a[11]).length<16||typeof a[6]!=='string'||!/^[-0-9a-f]{36}$/i.test(a[6]))fail('Invalid event context.');
   const e:Event={hash:id,author:a[2],control:a[3],epoch:a[4],kind:a[5],id:a[6],parent:a[7],previous:a[8],created:a[9],signed:r.event};
   const root=events.find(x=>x.id===e.id&&!x.previous);const role=m.role;
   if(root){const latest=events.filter(x=>x.id===e.id).at(-1);if(e.previous!==latest?.hash)fail('Stale object revision.');const prior=byHash.get(e.previous);if(!prior||prior.id!==e.id||prior.kind==='delete'||e.parent!==root.parent||(e.kind!==root.kind&&e.kind!=='delete')||(root.author!==e.author&&!['administrator','moderator'].includes(role)))fail('Unauthorized edit.');if(root.kind==='board'&&role!=='administrator')fail('Unauthorized board edit.');}
   else{if(e.previous)fail('Missing object root.');if(e.kind==='board'){if(e.parent||role!=='administrator')fail('Unauthorized board creation.');}else if(e.kind==='topic'||e.kind==='reply'){if(!events.some(x=>x.id===e.parent&&x.kind===(e.kind==='topic'?'board':'topic')))fail('Missing parent.');}else fail('Unknown object type.');}
   const parentError=parentProblem(events,view.policy.content_version,e.kind,e.parent);if(parentError)fail(parentError);
   const topic=e.kind==='topic'?e.id:e.kind==='reply'?e.parent:'';if(e.kind!=='delete'&&view.locked_topics?.includes(topic)&&!['administrator','moderator'].includes(role))fail('Thread is locked; a moderator must unlock it before members can post or edit.');
   events.push(e);byHash.set(id,e);prefixRecords.push(r);await append({kind:'event',data:r},m.device.sign,view,branch);
  }
  tip=id;views[tip]=view;prefixOrder.push(id);
 }
 if(pin?.tip&&!views[pin.tip])fail('Replica diverged or is older than your verified checkpoint. Choose a branch explicitly.');
 if(view.policy.consensus){
  if(!archive.proof)fail('Consensus confirmation is still pending.');
  const core={genesis:archive.genesis,controls:archive.controls,records:archive.records,order:archive.order};
  await initProof();verify_consensus(JSON.stringify(view.policy.consensus),JSON.stringify(archive.proof),await hash(canonical(core)));
 }
 if(cert&&(!view.policy.portable||cert.headers.length!==sequence-anchorCount))fail('Invalid portable certificate inventory.');if(view.policy.portable&&view.policy.consensus)fail('Mixed ordering modes.');
 return {checkpoint:view.policy.portable?'p:'+parent:tip,community,branch,tip,authority,view,views,events,archive};
}
export function parentProblem(events:Event[],version:number|undefined,kind:string,parent:string):string|undefined{if(version!==1||!['topic','reply'].includes(kind))return;const expected=kind==='topic'?'board':'topic',p=events.filter(e=>e.id===parent).at(-1);if(p?.kind!==expected)return 'Parent was removed.';if(kind==='reply'&&events.filter(e=>e.id===p!.parent).at(-1)?.kind!=='board')return 'Parent board was removed.';}
export function heads(events:Event[],id:string):Event[]{const revisions=events.filter(e=>e.id===id);const parents=new Set(revisions.map(e=>e.previous));return revisions.filter(e=>!parents.has(e.hash)).sort((a,b)=>a.hash.localeCompare(b.hash));}
