import * as c from './crypto.ts';
import type {Verified} from './protocol.ts';
import {deriveShared,sealShared,openShared} from './shared-frame.ts';
export const presenceLifetime=90000,maximumPresence=128;
export type Presence={epoch:number;member:string;session:string;publicKey:string;issued:number;expires:number;signed:c.Signed};
export type PresenceSession={nonce:string;publicKey:string;privateKey:CryptoKey};
export type PresencePool={version:1;entries:c.Signed[]};
const hex=(raw:Uint8Array)=>Array.from(raw,b=>b.toString(16).padStart(2,'0')).join('');
export async function presenceSession():Promise<PresenceSession>{const pair=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);return {nonce:hex(c.random()),publicKey:c.b64(await crypto.subtle.exportKey('raw',pair.publicKey)),privateKey:pair.privateKey};}
const scope=(v:Verified)=>[v.community,v.branch,v.view.epoch];
export async function presenceStorage(metadata:string,v:Verified){
 const raw=await deriveShared(metadata,['nightbuoy-presence-key-v1',...scope(v)]),path=await deriveShared(metadata,['nightbuoy-presence-path-v1',...scope(v)]);
 try{return {raw,locator:hex(path),context:c.bytes(c.canonical(['nightbuoy-presence-frame-v1',...scope(v)]))};}finally{path.fill(0);}
}
export async function announcePresence(who:c.Identity,v:Verified,session:PresenceSession,now:number){
 if(v.view.members[who.device.id]?.status!=='active'||!Number.isSafeInteger(now)||now<0||now>Number.MAX_SAFE_INTEGER-presenceLifetime)throw Error('Active membership and valid local clock required.');
 return c.signed(who,['nightbuoy-presence',1,...scope(v),v.authority,who.device.id,session.nonce,session.publicKey,now,now+presenceLifetime]);
}
export async function checkPresence(signed:c.Signed,v:Verified,now:number):Promise<Presence>{
 if(!Number.isSafeInteger(now)||now<0||now>Number.MAX_SAFE_INTEGER-30000||!signed||Object.keys(signed).sort().join(',')!=='body,signature'||typeof signed.body!=='string'||signed.body.length>2000||typeof signed.signature!=='string'||signed.signature.length!==88)throw Error('Invalid presence announcement.');
 const a=JSON.parse(signed.body);if(!Array.isArray(a)||a.length!==11||c.canonical(a)!==signed.body||a[0]!=='nightbuoy-presence'||a[1]!==1||a[2]!==v.community||a[3]!==v.branch||a[4]!==v.view.epoch)throw Error('Presence belongs to another forum, branch or epoch.');
 const member=v.view.members[a[6]],previous=v.views[a[5]]?.members[a[6]];
 if(!member||member.status!=='active'||previous?.status!=='active'||previous.device.sign!==member.device.sign||typeof a[7]!=='string'||!/^[a-f0-9]{64}$/.test(a[7])||typeof a[8]!=='string'||!Number.isSafeInteger(a[9])||!Number.isSafeInteger(a[10])||a[9]<0||a[9]>now+30000||a[10]!==a[9]+presenceLifetime||a[10]<=now)throw Error('Presence is expired or unauthorized.');
 const point=c.un64(a[8]);if(point.length!==65||point[0]!==4)throw Error('Invalid presence key.');await crypto.subtle.importKey('raw',point,{name:'ECDH',namedCurve:'P-256'},false,[]);
 if(!await c.verify(member.device.sign,signed))throw Error('Invalid presence signature.');
 return {epoch:a[4],member:a[6],session:a[7],publicKey:a[8],issued:a[9],expires:a[10],signed};
}
export async function readPresence(value:unknown,v:Verified,now:number):Promise<Presence[]>{
 const pool=value as PresencePool;if(!pool||pool.version!==1||Object.keys(pool).sort().join(',')!=='entries,version'||!Array.isArray(pool.entries)||pool.entries.length>maximumPresence)throw Error('Invalid presence pool.');
 const entries=new Map<string,Presence>();for(const signed of pool.entries){try{const item=await checkPresence(signed,v,now),key=item.member+':'+item.session,old=entries.get(key);if(!old||old.issued<item.issued)entries.set(key,item);}catch{}}
 return [...entries.values()].sort((a,b)=>a.member.localeCompare(b.member)||a.session.localeCompare(b.session));
}
export async function openPresence(metadata:string,v:Verified,frame:Uint8Array<ArrayBuffer>,now:number){const storage=await presenceStorage(metadata,v);try{return await readPresence(await openShared(storage.raw,storage.context,frame),v,now);}finally{storage.raw.fill(0);}}
export async function sealPresence(metadata:string,v:Verified,entries:c.Signed[]){if(entries.length>maximumPresence)throw Error('Recently-active list is full. Try again after entries expire.');const storage=await presenceStorage(metadata,v);try{return await sealShared(storage.raw,storage.context,{version:1,entries});}finally{storage.raw.fill(0);}}
