// Member-owned exports. Neither other forum members nor forum epoch keys unlock them.
import * as c from './crypto.ts';
const maximum=64*1024*1024,frameMaximum=66*1024*1024+1,block=4096;
async function privateKey(identity:c.Identity,community:string,purpose:string){
 const context=c.bytes(JSON.stringify(['nightbuoy-private-v1',purpose,community]));
 const d=c.un64(identity.privateSign.d!.replace(/-/g,'+').replace(/_/g,'/'));
 try{const material=await crypto.subtle.importKey('raw',d,{name:'HMAC',hash:'SHA-256'},false,['sign']);const raw=new Uint8Array(await crypto.subtle.sign('HMAC',material,context));try{return {context,key:await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt','decrypt'])};}finally{raw.fill(0);}}finally{d.fill(0);}
}
export async function sealPrivate(identity:c.Identity,community:string,purpose:string,value:unknown):Promise<Uint8Array<ArrayBuffer>>{
 const {key,context}=await privateKey(identity,community,purpose),json=c.bytes(JSON.stringify(value));
 if(json.length>maximum)throw Error('Private export exceeds the size limit.');
 const plain=new Uint8Array(Math.ceil((json.length+4)/block)*block);
 new DataView(plain.buffer).setUint32(0,json.length,false);plain.set(json,4);const pad=plain.length-json.length-4;if(pad)plain.set(c.random(pad),json.length+4);
 const iv=c.random(12);try{const cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:context},key,plain));const frame=new Uint8Array(13+cipher.length);frame[0]=3;frame.set(iv,1);frame.set(cipher,13);return frame;}finally{plain.fill(0);json.fill(0);}
}
export async function openPrivate(identity:c.Identity,community:string,purpose:string,frame:Uint8Array<ArrayBuffer>):Promise<any>{
 if(frame.length<4125||frame.length>frameMaximum||frame[0]!==3||(frame.length-29)%block)throw Error('Invalid private export frame.');
 const {key,context}=await privateKey(identity,community,purpose);
 let plain:Uint8Array<ArrayBuffer>;try{plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:frame.slice(1,13),additionalData:context},key,frame.slice(13)));}catch{throw Error('This private export does not unlock for this identity, forum and purpose.');}
 try{const size=new DataView(plain.buffer).getUint32(0,false);if(size>maximum||size>plain.length-4)throw Error('Invalid private export size.');return JSON.parse(new TextDecoder().decode(plain.slice(4,4+size)));}finally{plain.fill(0);}
}
