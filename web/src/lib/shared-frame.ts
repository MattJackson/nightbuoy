// Bounded padded frames for explicitly shared, off-ledger client state.
import * as c from './crypto.ts';
const block=4096,maximum=256*1024;
export async function deriveShared(metadata:string,domain:unknown):Promise<Uint8Array<ArrayBuffer>>{
 const raw=c.un64(metadata);if(raw.length!==32)throw Error('Invalid shared metadata key.');
 try{const key=await crypto.subtle.importKey('raw',raw,{name:'HMAC',hash:'SHA-256'},false,['sign']);return new Uint8Array(await crypto.subtle.sign('HMAC',key,c.bytes(c.canonical(domain))));}finally{raw.fill(0);}
}
export async function sealShared(raw:Uint8Array<ArrayBuffer>,context:Uint8Array<ArrayBuffer>,value:unknown){
 if(raw.length!==32)throw Error('Shared frames require a 256-bit key.');
 const json=c.bytes(c.canonical(value));if(json.length>192*1024)throw Error('Shared state exceeds capacity.');
 const plain=new Uint8Array(Math.ceil((json.length+4)/block)*block);new DataView(plain.buffer).setUint32(0,json.length,false);plain.set(json,4);plain.set(c.random(plain.length-json.length-4),json.length+4);
 try{const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['encrypt']),iv=c.random(12),cipher=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:context},key,plain)),frame=new Uint8Array(13+cipher.length);frame[0]=3;frame.set(iv,1);frame.set(cipher,13);return frame;}finally{plain.fill(0);json.fill(0);}
}
export async function openShared(raw:Uint8Array<ArrayBuffer>,context:Uint8Array<ArrayBuffer>,frame:Uint8Array<ArrayBuffer>):Promise<unknown>{
 if(raw.length!==32)throw Error('Shared frames require a 256-bit key.');
 if(frame[0]!==3||frame.length<4125||frame.length>maximum||(frame.length-29)%block)throw Error('Invalid shared state frame.');
 const key=await crypto.subtle.importKey('raw',raw,'AES-GCM',false,['decrypt']);let plain:Uint8Array<ArrayBuffer>;
 try{plain=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:frame.slice(1,13),additionalData:context},key,frame.slice(13)));}catch{throw Error('Shared state authentication failed.');}
 try{const size=new DataView(plain.buffer).getUint32(0,false);if(size>192*1024||size>plain.length-4)throw Error('Invalid shared state length.');return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(plain.slice(4,4+size)));}finally{plain.fill(0);}
}
