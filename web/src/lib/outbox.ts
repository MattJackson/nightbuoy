import type {Signed} from './crypto';
export type Pending={hash:string;owner:string;community:string;event:Signed;wrappedKey:string;created:number};
export const MAX_PENDING_ITEMS=100,MAX_PENDING_BYTES=16*1024*1024;
export function assertPendingCapacity(items:Pending[]){if(items.length>MAX_PENDING_ITEMS||new TextEncoder().encode(JSON.stringify(items)).length>MAX_PENDING_BYTES)throw Error('Pending submissions are limited to 100 items and 16 MiB. Export, retry or discard saved submissions before adding more.');}
function database():Promise<IDBDatabase>{return new Promise((resolve,reject)=>{const request=indexedDB.open('nightbuoy-outbox',1);request.onupgradeneeded=()=>{const store=request.result.createObjectStore('pending',{keyPath:'hash'});store.createIndex('owner','owner');};request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(Error('Encrypted pending storage is unavailable. Export or retry before closing this browser.'));});}
async function transaction<T>(mode:IDBTransactionMode,operation:(store:IDBObjectStore)=>IDBRequest<T>):Promise<T>{const db=await database();return new Promise((resolve,reject)=>{const tx=db.transaction('pending',mode);const request=operation(tx.objectStore('pending'));let result:T;request.onsuccess=()=>{result=request.result;};tx.oncomplete=()=>{db.close();resolve(result);};tx.onerror=()=>{db.close();reject(Error('The encrypted pending draft could not be saved.'));};tx.onabort=tx.onerror;});}
export async function savePending(p:Pending){await transaction('readwrite',s=>s.put(p));}
export async function removePending(hash:string){await transaction('readwrite',s=>s.delete(hash));}
export async function listPending(owner:string,community:string):Promise<Pending[]>{return (await transaction<Pending[]>('readonly',s=>s.index('owner').getAll(owner))).filter(p=>p.community===community).sort((a,b)=>a.created-b.created);}

export async function validatePending(identity:import('./crypto').Identity,community:string,value:unknown):Promise<Pending>{
 const c=await import('./crypto.ts'),{validateContent}=await import('./content.ts');
 if(!value||typeof value!=='object'||Array.isArray(value))throw Error('Invalid pending submission.');
 const p=value as Pending;
 if(p.owner!==identity.device.id||p.community!==community||typeof p.hash!=='string'||typeof p.event?.body!=='string'||p.event.body.length>8_000_000||typeof p.event?.signature!=='string'||typeof p.wrappedKey!=='string'||p.wrappedKey.length!==512||!Number.isSafeInteger(p.created)||p.created<=0||p.created>253402300799999||await c.hash(p.event.body)!==p.hash||!await c.verify(identity.device.sign,p.event))throw Error('Pending submission identity mismatch.');
 const a=JSON.parse(p.event.body);
 if(!Array.isArray(a)||a.length!==12||a[0]!==1||a[1]!==community||a[2]!==identity.device.id)throw Error('Pending submission context mismatch.');
 const key=await c.openGrant(identity,p.wrappedKey);
 try{validateContent({kind:a[5]} as import('./protocol').Event,await c.decryptEvent(key,p.event));}finally{key.fill(0);}
 return {hash:p.hash,owner:p.owner,community:p.community,event:{body:p.event.body,signature:p.event.signature},wrappedKey:p.wrappedKey,created:p.created};
}
