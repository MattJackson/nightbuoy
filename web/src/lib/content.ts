import type {Event} from './protocol';
export type Content={title?:string;body?:string;description?:string;order?:number;attachments?:{name:string;data:string;size:number}[]};
function text(value:unknown,max:number,required=false):string|undefined{if(value===undefined&&!required)return undefined;if(typeof value!=='string'||value.length>max||(required&&!value.trim()))throw Error('Invalid text field.');return value;}
export function validateContent(event:Event,p:unknown):Content{
 if(!p||typeof p!=='object'||Array.isArray(p))throw Error('Invalid content payload.');const v=p as Record<string,unknown>;
 if(event.kind==='delete')return {body:text(v.body,1000)};
 if(event.kind==='board'){const order=v.order??0;if(typeof order!=='number'||!Number.isSafeInteger(order)||Math.abs(order)>100000)throw Error('Invalid board order.');return {title:text(v.title,240,true),description:text(v.description,2000),order};}
 if(!['topic','reply'].includes(event.kind))throw Error('Unknown content type.');
 const title=event.kind==='topic'?text(v.title,240,true):undefined;const body=text(v.body,100000,true);const raw=v.attachments??[];
 if(!Array.isArray(raw)||raw.length>30)throw Error('Invalid attachment list.');let total=0;
 const attachments=raw.map(f=>{if(!f||typeof f!=='object')throw Error('Invalid attachment.');const name=text(f.name,255,true)!;if(typeof f.data!=='string'||f.data.length>4194304||!Number.isSafeInteger(f.size)||f.size<0||f.size>3145728)throw Error('Invalid attachment size.');let decoded:string;try{decoded=atob(f.data);}catch{throw Error('Invalid attachment encoding.');}if(decoded.length!==f.size)throw Error('Attachment size mismatch.');total+=decoded.length;if(total>3145728)throw Error('Attachment limit exceeded.');return {name,data:f.data,size:f.size};});return {title,body,attachments};
}
export function dateLabel(created:number):string{const date=new Date(created);return Number.isFinite(date.getTime())?date.toLocaleString():'Unknown time';}
export function isoDate(created:number):string|undefined{const date=new Date(created);return Number.isFinite(date.getTime())?date.toISOString():undefined;}

export async function openContents(events:Event[],keys:Record<number,Uint8Array<ArrayBuffer>>){
 const {decryptEvent}=await import('./crypto.ts');const contents:Record<string,Content>={};const rejected:{event:Event;reason:string}[]=[];
 for(const event of events){const key=keys[event.epoch];if(!key)continue;try{contents[event.hash]=validateContent(event,await decryptEvent(key,event.signed));}catch{rejected.push({event,reason:'Content could not be authenticated or has an invalid payload.'});}}
 return {contents,rejected};
}
