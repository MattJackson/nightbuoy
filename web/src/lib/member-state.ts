// Private reading state uses verified ledger positions, never author-supplied clocks.
import type {Event,Verified} from './protocol.ts';
import type {Content} from './content.ts';
export type MemberState={version:1;community:string;branch:string;since:string;visit:string;read:Record<string,string>;watched:string[]};
export const MAX_TRACKED_TOPICS=1000;
function history(v:Verified){
 const roots=new Map<string,Event>(),latest=new Map<string,Event>(),byHash=new Map<string,Event>(),rank=new Map<string,number>([[v.community,-1]]);
 v.archive.order.forEach((hash,index)=>rank.set(hash,index));
 for(const e of v.events){if(!e.previous)roots.set(e.id,e);latest.set(e.id,e);byHash.set(e.hash,e);}
 const topic=(e:Event)=>{const root=roots.get(e.id);return root?.kind==='topic'?root.id:root?.kind==='reply'?root.parent:undefined;};
 return {roots,latest,byHash,rank,topic};
}
export function newMemberState(v:Verified):MemberState{return {version:1,community:v.community,branch:v.branch,since:v.tip,visit:v.tip,read:{},watched:[]};}
export function validateMemberState(raw:unknown,v:Verified):MemberState{
 const fail=():never=>{throw Error('Private reading state does not match this verified forum history.');};
 if(!raw||typeof raw!=='object'||Array.isArray(raw))return fail();const s=raw as MemberState;
 if(Object.keys(s).sort().join(',')!=='branch,community,read,since,version,visit,watched'||s.version!==1||s.community!==v.community||s.branch!==v.branch||typeof s.since!=='string'||typeof s.visit!=='string'||!s.read||typeof s.read!=='object'||Array.isArray(s.read)||!Array.isArray(s.watched)||Object.keys(s.read).length>MAX_TRACKED_TOPICS||s.watched.length>MAX_TRACKED_TOPICS)return fail();
 const h=history(v);if(!h.rank.has(s.since)||!h.rank.has(s.visit)||h.rank.get(s.visit)!<h.rank.get(s.since)!)return fail();
 for(const [id,hash] of Object.entries(s.read)){const e=h.byHash.get(hash);if(!e||h.roots.get(id)?.kind!=='topic'||h.topic(e)!==id)return fail();}
 for(const id of s.watched)if(typeof id!=='string'||h.roots.get(id)?.kind!=='topic')return fail();
 if(new Set(s.watched).size!==s.watched.length)return fail();
 return {...s,read:{...s.read},watched:[...s.watched]};
}
export function toggleWatched(s:MemberState,v:Verified,topic:string):MemberState{
 const h=history(v);if(h.latest.get(topic)?.kind!=='topic')throw Error('Watch an existing live topic.');
 const watched=new Set(s.watched);if(watched.has(topic))watched.delete(topic);else watched.add(topic);
 if(watched.size>MAX_TRACKED_TOPICS)throw Error('At most 1,000 topics can be watched.');return {...s,watched:[...watched].sort()};
}
export function markTopicRead(s:MemberState,v:Verified,contents:Record<string,Content>,topic:string):MemberState{
 const h=history(v);let marker=s.read[topic]||s.since;
 for(const e of v.events)if(h.topic(e)===topic&&contents[e.hash]&&(h.rank.get(e.hash)??-1)>(h.rank.get(marker)??-1))marker=e.hash;
 if(marker===s.since||marker===s.read[topic])return s;
 const read={...s.read,[topic]:marker};if(Object.keys(read).length>MAX_TRACKED_TOPICS)throw Error('Mark all read to compact reading state before tracking more topics.');return {...s,read};
}
export function markAllRead(s:MemberState,v:Verified):MemberState{return {...s,since:v.tip,visit:v.tip,read:{}};}
export function readingSummary(s:MemberState,v:Verified,contents:Record<string,Content>,owner:string){
 const h=history(v),unread:Record<string,number>={},missed={topics:0,replies:0,watched:0,mentions:0};
 const short='@member-'+owner.slice(0,10),full='@'+owner;
 const mentioned=(text:string)=>[short,full].some(token=>{let start=0;for(;;){const i=text.indexOf(token,start);if(i<0)return false;const before=text[i-1]||'',after=text[i+token.length]||'';if(!/[A-Za-z0-9_-]/.test(before)&&!/[A-Za-z0-9_-]/.test(after))return true;start=i+token.length;}});
 for(const e of h.latest.values()){
  if(!['topic','reply'].includes(e.kind)||!contents[e.hash]||e.author===owner)continue;
  const topic=h.topic(e);if(!topic||h.latest.get(topic)?.kind!=='topic')continue;
  const position=h.rank.get(e.hash)!,unseen=position>h.rank.get(s.read[topic]||s.since)!;if(unseen)unread[topic]=(unread[topic]||0)+1;
  const root=h.roots.get(e.id)!;if(unseen&&h.rank.get(root.hash)!>h.rank.get(s.visit)!){if(e.kind==='topic')missed.topics++;else{missed.replies++;if(s.watched.includes(topic))missed.watched++;}}
  if(unseen&&position>h.rank.get(s.visit)!&&mentioned(contents[e.hash].body||''))missed.mentions++;
 }
 return {unread,missed,totalUnread:Object.values(unread).reduce((n,count)=>n+count,0)};
}
