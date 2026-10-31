import {test} from 'node:test';import assert from 'node:assert/strict';
import type {Event,Verified} from '../web/src/lib/protocol.ts';
import {newMemberState,validateMemberState,toggleWatched,markTopicRead,markAllRead,readingSummary} from '../web/src/lib/member-state.ts';
import {readFile} from 'node:fs/promises';
const community='a'.repeat(64),owner='b'.repeat(64),other='c'.repeat(64),board='00000000-0000-0000-0000-000000000001',topic='00000000-0000-0000-0000-000000000002',reply='00000000-0000-0000-0000-000000000003',second='00000000-0000-0000-0000-000000000004';
function event(n:number,kind:string,id:string,parent='',previous='',author=other):Event{return {hash:n.toString(16).padStart(64,'0'),kind,id,parent,previous,author,control:community,epoch:1,created:n%2?253402300799999:1,signed:{body:'synthetic unused body',signature:'synthetic unused signature'}};}
function verified(events:Event[]):Verified{return {community,branch:community,tip:events.at(-1)?.hash||community,events,archive:{order:events.map(e=>e.hash)}} as Verified;}
test('unread and catch-up follow signed order, ignore author clocks and retain read positions',()=>{
 const a=event(1,'board',board),b=event(2,'topic',topic,board),first=verified([a,b]);let state=toggleWatched(newMemberState(first),first,topic);
 const c=event(3,'reply',reply,topic),d=event(4,'topic',second,board),v=verified([a,b,c,d]),contents={[b.hash]:{body:'Original'},[c.hash]:{body:'Hi @member-'+owner.slice(0,10)},[d.hash]:{body:'Other topic'}};
 const summary=readingSummary(state,v,contents,owner);assert.deepEqual(summary.unread,{[topic]:1,[second]:1});assert.deepEqual(summary.missed,{topics:1,replies:1,watched:1,mentions:1});
 state=markTopicRead(state,v,contents,topic);assert.equal(readingSummary(state,v,contents,owner).unread[topic],undefined);assert.equal(readingSummary(state,v,contents,owner).unread[second],1);assert.equal(readingSummary(state,v,contents,owner).missed.replies,0);assert.equal(readingSummary(state,v,contents,owner).missed.mentions,0);
 assert.deepEqual(validateMemberState(state,v),state);state=markAllRead(state,v);assert.equal(readingSummary(state,v,contents,owner).totalUnread,0);assert.deepEqual(state.watched,[topic]);
});
test('private reading markers reject foreign branches, unknown history and transplanted topic cursors',()=>{
 const a=event(1,'board',board),b=event(2,'topic',topic,board),c=event(3,'topic',second,board),v=verified([a,b,c]),state=newMemberState(v);
 for(const bad of [{...state,branch:'d'.repeat(64)},{...state,community:'e'.repeat(64)},{...state,visit:'f'.repeat(64)},{...state,read:{[topic]:c.hash}},{...state,watched:[topic,topic]},{...state,extra:'plaintext metadata'}])assert.throws(()=>validateMemberState(bad,v),/does not match/);
 assert.throws(()=>validateMemberState({...state,since:c.hash,visit:b.hash},v),/does not match/);
 assert.throws(()=>toggleWatched(state,v,board),/live topic/);
});
test('deleted content, own posts and unavailable plaintext do not produce notifications',()=>{
 const a=event(1,'board',board),b=event(2,'topic',topic,board),base=verified([a,b]),state=newMemberState(base),c=event(3,'reply',reply,topic,'',owner),d=event(4,'reply',second,topic),deleted=event(5,'delete',second,topic,d.hash),v=verified([a,b,c,d,deleted]);
 const contents={[b.hash]:{body:'base'},[c.hash]:{body:'own reply'},[d.hash]:{body:'removed reply'},[deleted.hash]:{body:'Removed'}};assert.equal(readingSummary(state,v,contents,owner).totalUnread,0);
 const hidden=verified([a,b,c,d]);assert.equal(readingSummary(state,hidden,{[b.hash]:contents[b.hash],[c.hash]:contents[c.hash]},owner).missed.replies,0);
});
test('the shared native/browser reading projection vector remains compatible',async()=>{
 const f=JSON.parse(await readFile(new URL('../crates/server/tests/fixtures/member-state.json',import.meta.url),'utf8'));
 const v={community:f.state.community,branch:f.state.branch,tip:f.data.tip,archive:f.data.archive,events:f.data.events} as Verified;
 assert.deepEqual(readingSummary(validateMemberState(f.state,v),v,f.contents,f.owner),f.expected);
});
