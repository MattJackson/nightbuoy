import {test} from 'node:test';import assert from 'node:assert/strict';
import * as c from '../web/src/lib/crypto.ts';import {sealPrivate,openPrivate,privateLocator} from '../web/src/lib/private.ts';
test('private exports conceal metadata and bind identity, forum and purpose',async()=>{
 const owner=await c.generate(),other=await c.generate(),community='a'.repeat(64),value={owner:owner.device.id,name:'Private pending metadata',created:123456,body:'Private draft'};
 const frame=await sealPrivate(owner,community,'pending',value);assert.equal(frame[0],3);
 for(const secret of [owner.device.id,value.name,value.body,'created','owner'])assert.ok(!Buffer.from(frame).includes(Buffer.from(secret)));
 assert.deepEqual(await openPrivate(owner,community,'pending',frame),value);
 await assert.rejects(openPrivate(other,community,'pending',frame),/does not unlock/);
 await assert.rejects(openPrivate(owner,'b'.repeat(64),'pending',frame),/does not unlock/);
 await assert.rejects(openPrivate(owner,community,'member-state',frame),/does not unlock/);
 for(const offset of [0,1,13,frame.length-1]){const bad=frame.slice();bad[offset]^=1;await assert.rejects(openPrivate(owner,community,'pending',bad));}
 await assert.rejects(openPrivate(owner,community,'pending',frame.slice(0,-1)),/Invalid private/);
 const locator=await privateLocator(owner,community,'member-state');assert.match(locator,/^[a-f0-9]{64}$/);assert.equal(await privateLocator(owner,community,'member-state'),locator);
 assert.notEqual(await privateLocator(other,community,'member-state'),locator);assert.notEqual(await privateLocator(owner,'b'.repeat(64),'member-state'),locator);assert.notEqual(await privateLocator(owner,community,'pending'),locator);
});

test('pending imports validate routing and content before queueing; aggregate limits preserve exportability',async()=>{
 const {validatePending,assertPendingCapacity,MAX_PENDING_BYTES}=await import('../web/src/lib/outbox.ts');const owner=await c.generate(),community='a'.repeat(64),key=c.random();
 const event=await c.encryptEvent(owner,key,[1,community,owner.device.id,community,1,'reply',crypto.randomUUID(),crypto.randomUUID(),'',1],{body:'Owned pending message'});
 const packet={hash:await c.hash(event.body),owner:owner.device.id,community,event,wrappedKey:(await c.grant(owner.device,1,key)).key,created:1};
 assert.deepEqual(await validatePending(owner,community,packet),packet);
 await assert.rejects(validatePending(owner,'b'.repeat(64),packet),/identity mismatch/);
 const wrongContext=await c.encryptEvent(owner,key,[1,'b'.repeat(64),owner.device.id,community,1,'reply',crypto.randomUUID(),crypto.randomUUID(),'',1],{body:'Wrong forum'});
 await assert.rejects(validatePending(owner,community,{...packet,event:wrongContext,hash:await c.hash(wrongContext.body)}),/context mismatch/);
 assertPendingCapacity([packet]);assert.throws(()=>assertPendingCapacity(Array(101).fill(packet)),/100 items and 16 MiB/);
 assert.throws(()=>assertPendingCapacity([{...packet,event:{...event,body:'x'.repeat(MAX_PENDING_BYTES)}}]),/100 items and 16 MiB/);
});
