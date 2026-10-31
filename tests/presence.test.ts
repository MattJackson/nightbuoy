import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import * as c from '../web/src/lib/crypto.ts';
import {verifyArchive} from '../web/src/lib/protocol.ts';
import {presenceSession,presenceStorage,announcePresence,checkPresence,readPresence,openPresence,sealPresence,presenceLifetime,maximumPresence} from '../web/src/lib/presence.ts';
const fixture=JSON.parse(await readFile('crates/server/tests/fixtures/presence.json','utf8'));
const verified=await verifyArchive(fixture.archive);
test('presence vector verifies, conceals all metadata and binds the frame to its scope',async()=>{
 const checked=await checkPresence(fixture.signed,verified,fixture.now);
 assert.equal(checked.member,Object.keys(verified.view.members)[0]);
 const frame=c.un64(fixture.frame),storage=await presenceStorage(fixture.metadata,verified);assert.equal(storage.locator,fixture.locator);storage.raw.fill(0);
 assert.equal((await openPresence(fixture.metadata,verified,frame,fixture.now)).length,1);
 for(const value of ['nightbuoy-presence',checked.member,checked.publicKey,String(checked.expires),verified.community,checked.session])assert.ok(!Buffer.from(frame).includes(Buffer.from(value)));
 for(const offset of [0,1,13,frame.length-1]){const bad=frame.slice();bad[offset]^=1;await assert.rejects(openPresence(fixture.metadata,verified,bad,fixture.now));}
 await assert.rejects(openPresence(c.b64(c.random()),verified,frame,fixture.now));
 for(const scope of [{...verified,community:'b'.repeat(64)},{...verified,branch:'c'.repeat(64)},{...verified,view:{...verified.view,epoch:2}}]){
  assert.notEqual((await presenceStorage(fixture.metadata,scope)).locator,fixture.locator);
  await assert.rejects(checkPresence(fixture.signed,scope,fixture.now));
  await assert.rejects(openPresence(fixture.metadata,scope,frame,fixture.now));
 }
 assert.deepEqual(await readPresence({version:1,entries:[fixture.signed]},verified,fixture.now+presenceLifetime),[]);
});
test('presence is signed, short lived, revocation aware and session ephemeral',async()=>{
 const original=JSON.parse(await readFile('crates/server/tests/fixtures/browser-identity.json','utf8')),who=await c.unlock(original.vault,original.password),session=await presenceSession();
 assert.equal(session.privateKey.extractable,false);await assert.rejects(crypto.subtle.exportKey('jwk',session.privateKey));
 const signed=await announcePresence(who,verified,session,fixture.now);
 assert.equal((await checkPresence(signed,verified,fixture.now)).session,session.nonce);
 assert.notEqual((await presenceSession()).publicKey,session.publicKey);
 const revoked=structuredClone(verified);revoked.view.members[who.device.id].status='revoked';await assert.rejects(checkPresence(signed,revoked,fixture.now));
 for(const [index,value] of [[5,'d'.repeat(64)],[6,'e'.repeat(64)],[7,'bad'],[8,c.b64(c.random(65))],[9,fixture.now+30001],[10,fixture.now+presenceLifetime+1]] as const){const a=JSON.parse(signed.body);a[index]=value;await assert.rejects(checkPresence(await c.signed(who,a),verified,fixture.now));}
 const foreign=await c.generate();await assert.rejects(checkPresence({...signed,signature:(await c.signed(foreign,signed.body)).signature},verified,fixture.now));
 await assert.rejects(checkPresence(signed,verified,Number.NaN));
 const later=await announcePresence(who,verified,session,fixture.now+1000);
 assert.equal((await readPresence({version:1,entries:[signed,later,signed]},verified,fixture.now+1000))[0].issued,fixture.now+1000);
 assert.deepEqual(await readPresence({version:1,entries:[{body:'bad',signature:''},signed]},verified,fixture.now+presenceLifetime),[]);
 await assert.rejects(readPresence({version:1,entries:Array(maximumPresence+1).fill(signed)},verified,fixture.now));
 await assert.rejects(sealPresence(fixture.metadata,verified,Array(maximumPresence+1).fill(signed)));
});
