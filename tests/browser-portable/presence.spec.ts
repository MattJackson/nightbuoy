import {test,expect} from '@playwright/test';
import {mkdtemp,readFile,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import * as c from '../../web/src/lib/crypto.ts';
import {verifyArchive} from '../../web/src/lib/protocol.ts';
import {presenceStorage,openPresence} from '../../web/src/lib/presence.ts';
import {terminalFixture} from '../terminal-fixture.ts';
test('presence is invisible by default and interoperates between GUI and terminal',async({page})=>{
 const dir=await mkdtemp(join(tmpdir(),'nightbuoy-presence-ui-')),stop=join(dir,'exit-native');let native:Promise<unknown>|undefined;
 try{
  const password='PUBLIC synthetic presence test passphrase',downloads:any[]=[];
  page.on('dialog',d=>d.accept());page.on('download',d=>downloads.push(d));
  await page.goto('/');await page.getByLabel('Storage URL',{exact:true}).fill('http://127.0.0.1:4120/owner/repo/tree/main/presence');await page.getByLabel('Access key (optional)',{exact:true}).fill('deadbeef'.repeat(5));await page.getByRole('button',{name:'Join',exact:true}).click();
  await page.getByLabel('Community name').fill('Presence interoperability');await page.getByLabel('Unique passphrase',{exact:true}).fill(password);await page.getByLabel('Repeat passphrase',{exact:true}).fill(password);await page.getByRole('button',{name:'Create community & download recovery file'}).click();
  await expect(page.getByRole('button',{name:'New board',exact:true})).toBeEnabled();await expect.poll(()=>downloads.length).toBeGreaterThanOrEqual(3);
  const vaults=[];for(let i=0;i<downloads.length;i++){const path=join(dir,'download-'+i);await downloads[i].saveAs(path);const value=JSON.parse(await readFile(path,'utf8'));if(value.cipher)vaults.push(value);}
  const vault=vaults.at(-1),who=await c.unlock(vault,password);
  async function call(path:string,body:unknown={}){return page.evaluate(async({path,body})=>{const bootstrap=await fetch('/api/session',{method:'POST',headers:{'x-nightbuoy-bootstrap':'1'}}),{csrf}=await bootstrap.json(),response=await fetch('/api/'+path,{method:'POST',headers:{'Content-Type':'application/json','x-nightbuoy-csrf':csrf},body:JSON.stringify(body)});const value=await response.json();if(!response.ok)throw Error(value.error);return value;},{path,body});}
  const verified=await verifyArchive(await call('sync')),metadata=who.access!.metadata,storage=await presenceStorage(metadata,verified);storage.raw.fill(0);
  const binding={community:verified.community,branch:verified.branch,member:who.device.id,locator:storage.locator};
  expect(await call('private-read',binding)).toBeNull();
  const activity=page.locator('details[aria-label="Member activity"]');await activity.locator('summary').click();
  const toggle=activity.getByRole('checkbox',{name:'Share my recent activity with forum readers'});await expect(toggle).not.toBeChecked();await toggle.check();
  await expect.poll(async()=>{const value=await call('private-read',binding);return value? (await openPresence(metadata,verified,c.un64(value.frame),Date.now())).length:0;}).toBe(1);
  const first=await call('private-read',binding);for(const text of [who.device.id,verified.community,'nightbuoy-presence'])expect(Buffer.from(c.un64(first.frame)).includes(Buffer.from(text))).toBe(false);
  if(process.platform!=='win32'){
   const identity=join(dir,'identity.json'),token=join(dir,'token');await writeFile(identity,JSON.stringify(vault),{mode:0o600});await writeFile(token,'synthetic-only-token',{mode:0o600});
   native=terminalFixture(resolve('target/debug/nightbuoy'),['cli','-f','http://127.0.0.1:4120/owner/repo/tree/main/presence','-i',identity,'--provider-token-file',token],{passwords:[{prompt:'Identity passphrase',value:password}],actions:[{after:'Verified content',keys:'oo'},{file:stop,keys:'qq'}]});
   // Avoid an unhandled rejection while Playwright waits for the live second client.
   void native.catch(()=>{});
   await expect.poll(async()=>{const value=await call('private-read',binding);return (await openPresence(metadata,verified,c.un64(value.frame),Date.now())).length;},{timeout:25000}).toBe(2);
   await activity.getByRole('button',{name:'Refresh recent activity'}).click();await expect(activity.getByRole('listitem')).toHaveCount(2);
   await writeFile(stop,'exit');await native;native=undefined;
   await expect.poll(async()=>{const value=await call('private-read',binding);return (await openPresence(metadata,verified,c.un64(value.frame),Date.now())).length;}).toBe(1);
  }
  await toggle.uncheck();await expect.poll(async()=>{const value=await call('private-read',binding);return (await openPresence(metadata,verified,c.un64(value.frame),Date.now())).length;}).toBe(0);
  expect((await call('sync')).order).toHaveLength(0);
 }finally{await writeFile(stop,'exit');if(native)await native.catch(()=>{});await rm(dir,{recursive:true,force:true});}
});
