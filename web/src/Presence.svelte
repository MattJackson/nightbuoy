<script lang="ts">
 import {onMount} from 'svelte';
 import {api,ApiError} from './lib/api';
 import * as c from './lib/crypto';
 import {metadataKey} from './lib/metadata';
 import type {Verified} from './lib/protocol';
 import {presenceSession,presenceStorage,announcePresence,checkPresence,openPresence,sealPresence,maximumPresence,type PresenceSession,type Presence as Announcement} from './lib/presence';
 let {identity,verified,epochKey,canShare,expired}:{identity:c.Identity;verified:Verified;epochKey:Uint8Array<ArrayBuffer>|undefined;canShare:boolean;expired:()=>void}=$props();
 let session:PresenceSession|null=$state(null),entries:Announcement[]=$state([]),busy=$state(false),warning=$state(''),now=$state(Date.now());
 let alive=true,generation=0,lastRenew=0,current=Promise.resolve();
 const active=$derived(entries.filter(p=>p.expires>now&&p.epoch===verified.view.epoch&&verified.view.members[p.member]?.status==='active'));
 async function perform(enabled?:boolean){
  const withdraw=enabled===false?session?.nonce:undefined;
  if(enabled===false){session=null;generation++;}
  if(busy&&enabled!==false)return;
  while(busy)await current;
  if(!alive)return;
  busy=true;let settle!:()=>void;current=new Promise<void>(resolve=>settle=resolve);
  const owner=identity,v=verified,epoch=epochKey?.slice(),token=generation;
  const valid=()=>alive&&generation===token&&identity===owner&&verified.community===v.community&&verified.branch===v.branch&&verified.view.epoch===v.view.epoch;
  warning='';lastRenew=Date.now();
  try{
   if(!epoch)throw Error('Unlock the current forum key first.');
   const metadata=await metadataKey(epoch);epoch.fill(0);if(!valid())return;
   if(enabled===true&&!session){const candidate=await presenceSession();if(!valid())return;session=candidate;}
   const storage=await presenceStorage(metadata,v);storage.raw.fill(0);if(!valid())return;
   const binding={community:v.community,branch:v.branch,epoch:v.view.epoch,member:owner.device.id,locator:storage.locator};
   for(let attempt=0;attempt<2;attempt++){
    const stored=await api('/api/private-read',binding);if(!valid())return;
    const time=Date.now();let found=stored?await openPresence(metadata,v,c.un64(stored.frame),time):[];if(!valid())return;
    if(enabled===undefined){entries=found;return;}
    const nonce=enabled?session?.nonce:withdraw;
    found=found.filter(p=>p.member!==owner.device.id||p.session!==nonce);
    if(enabled&&session){const signed=await announcePresence(owner,v,session,time);found.push(await checkPresence(signed,v,time));}
    if(found.length>maximumPresence)throw Error('Recently-active list is full. Try again after entries expire.');
    const frame=await sealPresence(metadata,v,found.map(p=>p.signed));if(!valid())return;
    try{await api('/api/private-write',{...binding,frame:c.b64(frame),version:stored?.version||null});if(valid())entries=found;return;}
    catch(e){if(e instanceof ApiError&&e.status===401)throw e;if(attempt===1)throw e;}
   }
  }catch(e){if(valid()){warning=(e instanceof Error?e.message:String(e))+'. Previously shared hints expire automatically; clock tolerance can extend them to two minutes.';if(e instanceof ApiError&&e.status===401){session=null;generation++;expired();}}}
  finally{epoch?.fill(0);busy=false;settle();}
 }
 onMount(()=>{const timer=setInterval(()=>{now=Date.now();if(session&&!busy&&document.visibilityState==='visible'&&now-lastRenew>=30000)void perform(true);},1000);return()=>{alive=false;generation++;session=null;entries=[];clearInterval(timer);};});
</script>
<details class="card" aria-label="Member activity">
 <summary>Members · {session?'sharing recent activity':'invisible'}</summary>
 <p>Sharing is off by default. An enabled visible tab renews a signed hint for 90 seconds. Hints are encrypted for people with the current forum key; the provider can retain activity history. Closing this tab or signing out stops renewal. Recent activity does not prove someone is online.</p>
 <label><input type="checkbox" checked={!!session} disabled={!session&&(busy||!canShare)} onchange={e=>perform(e.currentTarget.checked)}/> Share my recent activity with forum readers</label>
 <button disabled={busy} onclick={()=>perform()}>Refresh recent activity</button>
 {#if warning}<p class="alert">{warning}</p>{/if}
 {#if active.length}<ul>{#each active as member (member.member+member.session)}<li><code>member-{member.member.slice(0,10)}</code> · recently active · expires in {Math.ceil((member.expires-now)/1000)}s</li>{/each}</ul>{:else}<p>No recent activity loaded.</p>{/if}
</details>
