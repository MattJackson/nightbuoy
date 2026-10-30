import {docker,compose,root} from './compose.mjs';
import {firefox,expect} from '@playwright/test';
import {mkdir,copyFile,writeFile,access,chmod} from 'node:fs/promises';
import {resolve} from 'node:path';
const dir=resolve(root,'.dev/tor-operator');
await access(resolve(root,'.dev/tor-smoke-archive.json'));
await mkdir(resolve(dir,'public'),{recursive:true,mode:0o700});await mkdir(resolve(dir,'secrets'),{recursive:true,mode:0o700});
await chmod(resolve(dir,'public'),0o755);
await copyFile(resolve(root,'.dev/tor-smoke-archive.json'),resolve(dir,'public/archive.json'));await writeFile(resolve(dir,'public/replicas.json'),'[]');
// This temporary file is needed for Compose validation before an onion identity exists.
await writeFile(resolve(dir,'application.env'),'NIGHTBUOY_READ_ONLY=1\nNIGHTBUOY_PUBLIC_URL=https://unconfigured.invalid\n');
const env={NIGHTBUOY_OPERATOR_DIR:dir,NIGHTBUOY_HOST:'unused.invalid',NIGHTBUOY_P2P_PORT:'29656'};
const options={env,file:'compose.production.yaml'};const base=['-p','nightbuoy-tor-smoke'];const client='nightbuoy-tor-smoke-client';let browser;
try{
 docker(['build','-t','nightbuoy-tor:dev','-f',resolve(root,'docker/Dockerfile.tor'),root]);
 const hostname=compose([...base,'run','--rm','tor-init'],{...options,capture:true}).trim().split('\n').at(-1);
 if(!/^[a-z2-7]{56}\.onion$/.test(hostname))throw Error('Tor did not produce a v3 service address.');
 const url='http://'+hostname;
 await writeFile(resolve(dir,'application.env'),`NIGHTBUOY_READ_ONLY=1\nNIGHTBUOY_PUBLIC_URL=${url}\nNIGHTBUOY_ARCHIVE_FILE=/config/archive.json\nNIGHTBUOY_REPLICAS_FILE=/config/replicas.json\nNIGHTBUOY_SOCKS_PROXY=socks5h://127.0.0.1:9050\n`);
 compose([...base,'--profile','tor','up','-d','--no-build','app','tor'],options);
 docker(['run','--rm','-d','--name',client,'--publish','127.0.0.1:19050:9050','nightbuoy-tor:dev','tor','-f','/etc/tor/client-test']);
 const started=Date.now();while(Date.now()-started<180000){const logs=docker(['logs',client],{capture:true});if(logs.includes('Bootstrapped 100%'))break;await new Promise(r=>setTimeout(r,2000));if(Date.now()-started>=178000)throw Error('Tor client bootstrap timed out.');}
 browser=await firefox.launch({proxy:{server:'socks5://127.0.0.1:19050'},firefoxUserPrefs:{'network.proxy.socks_remote_dns':true,'network.trr.mode':5,'dom.securecontext.allowlist_onions':true,'dom.security.https_only_mode.upgrade_onion':false}});
 const page=await browser.newPage();let loaded=false;for(let attempt=0;attempt<4;attempt++){try{await page.goto(url,{timeout:45000});await page.getByRole('button',{name:'Import encrypted recovery file'}).waitFor({timeout:15000});loaded=true;break;}catch{await new Promise(r=>setTimeout(r,3000));}}if(!loaded)throw Error('Onion frontend could not be reached through the separate Tor client.');
 if(!await page.evaluate(()=>isSecureContext&&!!crypto.subtle))throw Error('Onion origin lacks the required secure cryptographic context.');
 await expect(page.getByText('A confirmed post on the deliberate recovery branch.',{exact:true})).toHaveCount(0);
 page.once('dialog',d=>d.accept());await page.getByRole('button',{name:'Choose this branch',exact:true}).click();
 await page.locator('input[type=file]').first().setInputFiles(resolve(root,'.dev/tor-smoke-recovery.json'));await page.getByLabel('Passphrase',{exact:true}).fill('six independently chosen words are not this test');await page.getByRole('button',{name:'Sign in & unlock'}).click();await expect(page.getByRole('heading',{name:'Shared consensus board'})).toBeVisible({timeout:60000});await page.getByRole('heading',{name:'Shared consensus board'}).click();await page.getByRole('heading',{name:'Parallel post B'}).click();await expect(page.getByText('A confirmed post on the deliberate recovery branch.',{exact:true})).toBeVisible();
 await page.screenshot({path:resolve(root,'.dev/tor-smoke.png'),fullPage:true});console.log('Tor smoke passed: separate Tor client, v3 onion frontend, secure WebCrypto context, explicit branch choice, key sign-in and authenticated history decryption. This uses automated Firefox with the onion secure-context preference, not a Tor Browser anonymity certification.');
}finally{await browser?.close();try{docker(['rm','-f',client],{capture:true});}catch{}compose([...base,'--profile','*','down','--volumes','--remove-orphans'],options);}
