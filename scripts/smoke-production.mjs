import {compose,docker,root} from './compose.mjs';
import {spawnSync} from 'node:child_process';
import {mkdir,readFile,writeFile,rm,access} from 'node:fs/promises';
import {resolve} from 'node:path';
import {X509Certificate,createHash} from 'node:crypto';
import {chromium,expect} from '@playwright/test';
const work=resolve(root,'.dev/production-acceptance'),operator=resolve(work,'validator'),full=resolve(work,'full-node');
try{await access(work);throw Error('Remove only the previous disposable .dev/production-acceptance fixture after inspecting it.');}catch(e){if(e.code!=='ENOENT')throw e;}
await mkdir(work,{recursive:true,mode:0o700});
function op(...args){const r=spawnSync(process.execPath,['scripts/operator.mjs',...args],{cwd:root,stdio:'inherit'});if(r.status!==0)throw Error('Operator provisioning failed.');}
const base=['-p','nightbuoy-production-smoke'];const env={NIGHTBUOY_OPERATOR_DIR:operator,NIGHTBUOY_HOST:'localhost',NIGHTBUOY_P2P_PORT:'29657'};let browser;
let options={file:'compose.production.yaml',env,capture:true};
try{
 op('init','--dir',operator);const descriptor=JSON.parse(await readFile(resolve(operator,'public/validator.json'),'utf8'));
 op('assemble','--dir',operator,'--output',resolve(work,'genesis.json'),'--allow-single-validator',resolve(operator,'public/validator.json'));
 op('install','--dir',operator,'--genesis',resolve(work,'genesis.json'),'--origin','https://localhost:10443');
 op('init','--dir',full);op('install','--dir',full,'--genesis',resolve(work,'genesis.json'),'--origin','https://node1.localhost:10443','--non-voting','--peers',descriptor.node_id+'@app:26656');
 const caddy=resolve(work,'Caddyfile');await writeFile(caddy,'{\n admin off\n auto_https disable_redirects\n skip_install_trust\n}\nhttps://localhost:10443 {\n tls internal\n reverse_proxy app:3000\n}\nhttps://node1.localhost:10443 {\n tls internal\n reverse_proxy full:3000\n}\n');
 const overlay=resolve(work,'overlay.yaml');await writeFile(overlay,`services:
  https:
    ports: !override ['127.0.0.1:10443:10443']
    volumes: !override ['${caddy}:/etc/caddy/Caddyfile:ro', 'certificates:/data']
  full:
    image: nightbuoy:dev
    env_file: ${full}/application.env
    environment:
      NIGHTBUOY_DATA: /data/app
      NIGHTBUOY_WEB: /app/web
      NIGHTBUOY_LISTEN: 0.0.0.0:3000
    volumes: ['full-data:/data/app', '${full}/public:/config:ro', '${full}/secrets:/run/secrets:ro']
  full-consensus:
    image: nightbuoy:dev
    command: [cometbft, start, --home, /data/comet, --log_level, error, --rpc.laddr, 'tcp://127.0.0.1:26657']
    network_mode: service:full
    depends_on: [full]
    volumes: ['${full}/validator:/data/comet']
volumes:
  full-data:
`);
 const cmd=args=>compose(['-f',overlay,...base,...args],options);
 cmd(['--profile','validator','--profile','https','up','-d','--no-build']);
 await new Promise(r=>setTimeout(r,2000));
 for(const name of ['root','intermediate'])cmd(['cp',`https:/data/caddy/pki/authorities/local/${name}.crt`,resolve(work,name+'.crt')]);
 const pins=[];for(const name of ['root','intermediate']){const cert=new X509Certificate(await readFile(resolve(work,name+'.crt')));pins.push(createHash('sha256').update(cert.publicKey.export({format:'der',type:'spki'})).digest('base64'));}
 browser=await chromium.launch({args:[`--ignore-certificate-errors-spki-list=${pins.join(',')}`]});const page=await browser.newPage();await page.goto('https://localhost:10443');await page.getByLabel('Local setup token').fill(cmd(['exec','-T','app','cat','/data/app/bootstrap-token']).trim());await page.getByLabel('Public community label').fill('Disposable production acceptance');const pass='a disposable production acceptance identity only';await page.getByLabel('Unique passphrase',{exact:true}).fill(pass);await page.getByLabel('Repeat passphrase').fill(pass);const download=page.waitForEvent('download');await page.getByRole('button',{name:'Create community & download recovery file'}).click();const vault=resolve(work,'recovery.json');await(await download).saveAs(vault);await expect(page.getByRole('button',{name:'New board',exact:true})).toBeVisible({timeout:30000});await page.getByRole('button',{name:'New board',exact:true}).click();await page.getByLabel('Board name').fill('Production profile board');await page.getByRole('button',{name:'Publish board',exact:true}).click();await expect(page.getByRole('heading',{name:'Production profile board'})).toBeVisible();
 const fullPage=await browser.newPage();await fullPage.goto('https://node1.localhost:10443');await expect(fullPage.getByRole('button',{name:'Import encrypted recovery file'})).toBeVisible({timeout:30000});await fullPage.locator('input[type=file]').first().setInputFiles(vault);await fullPage.getByLabel('Passphrase',{exact:true}).fill(pass);await fullPage.getByRole('button',{name:'Sign in & unlock'}).click();await expect(fullPage.getByRole('heading',{name:'Production profile board'})).toBeVisible({timeout:30000});await fullPage.getByRole('button',{name:'Account',exact:true}).click();await fullPage.getByRole('button',{name:'Approve this host for signed member writes'}).click();await expect(fullPage.getByText('This host is approved for signed member writes.',{exact:true})).toBeVisible({timeout:20000});await fullPage.getByRole('button',{name:'Forum',exact:true}).click();await fullPage.getByRole('heading',{name:'Production profile board'}).click();await fullPage.getByRole('button',{name:'New topic',exact:true}).click();await fullPage.getByLabel('Topic title').fill('A non-voting frontend can publish');await fullPage.getByLabel('Message',{exact:true}).fill('Confirmed through the existing validator; no validator vote was added.');await fullPage.getByRole('button',{name:'Publish topic',exact:true}).click();await expect(fullPage.getByText('Confirmed through the existing validator; no validator vote was added.',{exact:true})).toBeVisible({timeout:30000});const archive=await fullPage.evaluate(()=>fetch('/api/sync').then(r=>r.json()));if(JSON.parse(archive.genesis.body)[3].consensus.validators.length!==1)throw Error('Non-voting participation changed validator membership.');
 const logs=cmd(['logs','--no-color','app','full']);if(logs.includes('Setup token:'))throw Error('Bootstrap token leaked into service logs.');await fullPage.screenshot({path:resolve(root,'.dev/production-smoke.png'),fullPage:true});console.log('Production profile smoke passed: separately generated keys, immutable shared genesis, HTTPS key enrollment, non-voting full-node catch-up, explicit publisher approval and confirmed encrypted posting. One validator is used only for this isolated packaging test.');
}finally{await browser?.close();try{compose(['-f',resolve(work,'overlay.yaml'),...base,'--profile','*','down','--volumes','--remove-orphans'],options);}catch{}await rm(work,{recursive:true,force:true});}
