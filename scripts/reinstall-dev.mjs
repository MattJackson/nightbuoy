// Fresh development install. Previous volumes/signing state are retained, never reused.
import {compose,docker,root} from './compose.mjs';
import {mkdir,writeFile,readFile,appendFile} from 'node:fs/promises';
import {resolve} from 'node:path';
const dir=resolve(root,'.dev');await mkdir(dir,{recursive:true,mode:0o700});let old='nightbuoy-dev';try{old=(await readFile(resolve(dir,'project'),'utf8')).trim();}catch{}
const certOverride=resolve(dir,'certificates.compose.yaml');try{await readFile(certOverride);}catch{const volume=old+'_caddy';docker(['volume','create',volume],{capture:true});await writeFile(certOverride,`volumes:
  caddy:
    external: true
    name: ${volume}
`);}
compose(['down']);
await appendFile(resolve(dir,'retained-projects.txt'),old+'\n',{mode:0o600});
const project='nightbuoy-dev-'+Date.now().toString(36);await writeFile(resolve(dir,'project'),project+'\n',{mode:0o600});
compose(['up','-d','--no-build']);
compose(['cp','ingress:/data/caddy/pki/authorities/local/root.crt',resolve(dir,'caddy-root.crt')]);
console.log('Fresh NightBuoy installer: https://localhost:8443. Previous development volumes are retained. Trust .dev/caddy-root.crt in your test browser, then run npm run dev:token for the one-use setup token.');
