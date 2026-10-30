import {spawnSync} from 'node:child_process';
import {mkdirSync} from 'node:fs';
import {resolve,dirname} from 'node:path';
import {fileURLToPath,pathToFileURL} from 'node:url';
export const root=resolve(dirname(fileURLToPath(import.meta.url)),'..');
let mode;
export function compose(args,{capture=false,env={}}={}){
 const merged={...process.env,...env};
 if(!mode){if(spawnSync('docker',['info','--format','{{.ServerVersion}}'],{stdio:'ignore',timeout:8000}).status===0)mode='docker';else if(spawnSync('colima',['ssh','--','docker','info','--format','{{.ServerVersion}}'],{stdio:'ignore',timeout:8000}).status===0)mode='colima';else throw Error('Start Docker (or Colima) before running the development environment.');}
 const base=['compose','--project-directory',root,'--file',resolve(root,'compose.yaml')];
 const forwarded=['NIGHTBUOY_HTTPS_PORT','NIGHTBUOY_NODE3_PUBLIC_URL','NIGHTBUOY_NODE3_SOCKS_PROXY'].filter(k=>merged[k]).map(k=>`${k}=${merged[k]}`);
 const command=mode==='docker'?'docker':'colima';const argv=mode==='docker'?[...base,...args]:['ssh','--','env',...forwarded,'docker',...base,...args];
 const r=spawnSync(command,argv,{cwd:root,env:merged,encoding:'utf8',stdio:capture?'pipe':'inherit',maxBuffer:20*1024*1024});
 if(r.error)throw r.error;if(r.status!==0)throw Error(capture?(r.stderr||`Compose exited ${r.status}`):`Compose exited ${r.status}`);return r.stdout||'';
}
if(process.argv[1]&&pathToFileURL(resolve(process.argv[1])).href===import.meta.url){try{let args=process.argv.slice(2);if(args[0]==='certificate'){mkdirSync(resolve(root,'.dev'),{recursive:true,mode:0o700});compose(['cp','ingress:/data/caddy/pki/authorities/local/root.crt',resolve(root,'.dev/caddy-root.crt')]);console.log('Development CA certificate: .dev/caddy-root.crt. Trust it explicitly in your test browser; no system trust was changed.');}else{compose(args.length?args:['ps']);}}catch(e){console.error(e.message);process.exitCode=1;}}
