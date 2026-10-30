import {spawnSync} from 'node:child_process';
import {existsSync,mkdirSync} from 'node:fs';
import {join} from 'node:path';
function run(cmd,args){const r=spawnSync(cmd,args,{stdio:'inherit'});if(r.status!==0)process.exit(r.status||1);}
run('cargo',['build','--locked','--release','--target','wasm32-unknown-unknown','-p','nightbuoy-proof']);
const explicit=process.env.NIGHTBUOY_WASM_BINDGEN;const cached=join('.tools','bin','wasm-bindgen');let cli=explicit||(existsSync(cached)?cached:'wasm-bindgen');
if(spawnSync(cli,['--version'],{stdio:'ignore'}).status!==0){mkdirSync('.tools',{recursive:true});run('cargo',['install','wasm-bindgen-cli','--locked','--version','0.2.130','--root','.tools']);cli=cached;}
run(cli,['target/wasm32-unknown-unknown/release/nightbuoy_proof.wasm','--target','web','--out-dir','web/src/generated-proof']);
