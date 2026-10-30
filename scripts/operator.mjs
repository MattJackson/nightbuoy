import {docker,root} from './compose.mjs';
import {mkdir,readFile,writeFile,access} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';
import {createHash,randomBytes} from 'node:crypto';
const args=process.argv.slice(2),command=args.shift();
function option(name,fallback){const i=args.indexOf(name);if(i<0)return fallback;const value=args[i+1];if(!value||value.startsWith('--'))throw Error('Missing value for '+name);args.splice(i,2);return value;}
const dir=resolve(option('--dir','operator')),image=option('--image','nightbuoy:dev');
const validator=resolve(dir,'validator'),publicDir=resolve(dir,'public');
const run=(argv,options={})=>docker(['run','--rm','--user','0:0','--volume',`${validator}:/validator`,image,...argv],{capture:true,...options});
const sha=b=>createHash('sha256').update(b).digest('hex');
function publicValidator(v){if(v.pub_key?.type!=='tendermint/PubKeyEd25519')throw Error('Only Ed25519 validator keys are supported.');const key=Buffer.from(v.pub_key.value,'base64');if(key.length!==32||sha(key).slice(0,40).toUpperCase()!==v.address)throw Error('Invalid validator key/address.');return {address:v.address,pub_key:v.pub_key,power:'1',name:'validator-'+v.address.slice(0,12).toLowerCase()};}
function validateSet(validators){const ids=new Set();for(const v of validators){publicValidator(v);if(ids.has(v.address))throw Error('Duplicate validator.');ids.add(v.address);}if(validators.length<1||validators.length>128)throw Error('Unsupported validator count.');}
async function writeNew(path,text){await mkdir(dirname(path),{recursive:true});await writeFile(path,text,{flag:'wx',mode:0o600});}
if(command==='init'){
 if(args.length)throw Error('Unexpected arguments.');
 await mkdir(validator,{recursive:true,mode:0o700});await mkdir(publicDir,{recursive:true});await mkdir(resolve(dir,'secrets'),{recursive:true,mode:0o700});
 run(['sh','-eu','-c','test ! -e /validator/config/priv_validator_key.json; cometbft init --home /validator >/dev/null 2>&1; chown -R 10001:10001 /validator; chmod 700 /validator /validator/config /validator/data; chmod 600 /validator/config/priv_validator_key.json /validator/config/node_key.json']);
 const pubKey=JSON.parse(run(['cometbft','show-validator','--home','/validator']));const descriptor=publicValidator({address:sha(Buffer.from(pubKey.value,'base64')).slice(0,40).toUpperCase(),pub_key:pubKey});descriptor.node_id=run(['cometbft','show-node-id','--home','/validator']).trim();
 await writeNew(resolve(publicDir,'validator.json'),JSON.stringify(descriptor,null,2)+'\n');await writeNew(resolve(publicDir,'template-genesis.json'),run(['cat','/validator/config/genesis.json']));console.log('Created local validator keys. Share only public/validator.json; never share validator/.');
}else if(command==='assemble'){
 const output=resolve(option('--output',resolve(dir,'shared-genesis.json')));const template=resolve(option('--template',resolve(publicDir,'template-genesis.json')));const allowSingle=args.includes('--allow-single-validator');if(allowSingle)args.splice(args.indexOf('--allow-single-validator'),1);
 if(args.length<4&&!allowSingle)throw Error('Provide at least four independently generated public descriptors. --allow-single-validator is only for isolated tests.');
 const validators=[];for(const file of args)validators.push(publicValidator(JSON.parse(await readFile(file,'utf8'))));validateSet(validators);
 const genesis=JSON.parse(await readFile(template,'utf8'));genesis.chain_id='nightbuoy-'+randomBytes(12).toString('hex');genesis.genesis_time=new Date().toISOString();genesis.initial_height='1';genesis.validators=validators;genesis.app_hash='';genesis.app_state=null;genesis.consensus_params.block.max_bytes='83886080';
 await writeNew(output,JSON.stringify(genesis,null,2)+'\n');console.log('Shared genesis SHA-256: '+sha(await readFile(output)));console.log('Every operator must independently confirm this fingerprint and their own public key before installation.');
}else if(command==='install'){
 const nonVoting=args.includes('--non-voting');if(nonVoting)args.splice(args.indexOf('--non-voting'),1);
 const file=resolve(option('--genesis','')),origin=option('--origin',''),peers=option('--peers','');if(args.length||!origin||file===root)throw Error('install requires --genesis FILE --origin ORIGIN [--peers ID@PRIVATE_HOST:PORT,...].');
 const url=new URL(origin);if(url.origin!==origin||!(url.protocol==='https:'||(url.protocol==='http:'&&/^[a-z2-7]{56}\.onion$/.test(url.hostname))))throw Error('Origin must be HTTPS or a v3 onion origin.');if(peers&&!/^[-a-zA-Z0-9.:@,\[\]]+$/.test(peers))throw Error('Invalid private peer coordinates.');
 const bytes=await readFile(file),genesis=JSON.parse(bytes);validateSet(genesis.validators);if(!/^[-a-zA-Z0-9_]{1,50}$/.test(genesis.chain_id)||genesis.initial_height!=='1'||genesis.app_hash||genesis.app_state||Number(genesis.consensus_params.block.max_bytes)<8500000||Number(genesis.consensus_params.block.max_bytes)>100000000)throw Error('Expected a fresh NightBuoy network genesis.');
 const local=JSON.parse(run(['cometbft','show-validator','--home','/validator']));const votes=genesis.validators.some(v=>v.pub_key.value===local.value);if(nonVoting?votes:!votes)throw Error(nonVoting?'The local key must be absent for non-voting mode.':'This operator is absent from the validator set; use --non-voting for a full node.');
 const state=JSON.parse(run(['cat','/validator/data/priv_validator_state.json']));if(state.height!=='0')throw Error('Validator has already signed. Preserve it; initialize new keys in a new directory for a separate network.');
 run(['sh','-eu','-c','test ! -e /validator/data/blockstore.db; test ! -e /validator/data/state.db']);
 try{await access(resolve(dir,'application.env'));throw Error('An application configuration already exists. Refusing to overwrite.');}catch(e){if(e.code!=='ENOENT')throw e;}
 await writeNew(resolve(publicDir,'genesis.json'),bytes);await writeNew(resolve(publicDir,'providers.json'),'[]\n');await writeNew(resolve(publicDir,'replicas.json'),'[]\n');
 // Container arguments and environment are separate from shell source; peer syntax excludes shell metacharacters.
 docker(['run','--rm','--user','0:0','--volume',`${validator}:/validator`,'--volume',`${resolve(publicDir,'genesis.json')}:/new-genesis:ro`,'--env',`NIGHTBUOY_PEERS=${peers}`,image,'sh','-eu','-c','cp /new-genesis /validator/config/genesis.json; sed -i "s/^persistent_peers = .*/persistent_peers = \\"$NIGHTBUOY_PEERS\\"/" /validator/config/config.toml; sed -i "s/^max_tx_bytes = .*/max_tx_bytes = 67109888/; s/^max_body_bytes = .*/max_body_bytes = 134217728/; s/^addr_book_strict = .*/addr_book_strict = false/; s/^pex = .*/pex = false/" /validator/config/config.toml; chown -R 10001:10001 /validator']);
 // Public config must be readable by the non-root application container.
 const {chmod}=await import('node:fs/promises');for(const name of ['genesis.json','providers.json','replicas.json'])await chmod(resolve(publicDir,name),0o644);
 let config=(await readFile(resolve(root,'examples/application.validator.env'),'utf8')).replace('https://forum.example.org',origin);if(url.protocol==='http:')config+='\nNIGHTBUOY_SOCKS_PROXY=socks5h://127.0.0.1:9050\n';await writeNew(resolve(dir,'application.env'),config);await chmod(resolve(dir,'application.env'),0o644);console.log('Installed fresh network. Genesis SHA-256: '+sha(bytes));
}else{throw Error('Use: operator.mjs init | assemble FILE... [--output FILE] | install --genesis FILE --origin ORIGIN [--peers ID@HOST:PORT,...]. Optional --dir and --image apply to all commands.');}
