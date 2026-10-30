// Independent JS verification is exercised by tests/crypto.test.ts; server CLI verifies in Rust.
import {readFile} from 'node:fs/promises';
const path=process.argv[2];if(!path)throw Error('Usage: node --experimental-strip-types scripts/verify-archive.mjs archive.json');
const {default:initProof}=await import('../web/src/generated-proof/nightbuoy_proof.js');await initProof({module_or_path:await readFile(new URL('../web/src/generated-proof/nightbuoy_proof_bg.wasm',import.meta.url))});
const {verifyArchive}=await import('../web/src/lib/protocol.ts');const v=await verifyArchive(JSON.parse(await readFile(path,'utf8')));console.log(JSON.stringify({community:v.community,tip:v.tip,records:v.events.length},null,2));
