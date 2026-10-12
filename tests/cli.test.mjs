import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {ROOT} from '../src/runtime/samples.mjs';

const invoke=args=>spawnSync(process.execPath,['bin/pcnaid-evidence.mjs',...args],{cwd:ROOT,encoding:'utf8'});

test('CLI help works without package install',()=>assert.match(invoke(['--help']).stdout,/No command installs packages/));
test('CLI rejects unknown options',()=>assert.equal(invoke(['evidence','--typo','value']).status,1));
test('CLI requires output explicitly',()=>assert.equal(invoke(['evidence','--recipe','recipes/cloudflare-zone-ssl.json','--input','examples/evidence/cloudflare-zone-ssl.json']).status,1));
test('CLI complete evidence signing and verification',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'pcnaid-cli-'));
  try{
    assert.equal(invoke(['keygen','--out',dir+'/keys']).status,0);
    const collect=invoke(['evidence','--recipe','recipes/cloudflare-zone-ssl.json','--input','examples/evidence/cloudflare-zone-ssl.json','--origin','fixture','--signing-key',dir+'/keys/private.pem','--out',dir+'/packet']);
    assert.equal(collect.status,0,collect.stderr);
    const verified=invoke(['verify','--packet',dir+'/packet/packet.zip','--public-key',dir+'/keys/public.pem','--require-signature']);
    assert.equal(verified.status,0,verified.stderr);
    assert.match(verified.stdout,/trusted_signature/);
    assert.equal(invoke(['keygen','--out',dir+'/keys']).status,1);
  }finally{
    await fs.rm(dir,{recursive:true,force:true});
  }
});
test('CLI imported evidence cannot claim live provenance',()=>assert.equal(invoke(['evidence','--recipe','recipes/cloudflare-zone-ssl.json','--input','examples/evidence/cloudflare-zone-ssl.json','--origin','live_api','--out','unused']).status,1));
test('keygen preflights both key paths without leaving a mismatched public key',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'pcnaid-existing-key-'));
  try{
    await fs.writeFile(dir+'/private.pem','existing private placeholder');
    assert.equal(invoke(['keygen','--out',dir]).status,1);
    await assert.rejects(fs.stat(dir+'/public.pem'));
    assert.equal(await fs.readFile(dir+'/private.pem','utf8'),'existing private placeholder');
  }finally{
    await fs.rm(dir,{recursive:true,force:true});
  }
});
