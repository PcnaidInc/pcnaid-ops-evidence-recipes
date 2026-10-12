import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {parseJSON,parseCSV,csv,pointer,sanitize,timestamp,canonical,endpointReference} from '../src/shared/data.mjs';
import {readText,writeFile} from '../src/shared/io.mjs';
import {isPublicAddress,validateURL,getJSON} from '../src/shared/network.mjs';
import {makeZip,readZip} from '../src/shared/zip.mjs';

for(const [name,fn]of Object.entries({
  'safe JSON rejects prototype mutation':()=>assert.throws(()=>parseJSON('{"__proto__":{}}')),
  'JSON accepts BOM':()=>assert.deepEqual(parseJSON('\uFEFF{"value":1}'),{value:1}),
  'JSON rejects malformed input':()=>assert.throws(()=>parseJSON('{')),
  'canonical JSON sorts keys':()=>assert.equal(canonical({b:2,a:1}),'{"a":1,"b":2}'),
  'CSV accepts quotes and multiline':()=>assert.equal(parseCSV('ID,Name\r\n1,"Hello,\nthere"\r\n')[0].name,'Hello,\nthere'),
  'CSV rejects duplicate headers':()=>assert.throws(()=>parseCSV('Name,name\n1,2')),
  'CSV rejects unterminated quote':()=>assert.throws(()=>parseCSV('Name\n"hello')),
  'CSV rejects uneven rows':()=>assert.throws(()=>parseCSV('ID,Name\n1')),
  'CSV formula escaping':()=>assert.match(csv([{x:'=1+1'}],['x']),/"'=1\+1"/),
  'JSON pointer escapes':()=>assert.equal(pointer({'a/b':{'~v':5}},'/a~1b/~0v'),5),
  'JSON pointer missing is undefined':()=>assert.equal(pointer({},'/missing'),undefined),
  'JSON pointer rejects unsafe keys':()=>assert.throws(()=>pointer({},'/__proto__')),
  'redaction removes known secrets':()=>assert.deepEqual(sanitize({password:'not-public',nested:{api_key:'not-public'}}),{password:'[REDACTED]',nested:{api_key:'[REDACTED]'}}),
  'URL redaction drops query':()=>assert(!sanitize('https://api.example.com/x?api_key=secret').includes('secret')),
  'endpoint references remove entire path':()=>assert.equal(endpointReference('https://hooks.example.com/secrettoken?x=secret'),'https://hooks.example.com/[path-redacted]'),
  'timestamps require timezone':()=>assert.throws(()=>timestamp('2026-10-05T12:00:00')),
  'timestamps reject impossible dates':()=>assert.throws(()=>timestamp('2026-02-30T12:00:00Z')),
  'timestamps normalize offsets':()=>assert.equal(timestamp('2026-10-05T07:00:00-05:00'),'2026-10-05T12:00:00.000Z'),
  'ZIP roundtrip':()=>assert.equal(readZip(makeZip({'hello.txt':'hello'})).get('hello.txt').toString(),'hello'),
  'ZIP refuses traversal':()=>assert.throws(()=>makeZip({'../secret':'x'})),
  'ZIP refuses absolute names':()=>assert.throws(()=>makeZip({'/secret':'x'})),
  'ZIP rejects corrupt CRC':()=>{const z=makeZip({'a.txt':'hello'});z[35]^=1;assert.throws(()=>readZip(z));},
  'ZIP rejects trailing junk':()=>assert.throws(()=>readZip(Buffer.concat([makeZip({'a':'b'}),Buffer.from('bad')]))),
  'network exact allowed host':()=>assert.equal(validateURL('https://api.example.com/x',['api.example.com']).hostname,'api.example.com'),
  'network rejects suffix lookalike':()=>assert.throws(()=>validateURL('https://api.example.com.evil.test',['api.example.com'])),
  'network rejects credentials':()=>assert.throws(()=>validateURL('https://user:secret@api.example.com',['api.example.com'])),
  'network rejects HTTP':()=>assert.throws(()=>validateURL('http://api.example.com',['api.example.com'])),
  'network rejects nonstandard ports':()=>assert.throws(()=>validateURL('https://api.example.com:444',['api.example.com'])),
  'network rejects raw IP URL':()=>assert.throws(()=>validateURL('https://8.8.8.8',['8.8.8.8']))
}))test(name,fn);

for(const address of ['127.0.0.1','10.0.0.1','192.168.0.1','169.254.169.254','172.16.1.1','100.64.0.1','0.0.0.0','224.0.0.1','198.18.1.1','192.0.2.1','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2001:db8::1','2002:7f00:1::'])
  test('network blocks '+address,()=>assert.equal(isPublicAddress(address),false));

for(const address of ['1.1.1.1','8.8.8.8','2606:4700:4700::1111'])
  test('network permits public '+address,()=>assert.equal(isPublicAddress(address),true));

test('unapproved GET fails before DNS',async()=>assert.rejects(getJSON('https://example.com',{allowedHosts:[]})));

test('file writes do not overwrite without force',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'pcnaid-io-'));
  try{
    const p=path.join(dir,'value');
    await writeFile(p,'one');
    await assert.rejects(writeFile(p,'two'));
    await writeFile(p,'three',true);
    assert.equal(await readText(p),'three');
  }finally{
    await fs.rm(dir,{recursive:true,force:true});
  }
});

test('file IO rejects symlinks',async()=>{
  const dir=await fs.mkdtemp(path.join(os.tmpdir(),'pcnaid-link-'));
  try{
    await fs.writeFile(path.join(dir,'real.txt'),'hello');
    await fs.symlink(path.join(dir,'real.txt'),path.join(dir,'linked.txt'));
    await assert.rejects(readText(path.join(dir,'linked.txt')));
    await assert.rejects(writeFile(path.join(dir,'linked.txt'),'x',true));
  }finally{
    await fs.rm(dir,{recursive:true,force:true});
  }
});
