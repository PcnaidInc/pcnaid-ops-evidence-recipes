import path from 'node:path';
import fs from 'node:fs/promises';
import {generateKeyPairSync} from 'node:crypto';
import {readJSON,readText,writeFile} from './shared/io.mjs';
import {assert,pretty,sha256,parseJSON} from './shared/data.mjs';
import {evaluateEvidence,collectEvidence,verifyEvidencePacket} from './evidence/runner.mjs';
import {renderReport,csvReport,packet} from './shared/reports.mjs';

export const HELP=`Pcnaid Evidence Recipes 0.1.0 — declarative evidence collection and verification

  evidence --recipe recipe.json --input response.json --out reports/evidence
           [--origin supplied_file|fixture] [--as-of ISO] [--signing-key key.pem]
  evidence --recipe recipe.json --live --param key=value --out reports/evidence
           [--allow-host exact.example.com] [--signing-key key.pem]
  keygen --out ./private-signing-keys
  verify --packet packet.zip [--public-key independently-trusted-public.pem]
         [--require-signature]

--force explicitly permits replacement of output files. Existing paths otherwise fail.
The --live option is the only network mode; it issues read-only HTTPS GET requests.
No command installs packages, runs repository code, transfers assets, or merges PRs.
`;

const FLAGS=new Set(['force','live','require-signature','help']);
const ALLOWED={
  evidence:['recipe','input','out','origin','as-of','signing-key','live','param','allow-host'],
  keygen:['out'],
  verify:['packet','public-key','require-signature']
};

function parseArgs(argv){
  const [command,...rest]=argv,options={};
  assert(Object.hasOwn(ALLOWED,command),`Unknown command ${command}. Run --help.`);
  for(let i=0;i<rest.length;i++){
    const key=rest[i];
    assert(/^--[a-z][a-z-]*$/.test(key),'Expected --option followed by a value');
    const name=key.slice(2);
    assert(ALLOWED[command].includes(name)||['force','help'].includes(name),`Unknown option ${key}`);
    const value=FLAGS.has(name)?true:rest[++i];
    assert(value!==undefined&&!String(value).startsWith('--'),`Missing value for ${key}`);
    if(Object.hasOwn(options,name)){
      assert(['param','allow-host'].includes(name),'Duplicate option '+key);
      options[name]=[].concat(options[name],value);
    }else options[name]=value;
  }
  return {command,options};
}

const need=(o,k)=>{assert(typeof o[k]==='string'&&o[k].length>0,`--${k} is required and must occur once`);return o[k];};
const all=x=>x===undefined?[]:Array.isArray(x)?x:[x];

export async function saveReport(report,out,{force=false,privateKey=null}={}){
  const files={'report.json':pretty(report),'report.html':renderReport(report),'findings.csv':csvReport(report),'packet.zip':packet(report,{privateKey})};
  if(!force)for(const name of Object.keys(files)){
    try{await fs.lstat(path.join(out,name));throw new Error('Output already exists: '+path.join(out,name));}
    catch(e){if(e.code!=='ENOENT')throw e;}
  }
  for(const [name,value]of Object.entries(files))await writeFile(path.join(out,name),value,force);
  return path.resolve(out);
}

export async function main(argv=process.argv.slice(2)){
  if(!argv.length||argv[0]==='--help'||argv[0]==='help'){console.log(HELP);return;}
  const {command,options:o}=parseArgs(argv);
  if(o.help){console.log(HELP);return;}
  const force=!!o.force;
  let report;
  if(command==='evidence'){
    const recipe=await readJSON(need(o,'recipe'));
    assert(!(o.live&&o.input),'Choose --input OR --live, not both');
    if(o.live){
      assert(!o.origin&&!o['as-of'],'Live origin and timestamp come from the collector, not command-line overrides');
      const parameters={};
      for(const item of all(o.param)){
        const idx=item.indexOf('=');
        assert(idx>0,'Use --param key=value');
        const key=item.slice(0,idx);
        assert(!Object.hasOwn(parameters,key),'Duplicate parameter');
        assert(!['__proto__','constructor','prototype'].includes(key),'Unsafe parameter');
        parameters[key]=item.slice(idx+1);
      }
      report=await collectEvidence(recipe,{parameters,allowHosts:all(o['allow-host'])});
    }else{
      assert(!o.param&&!o['allow-host'],'--param and --allow-host are only for --live');
      const text=await readText(need(o,'input'));
      assert(!o.origin||['supplied_file','fixture'].includes(o.origin),'Imported input cannot claim live_api origin');
      report=evaluateEvidence(recipe,parseJSON(text),{origin:o.origin??'supplied_file',rawHash:sha256(text),...(o['as-of']?{asOf:o['as-of']}:{})});
    }
  }else if(command==='keygen'){
    const out=need(o,'out');
    for(const name of ['public.pem','private.pem']){
      try{await fs.lstat(path.join(out,name));throw new Error('Signing key path already exists: '+name);}
      catch(e){if(e.code!=='ENOENT')throw e;}
    }
    const keys=generateKeyPairSync('ed25519',{privateKeyEncoding:{type:'pkcs8',format:'pem'},publicKeyEncoding:{type:'spki',format:'pem'}});
    assert(!force,'Key generation never overwrites existing keys');
    await writeFile(path.join(out,'public.pem'),keys.publicKey);
    await writeFile(path.join(out,'private.pem'),keys.privateKey);
    console.log('Created private.pem and public.pem. Keep the private key outside repositories and separately distribute the public key.');
    return;
  }else if(command==='verify'){
    const p=need(o,'packet'),s=await fs.lstat(p);
    assert(s.isFile()&&!s.isSymbolicLink()&&s.size<=26*1024*1024,'Packet must be a regular file under 26 MiB');
    const result=verifyEvidencePacket(await fs.readFile(p),{trustedPublicKey:o['public-key']?await readText(o['public-key']):null,requireSignature:!!o['require-signature']});
    console.log(pretty(result));
    return;
  }
  if(report){
    const out=await saveReport(report,need(o,'out'),{force,privateKey:o['signing-key']?await readText(o['signing-key']):null});
    console.log(`${report.kind}: ${out}`);
    console.log(pretty(report.summary));
  }
}
