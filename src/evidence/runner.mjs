import {assert, object, array, string, noExtra, pointer, sanitize, canonical, pretty, sha256, VERSION, timestamp, parseJSON} from '../shared/data.mjs';
import {makeZip, readZip} from '../shared/zip.mjs';
import {createPrivateKey, createPublicKey, sign, verify} from 'node:crypto';
import {getJSON} from '../shared/network.mjs';

export function validateRecipe(raw){
  object(raw,'recipe');
  noExtra(raw,['version','id','name','description','source','fields','checks'],'recipe');
  assert(raw.version==='1','Recipe version must be "1"');
  string(raw.id,'recipe.id',80);
  assert(/^[a-z0-9][a-z0-9-]*$/.test(raw.id),'Recipe ID must be a lowercase slug');
  string(raw.name,'recipe.name');
  string(raw.description,'recipe.description');
  object(raw.source,'source');
  noExtra(raw.source,['kind','url','tokenEnv','reference','pagination'],'recipe.source');
  assert(['cloudflare-zone-setting','azure-storage','custom-rest'].includes(raw.source.kind),'Unsupported collector');
  if(raw.source.url){
    string(raw.source.url,'source.url',3000);
    let url;
    try{url=new URL(raw.source.url);}catch{throw new Error('Recipe URL must be HTTPS');}
    assert(url.protocol==='https:'&&!url.username&&!url.password&&!url.hash,'Recipe URL must be HTTPS without embedded credentials or fragments');
    assert(!url.search||raw.source.kind==='azure-storage'&&url.search==='?api-version=2023-05-01','Recipe URLs cannot contain secret-bearing or arbitrary query strings');
  }
  if(raw.source.tokenEnv)assert(/^[A-Z][A-Z0-9_]{0,100}$/.test(raw.source.tokenEnv),'tokenEnv must be an environment-variable name, not a credential');
  if(raw.source.reference){
    string(raw.source.reference,'source.reference',3000);
    const ref=new URL(raw.source.reference);
    assert(ref.protocol==='https:'&&!ref.username&&!ref.password&&!ref.search&&!ref.hash,'Reference must be a credential-free HTTPS documentation URL without query/fragment');
  }
  assert(raw.source.pagination==='single','Recipes must explicitly declare a single-response scope; list pagination is not silently assumed complete');
  const fields=array(raw.fields,'fields',100);
  assert(fields.length>0,'Select at least one field');
  const names=new Set();
  for(const f of fields){
    object(f,'field');
    noExtra(f,['name','path'],'field');
    string(f.name,'field.name',100);
    assert(/^[a-zA-Z][a-zA-Z0-9_]*$/.test(f.name)&&!['constructor','prototype','__proto__'].includes(f.name),'Unsafe field name');
    assert(!names.has(f.name),'Duplicate field name');
    names.add(f.name);
    pointer({},f.path);
    assert(f.path!=='','Selecting the entire response is not permitted; select necessary fields');
  }
  const checks=array(raw.checks,'checks',100);
  assert(checks.length>0,'At least one check is required');
  const ids=new Set();
  for(const c of checks){
    object(c,'check');
    noExtra(c,['id','field','operator','expected','description'],'check');
    string(c.id,'check.id',100);
    assert(!ids.has(c.id),'Duplicate check ID');
    ids.add(c.id);
    assert(names.has(c.field),'Check field is not selected');
    assert(['equals','one_of','exists','nonempty','greater_or_equal','all_equals'].includes(c.operator),'Unsupported check operator');
    string(c.description,'check.description');
    if(['equals','one_of','greater_or_equal','all_equals'].includes(c.operator))assert(Object.hasOwn(c,'expected'),'Expected value is required');
    if(c.operator==='one_of')assert(Array.isArray(c.expected)&&c.expected.length>0,'one_of expected must be a nonempty array');
    if(c.operator==='greater_or_equal')assert(typeof c.expected==='number'&&Number.isFinite(c.expected),'greater_or_equal requires a finite number');
  }
  return structuredClone(raw);
}

export function evaluateEvidence(recipeRaw,input,{asOf=new Date().toISOString(),origin='supplied_file',rawHash=null,collectorStatus=null}={}){
  const recipe=validateRecipe(recipeRaw);
  timestamp(asOf);
  object(input,'evidence response');
  assert(['supplied_file','fixture','live_api'].includes(origin),'Invalid evidence origin');
  const fields={},missing=[],redacted=[];
  for(const f of recipe.fields){
    const value=pointer(input,f.path);
    if(value===undefined){
      fields[f.name]=null;
      missing.push(f.name);
    }else{
      const safe=sanitize({[f.name]:value})[f.name];
      fields[f.name]=safe;
      if(canonical(safe)!==canonical(value))redacted.push(f.name);
    }
  }
  const checks=recipe.checks.map(c=>{
    const value=fields[c.field];
    let status='unknown',reason=null;
    if(missing.includes(c.field))reason='Selected field is missing; missing data cannot pass.';
    else if(redacted.includes(c.field)||typeof value==='string'&&value.includes('[REDACTED]'))reason='Selected field was redacted; compare is withheld.';
    else {
      let pass;
      if(c.operator==='exists')pass=value!==null;
      if(c.operator==='equals')pass=canonical(value)===canonical(c.expected);
      if(c.operator==='one_of')pass=c.expected.some(x=>canonical(x)===canonical(value));
      if(c.operator==='nonempty'){if(Array.isArray(value)||typeof value==='string')pass=value.length>0;else reason='Expected string/array for nonempty.';}
      if(c.operator==='greater_or_equal'){if(typeof value==='number')pass=value>=c.expected;else reason='Expected a number; string coercion is disabled.';}
      if(c.operator==='all_equals'){if(Array.isArray(value)){if(!value.length)reason='Empty array is unknown, not a vacuous pass.';else pass=value.every(x=>canonical(x)===canonical(c.expected));}else reason='Expected array for all_equals.';}
      if(typeof pass==='boolean')status=pass?'pass':'fail';
    }
    return {id:c.id,description:c.description,field:c.field,operator:c.operator,expected:c.expected??null,status,reason};
  });
  const counts={pass:0,fail:0,unknown:0};
  for(const c of checks)counts[c.status]++;
  return {
    kind:'evidence',
    version:VERSION,
    generatedAt:timestamp(asOf),
    recipeId:recipe.id,
    recipeName:recipe.name,
    recipeSha256:sha256(recipe),
    inputSha256:rawHash??sha256(input),
    origin,
    collectorStatus,
    summary:{checks:checks.length,statuses:counts,result:counts.fail?'fail':counts.unknown?'unknown':'pass'},
    fields,
    checks,
    redaction:{selectedFields:recipe.fields.map(f=>f.name),changedFields:redacted,missingFields:missing,rawResponseIncluded:false},
    recipe,
    warnings:origin==='live_api'?[]:['Imported/fixture evidence is not a live API observation. Its origin and completeness are operator assertions.'],
    limitations:[
      'A recipe result is an observation, not an auditor opinion or proof of SOC 2/ISO compliance.',
      'SHA-256 detects changes relative to a trusted manifest; hashes alone do not authenticate a source.',
      'Optional Ed25519 signatures attest to the signing key, not independent source truth or trusted time.',
      'Timestamp uses the local computer clock; no trusted timestamp authority is contacted.',
      'Only selected fields from a single response are assessed; unselected fields and pagination are out of scope.',
      'Redaction is defense in depth, not a guarantee that every sensitive string is removed. Review before sharing.'
    ]
  };
}

function interpolate(url,parameters){
  return url.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g,(_,k)=>{
    assert(Object.hasOwn(parameters,k),`Missing recipe parameter ${k}`);
    const v=string(parameters[k],`parameter ${k}`,200);
    assert(/^[A-Za-z0-9._-]+$/.test(v),'Parameters must be identifier segments, not paths');
    return encodeURIComponent(v);
  });
}

export function collectorPlan(raw,parameters={},allowHosts=[]){
  const recipe=validateRecipe(raw);
  let url=interpolate(recipe.source.url??'',parameters),hosts=[];
  if(recipe.source.kind==='cloudflare-zone-setting'){
    assert(/^https:\/\/api\.cloudflare\.com\/client\/v4\/zones\/[a-fA-F0-9]{32}\/settings\/(?:ssl|always_use_https|min_tls_version)$/.test(url),'Cloudflare recipe URL must address one approved zone setting');
    hosts=['api.cloudflare.com'];
  }else if(recipe.source.kind==='azure-storage'){
    assert(/^https:\/\/management\.azure\.com\/subscriptions\/[0-9a-fA-F-]{36}\/resourceGroups\/[A-Za-z0-9._-]+\/providers\/Microsoft\.Storage\/storageAccounts\/[a-z0-9]{3,24}\?api-version=2023-05-01$/.test(url),'Azure recipe URL must address one storage account and the pinned API version');
    hosts=['management.azure.com'];
  }else{
    hosts=allowHosts;
    assert(hosts.length>0,'Custom REST requires --allow-host with an exact public hostname');
    const u=new URL(url);
    assert(!u.search,'Custom REST URLs with query strings are disabled to prevent secrets in artifact metadata');
  }
  return {recipe,url,hosts,tokenEnv:recipe.source.tokenEnv??null};
}

export async function collectEvidence(raw,{parameters={},allowHosts=[],env=process.env}={}){
  const plan=collectorPlan(raw,parameters,allowHosts),token=plan.tokenEnv?env[plan.tokenEnv]:null;
  if(plan.tokenEnv)assert(typeof token==='string'&&token.length>0,`Set ${plan.tokenEnv} in the environment; credentials are never accepted in recipes`);
  const response=await getJSON(plan.url,{allowedHosts:plan.hosts,token});
  if(plan.recipe.source.kind==='cloudflare-zone-setting')assert(response.data.success===true,'Cloudflare reported success=false; response is not evidence');
  const report=evaluateEvidence(plan.recipe,response.data,{origin:'live_api',rawHash:sha256(response.rawBytes),collectorStatus:{httpStatus:response.status,sourceHost:new URL(plan.url).hostname,etag:response.etag}});
  return report;
}

export function evidencePacket(report,html,{privateKey=null}={}){
  assert(report.kind==='evidence','Expected evidence report');
  const files={'report.json':pretty(report),'observations.json':pretty(report.fields),'recipe.json':pretty(report.recipe),'report.html':html};
  const manifest={format:'pcnaid-evidence-packet-v1',createdAt:report.generatedAt,recipeId:report.recipeId,origin:report.origin,sourceInputSha256:report.inputSha256,files:Object.fromEntries(Object.entries(files).map(([name,value])=>[name,{sha256:sha256(value),bytes:Buffer.byteLength(value)}])),signature:null};
  if(privateKey){
    const key=createPrivateKey(privateKey);
    assert(key.asymmetricKeyType==='ed25519','Only Ed25519 signing keys are supported');
    const pub=createPublicKey(key);
    const publicPem=pub.export({type:'spki',format:'pem'});
    manifest.signature={algorithm:'Ed25519',publicKeySha256:sha256(pub.export({type:'spki',format:'der'}))};
    files['manifest.json']=pretty(manifest);
    files['manifest.sig']=sign(null,Buffer.from(files['manifest.json']),key);
    files['public-key.pem']=publicPem;
  } else {
    files['manifest.json']=pretty(manifest);
  }
  return makeZip(files);
}

export function verifyEvidencePacket(bytes,{trustedPublicKey=null,requireSignature=false}={}){
  const files=readZip(bytes);
  assert(files.has('manifest.json'),'Evidence packet has no manifest');
  let manifest;
  try{manifest=parseJSON(files.get('manifest.json').toString('utf8'));}catch{throw new Error('Invalid manifest JSON');}
  assert(manifest.format==='pcnaid-evidence-packet-v1','Unsupported evidence format');
  object(manifest.files,'manifest.files');
  assert(['report.json','observations.json','recipe.json','report.html'].every(name=>Object.hasOwn(manifest.files,name)),'Missing required evidence file');
  const expected=['manifest.json',...Object.keys(manifest.files),...(manifest.signature?['manifest.sig','public-key.pem']:[])];
  assert(expected.length===files.size&&expected.every(name=>files.has(name)),'Missing or unexpected packet files');
  for(const [name,entry]of Object.entries(manifest.files)){
    assert(!['manifest.json','manifest.sig','public-key.pem'].includes(name),'Reserved manifest entry');
    const data=files.get(name);
    assert(entry.bytes===data.length&&entry.sha256===sha256(data),`Integrity mismatch for ${name}`);
  }
  let authentication='unsigned';
  if(manifest.signature){
    assert(manifest.signature.algorithm==='Ed25519','Unsupported signature algorithm');
    const pub=createPublicKey(files.get('public-key.pem'));
    assert(pub.asymmetricKeyType==='ed25519','Unsupported key type');
    assert(sha256(pub.export({type:'spki',format:'der'}))===manifest.signature.publicKeySha256,'Signing-key fingerprint mismatch');
    assert(verify(null,files.get('manifest.json'),pub,files.get('manifest.sig')),'Invalid manifest signature');
    authentication='valid_signature_untrusted_key';
    if(trustedPublicKey){
      const trusted=createPublicKey(trustedPublicKey);
      assert(sha256(trusted.export({type:'spki',format:'der'}))===manifest.signature.publicKeySha256,'The signing key is not the supplied trusted key');
      authentication='trusted_signature';
    }
  }
  if(requireSignature||trustedPublicKey)assert(authentication==='trusted_signature','A signature under an independently supplied trusted public key is required');
  return {integrity:'verified',authentication,manifestSha256:sha256(files.get('manifest.json')),files:files.size,origin:manifest.origin,createdAt:manifest.createdAt,warning:'Integrity/signature verification does not prove source truth, source permissions, clock accuracy, or compliance.'};
}
