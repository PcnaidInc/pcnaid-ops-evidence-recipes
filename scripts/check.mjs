import {spawnSync} from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

async function scan(dir){
  const entries=await fs.readdir(dir,{withFileTypes:true});
  const files=[];
  for(const e of entries){
    if(e.name==='node_modules'||e.name==='reports'||e.name==='.git')continue;
    const full=path.join(dir,e.name);
    if(e.isDirectory())files.push(...await scan(full));
    else if(e.name.endsWith('.mjs')||e.name.endsWith('.js')||e.name.endsWith('.json'))files.push(full);
  }
  return files;
}

const files=await scan(process.cwd());
let failed=0;
for(const f of files){
  if(f.endsWith('.mjs')||f.endsWith('.js')){
    const res=spawnSync(process.execPath,['--check',f],{stdio:'inherit'});
    if(res.status!==0){console.error('Check failed: '+f);failed++;}
  }else if(f.endsWith('.json')){
    try{JSON.parse(await fs.readFile(f,'utf8'));}
    catch(e){console.error('JSON invalid: '+f,e);failed++;}
  }
}
if(failed>0)process.exit(1);
console.log(`Checked ${files.length} files successfully.`);
