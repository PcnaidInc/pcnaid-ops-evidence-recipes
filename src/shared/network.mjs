import https from 'node:https';
import {lookup} from 'node:dns/promises';
import net from 'node:net';
import {assert, InputError, parseJSON} from './data.mjs';

export function isPublicAddress(address){
  if(net.isIPv4(address)){
    const p=address.split('.').map(Number),[a,b,c]=p;
    if(a===0||a===10||a===127||a>=224||a===169&&b===254||a===172&&b>=16&&b<=31||a===192&&b===168||a===100&&b>=64&&b<=127||a===198&&[18,19].includes(b)||a===192&&b===0||a===192&&b===88&&c===99||a===198&&b===51&&c===100||a===203&&b===0&&c===113)return false;
    return true;
  }
  if(net.isIPv6(address)){
    const s=address.toLowerCase();
    return /^[23][0-9a-f]{3}:/.test(s)&&!/^2001:(?:0:|0000:|db8:|0db8:|[01]?[0-9a-f]{1,2}:)/.test(s)&&!s.startsWith('2002:')&&!s.startsWith('3fff:')&&!s.includes('.');
  }
  return false;
}

export function validateURL(raw,allowedHosts){
  let url;
  try{url=new URL(raw);}catch{throw new InputError('Invalid URL');}
  assert(url.protocol==='https:'&&!url.username&&!url.password&&!url.hash&&(!url.port||url.port==='443'),'Only credential-free HTTPS URLs on port 443 are permitted');
  assert(!net.isIP(url.hostname)&&!url.hostname.endsWith('.')&&allowedHosts.includes(url.hostname),'Host is not on the exact approved hostname list');
  assert(!/[\r\n]/.test(raw)&&raw.length<=3000,'Invalid URL length/control characters');
  return url;
}

const delay=ms=>new Promise(resolve=>setTimeout(resolve,ms));

export async function getJSON(raw,{allowedHosts=[],token=null,timeoutMs=15000,maxBytes=5*1024*1024,retries=2,headers={}}={}){
  const url=validateURL(raw,allowedHosts);
  assert(token===null||typeof token==='string'&&!/[\r\n]/.test(token),'Invalid credential');
  for(let attempt=0;attempt<=retries;attempt++){
    const addresses=await lookup(url.hostname,{all:true,verbatim:true});
    assert(addresses.length>0&&addresses.every(x=>isPublicAddress(x.address)),'DNS returned a non-public address; request blocked');
    const chosen=addresses[0];
    const response=await new Promise((resolve,reject)=>{
      const req=https.request(url,{method:'GET',agent:false,servername:url.hostname,headers:{Accept:'application/json','Accept-Encoding':'identity','User-Agent':'Pcnaid-Evidence-Recipes/0.1.0',...headers,...(token?{Authorization:`Bearer ${token}`}:{})},lookup:(_hostname,opts,cb)=>{if(opts?.all)cb(null,[chosen]);else cb(null,chosen.address,chosen.family);}},res=>{
        let size=0;const parts=[];
        res.on('data',chunk=>{size+=chunk.length;if(size>maxBytes){res.destroy();req.destroy(new InputError('Response exceeds maximum size'));}else parts.push(chunk);});
        res.on('error',reject);
        res.on('end',()=>resolve({status:res.statusCode,headers:res.headers,body:Buffer.concat(parts)}));
      });
      const timer=setTimeout(()=>req.destroy(new InputError('Request deadline exceeded')),timeoutMs);
      req.on('close',()=>clearTimeout(timer));
      req.on('error',()=>reject(new InputError('HTTPS request failed or exceeded its limits; no credentials were logged')));
      req.end();
    });
    if([429,502,503,504].includes(response.status)&&attempt<retries){
      const wait=Number(response.headers['retry-after']);
      await delay(Number.isFinite(wait)&&wait>0?Math.min(wait*1000,3000):250*2**attempt);
      continue;
    }
    assert(response.status>=200&&response.status<300,`Source HTTP ${response.status}; redirects are not followed`);
    const type=String(response.headers['content-type']??'');
    assert(/(?:application\/json|\+json)(?:;|$)/i.test(type),'Expected JSON Content-Type');
    return {data:parseJSON(response.body.toString('utf8'),'source response'),rawBytes:response.body,status:response.status,etag:typeof response.headers.etag==='string'?response.headers.etag:null};
  }
  throw new InputError('Request retry limit exceeded');
}
