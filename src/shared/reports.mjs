import {escapeHTML as e, pretty, csv, sha256, assert} from './data.mjs';
import {evidencePacket} from '../evidence/runner.mjs';

export const label=s=>String(s).replace(/_/g,' ');
const badge=s=>`<span class="badge ${e(s)}">${e(label(s))}</span>`;
const list=items=>`<ul>${items.map(i=>`<li>${e(i)}</li>`).join('')}</ul>`;

export function reportTable(headers,rows){
  return `<div class="table-wrap"><table><thead><tr>${headers.map(h=>`<th>${e(h)}</th>`).join('')}</tr></thead><tbody>${rows.length?rows.map(r=>`<tr>${r.map(v=>`<td>${v}</td>`).join('')}</tr>`).join(''):`<tr><td colspan="${headers.length}">No entries in the supplied data. This does not establish complete coverage.</td></tr>`}</tbody></table></div>`;
}

export function reportBody(r){
  if(r.kind==='evidence')return `<h2>Recipe observations</h2><p><strong>Origin:</strong> ${e(r.origin)} · <strong>Result:</strong> ${badge(r.summary.result)}</p>${reportTable(['Selected field','Observed value'],Object.entries(r.fields).map(([k,v])=>[e(k),`<code>${e(JSON.stringify(v))}</code>`]))}<h2>Checks</h2>${reportTable(['Check','Result','Explanation'],r.checks.map(c=>[e(c.description),badge(c.status),e(c.reason??`Operator: ${c.operator}; expected: ${JSON.stringify(c.expected)}`)]))}<h2>Provenance</h2><p>Recipe: ${e(r.recipeId)}</p><code class="hash">Recipe SHA-256: ${e(r.recipeSha256)}</code><code class="hash">Input SHA-256: ${e(r.inputSha256)}</code><p>Only selected fields are included. Raw responses and API credentials are not included.</p>`;
  throw new Error('Unsupported report kind');
}

export function renderReport(r){
  assert(r.kind==='evidence','Unsupported report kind');
  const title='Evidence observation packet';
  const name=r.recipeName;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"><title>${e(title)} — Pcnaid</title><style>
:root{font-family:Arial,Helvetica,sans-serif;color:#172434;background:#f4f6fa;font-size:15px;line-height:1.55}body{margin:0}main{max-width:1100px;margin:38px auto;background:#fff;padding:42px;border:1px solid #dbe2eb;border-radius:16px}header{border-bottom:3px solid #003da5;padding-bottom:24px;margin-bottom:30px}.brand{font-size:17px;letter-spacing:.12em;font-weight:800;color:#003da5}h1{font-size:34px;line-height:1.15;margin:16px 0}h2{font-size:22px;margin:30px 0 14px}h3{font-size:17px}p{margin:10px 0}small{display:block;color:#526174;font-size:12px;overflow-wrap:anywhere}code{font-size:12px}.hash{display:block;overflow-wrap:anywhere;color:#526174;margin:8px 0}.notice{background:#edf3fd;border-left:4px solid #003da5;padding:16px 20px;margin:24px 0}.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px;text-align:left}th{background:#f2f5f9;font-size:12px;text-transform:uppercase;letter-spacing:.035em;color:#526174}td,th{padding:13px 12px;border-bottom:1px solid #dbe2eb;vertical-align:top}td{overflow-wrap:anywhere}article{padding:22px 0;border-bottom:1px solid #dbe2eb;break-inside:avoid}.badge{display:inline-block;font-size:11px;line-height:1.3;font-weight:700;text-transform:uppercase;padding:5px 8px;border-radius:4px;background:#eaf0f7;color:#314962;white-space:nowrap}.attention_required,.high,.fail,.migration_required{background:#ffebe8;color:#962d24}.unknown{background:#f1eafb;color:#614087}.medium,.review,.incomplete{background:#fff0d3;color:#7e530c}.documented,.routine,.pass{background:#e2f2e9;color:#225b3d}a{color:#003da5}li{margin:7px 0}footer{border-top:1px solid #dbe2eb;margin-top:30px;padding-top:18px;color:#526174;font-size:12px}@media(max-width:700px){main{margin:0;padding:22px;border:0;border-radius:0}h1{font-size:28px}}@media print{body{background:#fff}main{margin:0;max-width:none;border:0;padding:0}table{font-size:10px}td,th{padding:8px}a{color:inherit}h2{break-after:avoid}.table-wrap{overflow:visible}}
</style></head><body><main><header><div class="brand">PCNAID / OPERATIONS TOOLKIT</div><h1>${e(title)}</h1><p>${e(name)}</p><small>Generated ${e(r.generatedAt)} · Toolkit ${e(r.version)}</small></header><div class="notice">Narrow recipe observations, not a compliance certification or an auditor opinion.</div>${reportBody(r)}${r.warnings?.length?`<h2>Coverage warnings</h2>${list(r.warnings)}`:''}<h2>Interpretation limits</h2>${list(r.limitations??[])}<footer>Pcnaid Inc. · Venture With Confidence.<br>Review this packet for confidential information before sharing. Print from your browser to create a PDF.</footer></main></body></html>`;
}

export function csvReport(r){
  assert(r.kind==='evidence','Unsupported report kind');
  return csv(r.checks,['id','field','operator','expected','status','reason','description']);
}

export function packet(r,options={}){
  assert(r.kind==='evidence','Unsupported report kind');
  const html=renderReport(r);
  return evidencePacket(r,html,options);
}
