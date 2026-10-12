import {createHash, randomUUID} from 'node:crypto';
export const VERSION = '0.1.0';
export class InputError extends Error { constructor(message) { super(message); this.name = 'InputError'; } }
export function assert(condition, message) { if (!condition) throw new InputError(message); }
export const isObject = value => !!value && typeof value === 'object' && !Array.isArray(value);
export function object(value, name) { assert(isObject(value), `${name} must be an object`); return value; }
export function string(value, name, max = 2000) {
  assert(typeof value === 'string' && value.trim().length > 0 && value.length <= max, `${name} must be nonempty text (max ${max})`);
  assert(!/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(value), `${name} contains control characters`);
  return value.trim();
}
export function array(value, name, max = 10000) { assert(Array.isArray(value) && value.length <= max, `${name} must be an array (max ${max})`); return value; }
export function enumValue(value, choices, name) { assert(choices.includes(value), `${name} must be one of ${choices.join(', ')}`); return value; }
export function timestamp(value, name = 'timestamp') {
  string(value, name, 50);
  assert(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/.test(value) && Number.isFinite(Date.parse(value)), `${name} must be an ISO 8601 timestamp with timezone`);
  const [year,month,day]=value.slice(0,10).split('-').map(Number);
  const days=new Date(Date.UTC(year,month,0)).getUTCDate();
  assert(month>=1&&month<=12&&day>=1&&day<=days&&Number(value.slice(11,13))<24&&Number(value.slice(14,16))<60&&Number(value.slice(17,19))<60, `${name} contains an invalid calendar date/time`);
  return new Date(value).toISOString();
}
export function parseJSON(text, name = 'JSON') {
  assert(typeof text === 'string' && Buffer.byteLength(text) <= 20 * 1024 * 1024, `${name}: maximum 20 MiB`);
  try {
    let nodes = 0;
    return JSON.parse(text.replace(/^\uFEFF/, ''), (key, value) => {
      if (++nodes > 200000) throw new InputError('Too many JSON values');
      if (['__proto__', 'prototype', 'constructor'].includes(key)) throw new InputError(`Unsafe JSON key: ${key}`);
      return value;
    });
  } catch (e) { if (e instanceof InputError) throw e; throw new InputError(`${name}: invalid JSON`); }
}
export function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (isObject(value)) return Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])]));
  assert(value !== undefined && !(typeof value === 'number' && !Number.isFinite(value)), 'Non-JSON value');
  return value;
}
export const canonical = value => JSON.stringify(stable(value));
export const sha256 = value => createHash('sha256').update(typeof value === 'string' || Buffer.isBuffer(value) ? value : canonical(value)).digest('hex');
export const pretty = value => JSON.stringify(value, null, 2) + '\n';
export const uid = () => randomUUID();
export const escapeHTML = value => String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export function uniqueBy(items, name) { const seen = new Set(); for (const i of items) { assert(!seen.has(i.id), `Duplicate ${name} ID: ${i.id}`); seen.add(i.id); } }
export function noExtra(value, allowed, name) { for (const k of Object.keys(value)) assert(allowed.includes(k), `Unsupported ${name} field: ${k}`); }
export function pointer(value, path) {
  assert(typeof path === 'string' && (path === '' || path.startsWith('/')) && path.length <= 500, 'Expected RFC 6901 JSON pointer');
  if (path === '') return value;
  for (const raw of path.slice(1).split('/')) {
    assert(!/~(?![01])/u.test(raw), 'Invalid JSON pointer escape');
    const key = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    assert(!['__proto__','prototype','constructor'].includes(key), 'Unsafe JSON pointer');
    if (value === null || typeof value !== 'object' || !Object.hasOwn(value, key)) return undefined;
    value = value[key];
  }
  return value;
}
export function sanitize(value, depth = 0) {
  assert(depth <= 50, 'Data nesting is too deep');
  if (Array.isArray(value)) return value.map(x => sanitize(x, depth + 1));
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([k, v]) => [k,
    /^(?:password|passwd|secret|client_secret|access_?token|refresh_?token|api_?key|authorization|cookie|set-cookie|private_?key|credential|connectionstring|sas_?token)$/i.test(k)
      ? '[REDACTED]' : sanitize(v, depth + 1)]));
  if (typeof value === 'string') return value
    .replace(/-----BEGIN [\w ]*PRIVATE KEY-----[\s\S]*?-----END [\w ]*PRIVATE KEY-----/g, '[REDACTED]')
    .replace(/\bBearer\s+[^\s"']+/gi, 'Bearer [REDACTED]')
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk_live_[A-Za-z0-9]{12,})\b/g, '[REDACTED]')
    .replace(/https?:\/\/[^\s"<>]+/g, raw => { try { const u = new URL(raw); u.username=''; u.password=''; if(u.search)u.search='?REDACTED'; u.hash=''; return u.href; } catch { return '[REDACTED URL]'; } });
  return value;
}
export function endpointReference(raw) {
  if (!raw) return null;
  try { const u = new URL(raw); assert(['https:','http:'].includes(u.protocol), 'HTTP endpoint expected'); return `${u.origin}/[path-redacted]`; }
  catch { return '[endpoint reference withheld]'; }
}
export function csv(rows, headers) {
  const cell = value => { let text = String(value ?? ''); if (/^[\s]*[=+@\-]/.test(text) || /^[\t\r\n]/.test(text)) text = "'" + text; return '"'+text.replace(/"/g,'""')+'"'; };
  return '\uFEFF' + [headers, ...rows.map(r => headers.map(h => r[h]))].map(r => r.map(cell).join(',')).join('\r\n')+'\r\n';
}
export function parseCSV(text) {
  assert(typeof text === 'string' && Buffer.byteLength(text) <= 10*1024*1024, 'CSV maximum 10 MiB');
  text = text.replace(/^\uFEFF/,'');
  const rows=[]; let row=[], value='', quoted=false, closed=false;
  for(let i=0;i<text.length;i++) {
    const c=text[i];
    if(quoted) { if(c==='"') { if(text[i+1]==='"'){value+='"';i++;} else {quoted=false;closed=true;} } else value+=c; }
    else if(c==='"') { assert(!value && !closed, 'Malformed CSV quote'); quoted=true; }
    else if(c===',' || c==='\n' || c==='\r') {
      row.push(value);value='';closed=false;
      if(c!==','){ if(c==='\r'&&text[i+1]==='\n')i++; if(row.some(v=>v!==''))rows.push(row);row=[]; }
    } else { assert(!closed || c===' ', 'Unexpected character after CSV quote'); if(!closed)value+=c; }
    assert(value.length <= 10000 && rows.length <= 10000 && row.length<=100, 'CSV limits exceeded');
  }
  assert(!quoted, 'Unterminated CSV quote');
  row.push(value);if(row.some(v=>v!==''))rows.push(row);
  assert(rows.length>0, 'CSV is empty');
  const keys=rows.shift().map(k=>k.trim().toLowerCase().replace(/[\s_-]+/g,' '));
  assert(keys.every(k=>k && !['__proto__','prototype','constructor'].includes(k))&&new Set(keys).size===keys.length,'Invalid or duplicate CSV headers');
  return rows.map((r,i)=>{assert(r.length===keys.length,`CSV row ${i+2}: expected ${keys.length} columns`);return Object.fromEntries(keys.map((k,j)=>[k,r[j]]));});
}
