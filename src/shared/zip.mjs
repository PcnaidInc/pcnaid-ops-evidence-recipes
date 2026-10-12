import {assert} from './data.mjs';
const table=Uint32Array.from({length:256},(_,n)=>{let c=n;for(let i=0;i<8;i++)c=c&1?0xedb88320^(c>>>1):c>>>1;return c>>>0;});
export function crc32(data){let c=0xffffffff;for(const byte of data)c=table[(c^byte)&255]^(c>>>8);return(c^0xffffffff)>>>0;}
function safeName(name){assert(typeof name==='string'&&/^[a-zA-Z0-9][a-zA-Z0-9._/-]{0,200}$/.test(name)&&name.split('/').every(p=>p&&p!=='.'&&p!=='..'),'Unsafe ZIP entry name');}

export function makeZip(files){
  const local=[],central=[];let offset=0,total=0;const seen=new Set();
  assert(Object.keys(files).length<=100,'Too many ZIP entries');
  for(const [name,value]of Object.entries(files).sort(([a],[b])=>a.localeCompare(b))){
    safeName(name);assert(!seen.has(name),'Duplicate ZIP entry');seen.add(name);
    const filename=Buffer.from(name),data=Buffer.isBuffer(value)?value:Buffer.from(value),crc=crc32(data);total+=data.length;assert(total<=25*1024*1024,'ZIP size limit exceeded');
    const header=Buffer.alloc(30);header.writeUInt32LE(0x04034b50,0);header.writeUInt16LE(20,4);header.writeUInt16LE(0x800,6);header.writeUInt16LE(0,8);header.writeUInt16LE(0x21,12);header.writeUInt32LE(crc,14);header.writeUInt32LE(data.length,18);header.writeUInt32LE(data.length,22);header.writeUInt16LE(filename.length,26);
    local.push(header,filename,data);
    const directory=Buffer.alloc(46);directory.writeUInt32LE(0x02014b50,0);directory.writeUInt16LE(20,4);directory.writeUInt16LE(20,6);directory.writeUInt16LE(0x800,8);directory.writeUInt16LE(0,10);directory.writeUInt16LE(0x21,14);directory.writeUInt32LE(crc,16);directory.writeUInt32LE(data.length,20);directory.writeUInt32LE(data.length,24);directory.writeUInt16LE(filename.length,28);directory.writeUInt32LE(offset,42);central.push(directory,filename);offset+=header.length+filename.length+data.length;
  }
  const c=Buffer.concat(central),end=Buffer.alloc(22);end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(seen.size,8);end.writeUInt16LE(seen.size,10);end.writeUInt32LE(c.length,12);end.writeUInt32LE(offset,16);
  return Buffer.concat([...local,c,end]);
}

export function readZip(bytes){
  assert(Buffer.isBuffer(bytes)&&bytes.length>=22&&bytes.length<=26*1024*1024,'Invalid or oversized ZIP');
  const end=bytes.length-22;assert(bytes.readUInt32LE(end)===0x06054b50,'Only un-commented Pcnaid ZIP packets are supported');
  assert(bytes.readUInt16LE(end+4)===0&&bytes.readUInt16LE(end+6)===0,'Multi-disk ZIP is unsupported');
  const count=bytes.readUInt16LE(end+10),length=bytes.readUInt32LE(end+12),start=bytes.readUInt32LE(end+16);assert(count===bytes.readUInt16LE(end+8)&&count<=100&&start+length===end,'Invalid ZIP directory');
  const files=new Map();let p=start,expectedOffset=0,total=0;
  for(let i=0;i<count;i++){
    assert(p+46<=end&&bytes.readUInt32LE(p)===0x02014b50,'Invalid ZIP directory entry');
    const flags=bytes.readUInt16LE(p+8),method=bytes.readUInt16LE(p+10),crc=bytes.readUInt32LE(p+16),packed=bytes.readUInt32LE(p+20),size=bytes.readUInt32LE(p+24),nl=bytes.readUInt16LE(p+28),el=bytes.readUInt16LE(p+30),cl=bytes.readUInt16LE(p+32),offset=bytes.readUInt32LE(p+42);
    assert(flags===0x800&&method===0&&packed===size&&el===0&&cl===0&&bytes.readUInt16LE(p+34)===0,'Only simple unencrypted ZIP STORE packets are supported');
    assert(p+46+nl<=end,'Truncated ZIP name');const name=bytes.subarray(p+46,p+46+nl).toString('utf8');safeName(name);assert(!files.has(name),'Duplicate ZIP entry');
    assert(offset===expectedOffset&&offset+30<=start&&bytes.readUInt32LE(offset)===0x04034b50,'Invalid/overlapping ZIP local header');
    assert(bytes.readUInt16LE(offset+6)===flags&&bytes.readUInt16LE(offset+8)===method&&bytes.readUInt32LE(offset+14)===crc&&bytes.readUInt32LE(offset+18)===size&&bytes.readUInt32LE(offset+22)===size&&bytes.readUInt16LE(offset+26)===nl&&bytes.readUInt16LE(offset+28)===0,'ZIP header mismatch');
    assert(bytes.subarray(offset+30,offset+30+nl).toString('utf8')===name,'ZIP local filename mismatch');
    const from=offset+30+nl,to=from+size;assert(to<=start,'Truncated ZIP content');const data=bytes.subarray(from,to);assert(crc32(data)===crc,`ZIP CRC mismatch: ${name}`);total+=size;assert(total<=25*1024*1024,'ZIP output limit exceeded');files.set(name,data);expectedOffset=to;p+=46+nl;
  }
  assert(expectedOffset===start&&p===end,'Unexpected ZIP data');return files;
}
