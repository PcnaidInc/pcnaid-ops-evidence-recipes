import fs from 'node:fs/promises';
import path from 'node:path';
import {assert, parseJSON, pretty, uid} from './data.mjs';

export async function readText(file, max = 20 * 1024 * 1024) {
  const stat = await fs.lstat(file);
  assert(stat.isFile() && !stat.isSymbolicLink(), 'Input must be a regular, non-symlink file');
  assert(stat.size <= max, `Input exceeds ${max} bytes`);
  return fs.readFile(file, 'utf8');
}

export async function readJSON(file) {
  return parseJSON(await readText(file), path.basename(file));
}

export async function safeParent(file) {
  const dir = path.dirname(path.resolve(file));
  let cursor = path.parse(dir).root;
  for (const bit of dir.slice(cursor.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, bit);
    try {
      const s = await fs.lstat(cursor);
      assert(s.isDirectory() && !s.isSymbolicLink(), 'Output path contains a symlink or non-directory');
    } catch (e) {
      if (e.code === 'ENOENT') await fs.mkdir(cursor, {mode: 0o700});
      else throw e;
    }
  }
}

export async function writeFile(file, data, force = false) {
  await safeParent(file);
  if (!force) {
    await fs.writeFile(file, data, {flag: 'wx', mode: 0o600});
    return;
  }
  try {
    const s = await fs.lstat(file);
    assert(s.isFile() && !statIsSymlink(s), 'Refusing to replace a symlink/non-file');
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  const temporary = file + '.' + uid() + '.tmp';
  await fs.writeFile(temporary, data, {flag: 'wx', mode: 0o600});
  try {
    await fs.rename(temporary, file);
  } finally {
    await fs.rm(temporary, {force: true});
  }
}

function statIsSymlink(s) {
  return s.isSymbolicLink();
}

export async function writeJSON(file, value, force = false) {
  await writeFile(file, pretty(value), force);
}
