// The release build. Copies exactly the files the site serves into dist/site/, and packages the files needed to run
// MailAnalyzer locally into dist/MailAnalyzer-v<version>.zip with dist/SHA256SUMS.txt. The output is byte-for-byte
// reproducible: files are stored uncompressed with one fixed timestamp, in a fixed order.
//
//   node tools/build.mjs            build dist/
//   node tools/build.mjs --verify   also prove two more builds are identical and the zip holds the source files
//
// SPDX-License-Identifier: MIT
import { mkdirSync, rmSync, readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const { VERSION } = createRequire(import.meta.url)(join(ROOT, 'mailanalyzer-core.js'));

/** The files the site is made of. Nothing else is published. */
export const SITE_FILES = ['index.html', 'mailanalyzer-core.js', 'app.js'];
/** The release zip: the page and its scripts, plus the license (which must travel with the code) and the README. */
export const ZIP_FILES = [...SITE_FILES, 'LICENSE', 'README.md'];
export const ZIP_NAME = `MailAnalyzer-v${VERSION}.zip`;
export const ZIP_DIR = `MailAnalyzer-v${VERSION}/`;
// 2026-11-14 00:00:00 in MS-DOS date/time form, the release date. Every entry carries it.
const DOS_TIME = 0, DOS_DATE = ((2026 - 1980) << 9) | (11 << 5) | 14;

const sha256 = b => createHash('sha256').update(b).digest('hex');
const CRC_TABLE = (() => { const t = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; } return t; })();
function crc32(buf) { let c = 0xffffffff; for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }

/** A stored (uncompressed) zip with fixed metadata, so the same files always give the same bytes. */
export function makeZip(entries) {
  const locals = [], centrals = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, 'utf8'), crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(10, 4); local.writeUInt16LE(0x0800, 6); local.writeUInt16LE(0, 8);
    local.writeUInt16LE(DOS_TIME, 10); local.writeUInt16LE(DOS_DATE, 12); local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(nameBuf.length, 26); local.writeUInt16LE(0, 28);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE((3 << 8) | 20, 4); central.writeUInt16LE(10, 6); central.writeUInt16LE(0x0800, 8); central.writeUInt16LE(0, 10);
    central.writeUInt16LE(DOS_TIME, 12); central.writeUInt16LE(DOS_DATE, 14); central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt16LE(0, 30); central.writeUInt16LE(0, 32); central.writeUInt16LE(0, 34); central.writeUInt16LE(0, 36);
    central.writeUInt32LE(((name.endsWith('/') ? 0o040755 : 0o100644) << 16) >>> 0, 38); central.writeUInt32LE(offset, 42);
    locals.push(local, nameBuf, data); centrals.push(central, nameBuf);
    offset += local.length + nameBuf.length + data.length;
  }
  const cd = Buffer.concat(centrals), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

/** Reads a zip made by makeZip (stored entries only) back into { name: Buffer }, checking every CRC. */
export function readZip(buf) {
  const out = {};
  const endAt = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  if (endAt < 0) throw new Error('no end of central directory');
  let p = buf.readUInt32LE(endAt + 16);
  const count = buf.readUInt16LE(endAt + 10);
  for (let i = 0; i < count; i++) {
    if (buf.readUInt32LE(p) !== 0x02014b50) throw new Error('bad central directory');
    const method = buf.readUInt16LE(p + 10), crc = buf.readUInt32LE(p + 16), size = buf.readUInt32LE(p + 24), nameLen = buf.readUInt16LE(p + 28), extra = buf.readUInt16LE(p + 30), comment = buf.readUInt16LE(p + 32), at = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    if (method !== 0) throw new Error(`${name} is compressed`);
    const dataAt = at + 30 + buf.readUInt16LE(at + 26) + buf.readUInt16LE(at + 28), data = buf.subarray(dataAt, dataAt + size);
    if (crc32(data) !== crc) throw new Error(`${name}: CRC mismatch`);
    out[name] = data;
    p += 46 + nameLen + extra + comment;
  }
  return out;
}

export function build(outDir = join(ROOT, 'dist')) {
  const html = readFileSync(join(ROOT, 'index.html'), 'utf8');
  const scripts = [...html.matchAll(/<script src="([^"?]+)(?:\?[^"]*)?"><\/script>/g)].map(m => m[1]);
  const listed = SITE_FILES.filter(f => f.endsWith('.js'));
  if (JSON.stringify(scripts) !== JSON.stringify(listed)) throw new Error(`index.html loads ${scripts.join(', ')} but SITE_FILES lists ${listed.join(', ')}`);
  rmSync(outDir, { recursive: true, force: true });
  mkdirSync(join(outDir, 'site'), { recursive: true });
  const manifest = [];
  for (const f of SITE_FILES) {
    const body = readFileSync(join(ROOT, f));
    if (body.includes(13)) throw new Error(`${f} has CRLF line endings`);
    writeFileSync(join(outDir, 'site', f), body);
    manifest.push(`${sha256(body)}  site/${f}`);
  }
  const zip = makeZip([{ name: ZIP_DIR, data: Buffer.alloc(0) }, ...ZIP_FILES.map(f => { const data = readFileSync(join(ROOT, f)); if (data.includes(13)) throw new Error(`${f} has CRLF line endings`); return { name: ZIP_DIR + f, data }; })]);
  writeFileSync(join(outDir, ZIP_NAME), zip);
  const sums = `${sha256(zip)}  ${ZIP_NAME}\n`;
  writeFileSync(join(outDir, 'SHA256SUMS.txt'), sums);
  manifest.push(`${sha256(zip)}  ${ZIP_NAME}`);
  return { outDir, manifest, zip };
}

/** Confirms the zip holds exactly ZIP_FILES with the same bytes as the working tree. */
export function verifyZip(zip) {
  const files = readZip(zip), names = Object.keys(files);
  const want = [ZIP_DIR, ...ZIP_FILES.map(f => ZIP_DIR + f)];
  if (JSON.stringify(names) !== JSON.stringify(want)) throw new Error(`zip holds ${names.join(', ')}`);
  for (const f of ZIP_FILES) if (!files[ZIP_DIR + f].equals(readFileSync(join(ROOT, f)))) throw new Error(`${f} in the zip differs from the source`);
  return names.length;
}

if (process.argv[1] && process.argv[1].endsWith('build.mjs')) {
  try {
    const { outDir, manifest, zip } = build();
    console.log(`Built ${outDir}:\n${manifest.join('\n')}`);
    if (process.argv.includes('--verify')) {
      const a = build(mkdtempSync(join(tmpdir(), 'mailanalyzer-build-a-'))), b = build(mkdtempSync(join(tmpdir(), 'mailanalyzer-build-b-')));
      for (const d of [a.outDir, b.outDir]) rmSync(d, { recursive: true, force: true });
      if (a.manifest.join('\n') !== manifest.join('\n') || b.manifest.join('\n') !== manifest.join('\n')) { console.error('Two builds differ.'); process.exit(1); }
      console.log(`Reproducible: three builds produced identical files. The zip holds ${verifyZip(zip)} entries matching the source.`);
    }
  } catch (e) {
    console.error(e.message);
    process.exit(1);
  }
}
