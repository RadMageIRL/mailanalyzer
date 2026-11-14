// A minimal writer for OLE compound files (the container Outlook .msg files use), so the tests can build .msg
// files with known contents instead of shipping real messages. Version 3 layout: 512-byte sectors, one FAT sector,
// streams under 4096 bytes in the mini stream. The directory is a simple right-leaning tree.
// SPDX-License-Identifier: MIT
'use strict';
const SS = 512, END = 0xFFFFFFFE, FREE = 0xFFFFFFFF, FATSECT = 0xFFFFFFFD, NOSTREAM = 0xFFFFFFFF;

function cfb(streams) {
  const sectors = [null], fat = [FATSECT]; // sector 0 holds the FAT, filled in at the end
  const alloc = buf => {
    const n = Math.ceil(buf.length / SS);
    if (!n) return END;
    const start = sectors.length;
    for (let i = 0; i < n; i++) { const b = Buffer.alloc(SS); buf.copy(b, 0, i * SS, Math.min(buf.length, (i + 1) * SS)); sectors.push(b); fat.push(i === n - 1 ? END : start + i + 1); }
    return start;
  };
  const mini = [], miniFat = [], entries = [{ name: 'Root Entry', type: 5 }];
  for (const s of streams) {
    const data = Buffer.from(s.data);
    if (data.length < 4096) {
      const n = Math.ceil(data.length / 64), start = mini.length / 64;
      for (let i = 0; i < n; i++) { const b = Buffer.alloc(64); data.copy(b, 0, i * 64, Math.min(data.length, (i + 1) * 64)); mini.push(...b); miniFat.push(i === n - 1 ? END : start + i + 1); }
      entries.push({ name: s.name, type: 2, start: n ? start : END, size: data.length });
    } else entries.push({ name: s.name, type: 2, start: alloc(data), size: data.length });
  }
  const miniBuf = Buffer.from(mini);
  entries[0].start = alloc(miniBuf); entries[0].size = miniBuf.length;
  const mf = Buffer.alloc(Math.max(1, miniFat.length) * 4, 0xff); miniFat.forEach((v, i) => mf.writeUInt32LE(v, i * 4));
  const miniFatStart = miniFat.length ? alloc(mf) : END;
  const dir = Buffer.alloc(Math.ceil(entries.length / 4) * 4 * 128);
  entries.forEach((e, i) => {
    const o = i * 128, name = Buffer.from(`${e.name}\0`, 'utf16le');
    name.copy(dir, o); dir.writeUInt16LE(name.length, o + 64); dir[o + 66] = e.type; dir[o + 67] = 1;
    dir.writeUInt32LE(NOSTREAM, o + 68); dir.writeUInt32LE(i > 0 && i < entries.length - 1 ? i + 1 : NOSTREAM, o + 72); dir.writeUInt32LE(i === 0 && entries.length > 1 ? 1 : NOSTREAM, o + 76);
    dir.writeUInt32LE(e.start ?? END, o + 116); dir.writeUInt32LE(e.size ?? 0, o + 120);
  });
  for (let o = entries.length * 128; o < dir.length; o += 128) { dir.writeUInt32LE(NOSTREAM, o + 68); dir.writeUInt32LE(NOSTREAM, o + 72); dir.writeUInt32LE(NOSTREAM, o + 76); }
  const dirStart = alloc(dir);
  if (fat.length > SS / 4) throw new Error('test file too large for one FAT sector');
  const fatBuf = Buffer.alloc(SS, 0xff); fat.forEach((v, i) => fatBuf.writeUInt32LE(v, i * 4));
  sectors[0] = fatBuf;
  const h = Buffer.alloc(SS);
  Buffer.from('D0CF11E0A1B11AE1', 'hex').copy(h, 0);
  h.writeUInt16LE(0x3E, 24); h.writeUInt16LE(3, 26); h.writeUInt16LE(0xFFFE, 28); h.writeUInt16LE(9, 30); h.writeUInt16LE(6, 32);
  h.writeUInt32LE(1, 44); h.writeUInt32LE(dirStart, 48); h.writeUInt32LE(4096, 56);
  h.writeUInt32LE(miniFatStart, 60); h.writeUInt32LE(miniFat.length ? Math.ceil(mf.length / SS) : 0, 64);
  h.writeUInt32LE(END, 68); h.writeUInt32LE(0, 72);
  for (let i = 0; i < 109; i++) h.writeUInt32LE(i === 0 ? 0 : FREE, 76 + i * 4);
  return Buffer.concat([h, ...sectors]);
}

/** An .msg holding `headers` as PR_TRANSPORT_MESSAGE_HEADERS (UTF-16 by default), plus a body stream. */
function msg(headers, { wide = true, body = 'This is the message body and must never be read.' } = {}) {
  return cfb([
    { name: '__substg1.0_1000001F', data: Buffer.from(body, 'utf16le') },
    { name: wide ? '__substg1.0_007D001F' : '__substg1.0_007D001E', data: wide ? Buffer.from(headers, 'utf16le') : Buffer.from(headers, 'latin1') }
  ]);
}

module.exports = { cfb, msg, SS };
