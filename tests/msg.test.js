// Outlook .msg files: the stored internet headers are read; corrupt and hostile files are refused quickly.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { C, F } = require('./helpers.js');
const { cfb, msg } = require('./cfb.js');
const ab = buf => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

test('reads UTF-16 headers stored in the mini stream', () => {
  const headers = 'From: a@example.com\r\nSubject: small\r\n';
  assert.equal(C.msgHeaders(ab(msg(headers))), headers);
});

test('reads UTF-16 headers large enough to sit in regular sectors', () => {
  const headers = F.m365({ extra: [`X-MS-Exchange-AntiSpam-MessageData-0: ${'QUJD'.repeat(400)}`] }).replace(/\n/g, '\r\n') + '\r\n';
  assert.ok(Buffer.byteLength(headers, 'utf16le') >= 4096);
  const out = C.msgHeaders(ab(msg(headers)));
  assert.equal(out, headers);
  assert.equal(C.analyze(out).boundary, 1);
});

test('reads 8-bit headers (007D001E)', () => {
  const headers = 'From: caf\u00E9@example.com\r\nSubject: eight bit\r\n';
  assert.equal(C.msgHeaders(ab(msg(headers, { wide: false }))), headers);
});

test('returns an empty string for a valid file with no internet headers, and never reads the body', () => {
  const file = cfb([{ name: '__substg1.0_1000001F', data: Buffer.from('secret body', 'utf16le') }]);
  assert.equal(C.msgHeaders(ab(file)), '');
});

test('returns null for files that are not compound files', () => {
  assert.equal(C.msgHeaders(new ArrayBuffer(0)), null);
  assert.equal(C.msgHeaders(ab(Buffer.from('From: a@example.com\r\n\r\nbody'.padEnd(600, 'x')))), null);
  assert.equal(C.msgHeaders(ab(Buffer.alloc(4096, 0xAB))), null);
});

// Each corruption below sets one header field or link to a hostile value. Every one must return null (or the
// headers, where the damage is outside what is read) without throwing, hanging or allocating the claimed size.
const corrupt = (mutate) => { const b = Buffer.from(msg(F.m365().replace(/\n/g, '\r\n'))); mutate(b); return ab(b); };
const cases = {
  'sector shift of 30 (a 1 GB sector)': b => b.writeUInt16LE(30, 30),
  'mini sector shift of 20': b => b.writeUInt16LE(20, 32),
  'mini stream cutoff of 0': b => b.writeUInt32LE(0, 56),
  'four billion FAT sectors': b => b.writeUInt32LE(0xFFFFFFF0, 44),
  'zero FAT sectors': b => b.writeUInt32LE(0, 44),
  'FAT sector beyond the file': b => b.writeUInt32LE(100000, 76),
  'directory start beyond the file': b => b.writeUInt32LE(90000, 48),
  'a DIFAT chain pointing at itself': b => { b.writeUInt32LE(3, 44); b.writeUInt32LE(1, 68); b.writeUInt32LE(1, 72); for (let i = 0; i < 127; i++) b.writeUInt32LE(0xFFFFFFFF, 1024 + i * 4); b.writeUInt32LE(1, 1024 + 508); },
  'a FAT that loops back on itself': b => { const fat = 512; for (let i = 1; i < 128; i++) b.writeUInt32LE(1, fat + i * 4); },
  'a stream size of 4 GB': b => { const dirAt = 512 * (b.readUInt32LE(48) + 1); for (let o = dirAt; o < dirAt + 512; o += 128) if (b[o + 66] === 2) b.writeUInt32LE(0xFFFFFFF0, o + 120); },
  'a root entry that is not a root': b => { b[512 * (b.readUInt32LE(48) + 1) + 66] = 2; },
  'a truncated file': null
};
for (const [name, mutate] of Object.entries(cases)) {
  test(`a corrupt .msg is refused quickly: ${name}`, () => {
    const input = mutate ? corrupt(mutate) : ab(msg(F.m365().replace(/\n/g, '\r\n')).subarray(0, 1536));
    const started = performance.now();
    let out;
    assert.doesNotThrow(() => { out = C.msgHeaders(input); });
    assert.ok(performance.now() - started < 500, 'took too long');
    assert.ok(out === null || typeof out === 'string');
    if (name !== 'a FAT that loops back on itself') assert.equal(out, null);
  });
}

test('random bytes after a valid signature never throw', () => {
  let seed = 7;
  const rand = () => (seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32;
  for (let n = 0; n < 200; n++) {
    const b = Buffer.from(msg('From: a@example.com\r\n'));
    for (let k = 0; k < 20; k++) b[512 + Math.floor(rand() * (b.length - 512))] = Math.floor(rand() * 256);
    if (n % 3 === 0) b.writeUInt32LE(Math.floor(rand() * 2 ** 32) >>> 0, 44 + 4 * Math.floor(rand() * 8));
    assert.doesNotThrow(() => C.msgHeaders(ab(b)));
  }
});
