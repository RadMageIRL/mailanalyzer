// Malformed, oversized and pathological input. Each crafted shape below took seconds or longer before the release
// fixes (quadratic regex or scan); the budget is far above linear time and far below what a regression would cost.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { C, F, analyze, has } = require('./helpers.js');
const day = 'Tue, 10 Nov 2026 09:00:00 +0000';
const BUDGET_MS = 1500;
const N = 64 * 1024;

const shapes = {
  'blank lines between X- headers': `Received: from a by b; ${day}\n` + 'X-A: 1\n\n'.repeat(150000),
  'a 64 KB word in Authentication-Results': `Received: from a by b; ${day}\nAuthentication-Results: spf=pass ${'a'.repeat(N)}\nFrom: x@example.com`,
  'a 64 KB From with no @': `Received: from a by b; ${day}\nFrom: ${'a'.repeat(N)}`,
  'a From full of quotes, parentheses and angle brackets': `Received: from a by b; ${day}\nFrom: ${'"(<'.repeat(N / 3)}`,
  'a From full of encoded-word starts': `Received: from a by b; ${day}\nFrom: ${'=?'.repeat(N / 2)}`,
  'a Received full of "from (" with no closing parenthesis': `Received: ${'from ( '.repeat(N / 7)}by b; ${day}`,
  'a Received full of "with "': `Received: from a by b ${'with '.repeat(N / 5)}; ${day}`,
  'a Received-SPF full of parentheses': `Received: from a by b; ${day}\nReceived-SPF: Pass ${'('.repeat(N)}\nFrom: x@example.com`,
  'an X-Spam-Status full of tests=': `Received: from a by b; ${day}\nX-Spam-Status: Yes, ${'tests='.repeat(N / 6)}\nFrom: x@example.com`,
  'a Subject full of invisible characters': `Received: from a by b; ${day}\nSubject: ${'\u200B\u202E'.repeat(N / 2)}\nFrom: x@example.com`,
  'a long punycode label': `Received: from a by b; ${day}\nFrom: a` + '@xn--' + `${'a'.repeat(5000)}.test`,
  'a 64 KB Date header': `Received: from a by b; ${day}\nDate: ${'1 '.repeat(N / 2)}\nFrom: x@example.com`,
  'many address separators in To': `Received: from a by b; ${day}\nFrom: x@example.com\nTo: ${'a@b,'.repeat(N / 4)}`,
  'Received lines with "with x" and long runs of blanks (review finding 4)': Array.from({ length: 15 }, () => `Received: from a by b with x${' '.repeat(N - 100)}z; ${day}`).join('\n'),
  'long runs of blanks in every parsed header': `Received: from a${' '.repeat(N - 50)}(x by b; ${day}\nAuthentication-Results: spf=pass${' '.repeat(N - 50)}x\nReceived-SPF: Pass${' '.repeat(N - 50)}(\nFrom: a${' '.repeat(N - 50)}b\nDate: 1${' '.repeat(N - 50)}2\nX-Spam-Status: Yes${' '.repeat(N - 50)}tests=`,
  'thousands of DKIM signatures and results (review finding 5)': `Received: from a by b; ${day}\nAuthentication-Results: x; ${'dkim=pass header.d=example.com; '.repeat(1500)}\n` + 'DKIM-Signature: v=1; d=example.org; s=s; h=to; bh=x; b=y\n'.repeat(3000),
  '5000 Received headers':Array.from({ length: 5000 }, (_, i) => `Received: from h${i}.example.org (198.51.100.${i % 250}) by h${i + 1}.example.org with SMTP; ${day}`).join('\n')
};
for (const [name, text] of Object.entries(shapes)) {
  test(`stays fast on ${name}`, () => {
    const started = performance.now();
    const r = analyze(text);
    const report = r ? C.buildReport(r, { redact: true, subject: false, notes: true, raw: true }) : '';
    const ms = performance.now() - started;
    assert.ok(ms < BUDGET_MS, `${Math.round(ms)} ms`);
    assert.ok(r === null || Array.isArray(r.findings));
    assert.equal(typeof report, 'string');
  });
}

test('masking a report stays fast on a long run of address characters with no @', () => {
  const started = performance.now();
  const out = C.mask(`${'a.'.repeat(N)} and ${'b'.repeat(N)} then j@example.com`);
  assert.ok(performance.now() - started < BUDGET_MS);
  assert.ok(out.endsWith('j***@example.com'));
});

test('a header block past 1 MB is cut there, and the analysis says so', () => {
  const r = analyze(`Received: from a by b; ${day}\n` + `X-Pad: ${'x'.repeat(1000)}\n`.repeat(1100));
  assert.equal(r.truncated, true);
  assert.ok(r.block.length <= C.LIMITS.blockChars);
  assert.ok(has(r, /^Only part of the input was read/));
});

test('more than 5000 headers are cut at 5000', () => {
  const r = analyze(Array.from({ length: 6000 }, (_, i) => `X-H${i}: ${i}`).join('\n'));
  assert.equal(r.headers.length, C.LIMITS.headers);
  assert.equal(r.truncated, true);
});

test('a single header past 64 KB is cut short and marked', () => {
  const r = analyze(`Received: from a by b; ${day}\nX-Long: ${'y'.repeat(100000)}`);
  const h = r.headers.find(x => x.name === 'X-Long');
  assert.equal(h.value.length, C.LIMITS.valueChars);
  assert.equal(h.cut, true);
  assert.ok(has(r, /^A very long header was cut short/));
});

test('binary junk and stray control characters do not crash the analysis', () => {
  let seed = 3;
  const rand = () => (seed = (seed * 1103515245 + 12345) >>> 0) / 2 ** 32;
  for (let n = 0; n < 100; n++) {
    const junk = Array.from({ length: 2000 }, () => String.fromCharCode(Math.floor(rand() * 0x3000))).join('');
    assert.doesNotThrow(() => { const r = analyze(`X-Junk: ${junk}\nFrom: ${junk}\nReceived: ${junk}\nAuthentication-Results: ${junk}`); if (r) C.buildReport(r, { redact: true, subject: true, notes: true, raw: true }); });
  }
});

test('header names and values that look like markup stay plain strings (escaping is the page\'s job, and it is tested in the browser)', () => {
  const r = analyze(F.m365({ subject: '<img src=x onerror=alert(1)>', extra: ['X-<svg/onload=alert(1)>: "><script>alert(1)</script>'] }));
  assert.equal(r.subject, '<img src=x onerror=alert(1)>');
  assert.ok(r.headers.some(h => h.name === 'X-<svg/onload=alert(1)>'));
});
