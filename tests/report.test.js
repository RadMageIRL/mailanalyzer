// The troubleshooting report: what masking hides and what it says it does not, hiding the subject, notes, the
// appended raw headers and spelled-out control characters.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { C, F, analyze } = require('./helpers.js');
const NOW = Date.UTC(2026, 10, 14, 12, 0, 0);
const report = (text, o = {}) => C.buildReport(analyze(text), { ...C.REPORT_DEFAULTS, ...o }, NOW);

test('masking hides the mailbox part of every address in the report', () => {
  const out = report(C.SAMPLE);
  assert.match(out, /From: {9}Example Vendor Billing <b\*\*\*@example-vendor\.com>/);
  assert.match(out, /Reply-To: {5}a\*\*\*@example-vendor-payments\.net/);
  assert.match(out, /To: {11}a\*\*\*@example\.com/);
  assert.match(out, /Return-Path: {2}b\*\*\*@mg\.example-vendor\.com/);
  for (const raw of ['billing@', 'accounts@', 'ap@example.com', 'bounce+1a2b3c']) assert.ok(!out.includes(raw), raw);
});

test('masking says plainly that it is partial and not anonymization', () => {
  const out = report(C.SAMPLE);
  assert.match(out, /Partially masked: only the mailbox names in addresses are hidden/);
  assert.match(out, /not anonymized/);
  assert.match(report(C.SAMPLE, { redact: false }), /Not masked: addresses appear in full\./);
});

test('Message-ID and Network-Message-Id are never masked, so they can still be searched', () => {
  const out = report(C.SAMPLE, { raw: true });
  assert.ok(out.includes('Message-ID:   <20261026140139.ab12cd34ef56@mg.example-vendor.com>'));
  assert.ok(out.includes('Message-Id: <20261026140139.ab12cd34ef56@mg.example-vendor.com>'));
  assert.ok(out.includes('X-MS-Exchange-Organization-Network-Message-Id: 3f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b'));
});

test('mask covers addresses with non-ASCII mailbox names and domains, and a leading dot', () => {
  assert.equal(C.mask('j\u00F6rg.m\u00FCller@example.com'), 'j***@example.com');
  assert.equal(C.mask('\u0438\u0432\u0430\u043D@\u043F\u0440\u0438\u043C\u0435\u0440.example'), '\u0438***@\u043F\u0440\u0438\u043C\u0435\u0440.example');
  assert.equal(C.mask('x .john@example.com y'), 'x .j***@example.com y');
  assert.equal(C.mask('no address here'), 'no address here');
});

test('mask covers every mailbox character, quoted mailbox names and hosts with no dot (review finding 6)', () => {
  assert.equal(C.mask("john.o'brien@corp.example"), 'j***@corp.example');
  assert.equal(C.mask('"john.doe"@corp.example'), '"j***"@corp.example');
  assert.equal(C.mask('"service@paypal.com"@evil.example'), '"s***"@evil.example');
  assert.equal(C.mask('john.doe@mailhost'), 'j***@mailhost');
  assert.equal(C.mask('a{b}|c~d#e@example.com'), 'a***@example.com');
});

test('addresses in the subject are masked too, unless masking is off', () => {
  const text = F.m365({ subject: 'Message for jane.doe@example.org about the invoice' });
  assert.match(report(text), /Subject: {6}Message for j\*\*\*@example\.org about the invoice/);
  assert.ok(report(text, { redact: false }).includes('jane.doe@example.org'));
});

test('without masking, addresses appear in full', () => {
  const out = report(C.SAMPLE, { redact: false });
  assert.ok(out.includes('<billing@example-vendor.com>'));
  assert.ok(out.includes('ap@example.com'));
});

test('hide subject replaces it in the summary and in appended headers', () => {
  const out = report(F.m365({ subject: 'Secret project codename', extra: ['Thread-Topic: Secret project codename'] }), { subject: true, raw: true });
  assert.ok(!out.includes('Secret project codename'));
  assert.match(out, /Subject: {6}\[hidden\]/);
  assert.match(out, /^Thread-Topic: \[hidden\]$/m);
});

test('turning notes off leaves only serious findings and warnings', () => {
  const out = report(C.SAMPLE, { notes: false });
  assert.match(out, /\[WARNING\]/);
  assert.ok(!/\[NOTE\]|\[OK\]/.test(out));
  assert.match(report(C.SAMPLE), /\[OK\]/);
});

test('the appended original headers are masked line by line', () => {
  const out = report(C.SAMPLE, { raw: true });
  const raw = out.slice(out.indexOf('----- ORIGINAL HEADERS'));
  assert.match(raw, /^From: "Example Vendor Billing" <b\*\*\*@example-vendor\.com>$/m);
  assert.match(raw, /^To: Accounts Payable <a\*\*\*@example\.com>$/m);
});

test('direction overrides and invisible characters are spelled out in the report', () => {
  const out = report(F.m365({ subject: 'Invoice \u202Efdp.exe' }));
  assert.ok(out.includes('Invoice [U+202E]fdp.exe'));
  assert.ok(!out.includes('\u202E'));
});

test('the report names the app, its version, the time zone, and that nothing was re-verified', () => {
  const out = report(C.SAMPLE);
  assert.match(out, new RegExp(`^EMAIL HEADER ANALYSIS \\(MailAnalyzer v${C.VERSION.replace(/\./g, '\\.')}\\)$`, 'm'));
  assert.match(out, /Generated 2026-11-14 12:00:00 local time \(UTC\+00:00\)/);
  assert.match(out, /not re-verified\]/);
  assert.match(out, /does not query DNS, verify DKIM signatures or check reputation/);
  assert.ok(!/mops/i.test(out));
});

test('an untrusted authentication header is labeled UNTRUSTED in the report', () => {
  const out = report(F.m365({ ar: null, rspf: null, bottom: ['Authentication-Results: spf=pass smtp.mailfrom=example-vendor.com; dmarc=pass header.from=example-vendor.com'] }));
  assert.match(out, /AUTHENTICATION {2}\[UNTRUSTED: header sits below your gateway/);
  assert.match(out, /VERDICT: SUSPICIOUS/);
});

test('report options read from storage keep only known boolean settings', () => {
  assert.deepEqual(C.reportOptions('{"redact":false,"raw":true,"evil":"x","notes":"yes"}'), { redact: false, subject: false, notes: true, raw: true });
  assert.deepEqual(C.reportOptions('not json'), C.REPORT_DEFAULTS);
  assert.deepEqual(C.reportOptions(null), C.REPORT_DEFAULTS);
});
