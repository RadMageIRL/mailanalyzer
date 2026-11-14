// Header parsing: the header block, folding, encoded words, address lists, dates, Received and Authentication-Results.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { C } = require('./helpers.js');

test('splitHeaders unfolds continuation lines into one value', () => {
  const { headers } = C.splitHeaders('Subject: part one\n  part two\n\tpart three\nTo: a@example.com');
  assert.equal(headers.length, 2);
  assert.equal(headers[0].value, 'part one part two part three');
  assert.equal(headers[1].name, 'To');
});

test('splitHeaders stops at the blank line, so a pasted body never enters the header block', () => {
  const { headers, block } = C.splitHeaders('From: a@example.com\nSubject: hi\n\nBody line with secret@example.org\nX-Not-A-Header: body text');
  assert.deepEqual(headers.map(h => h.name), ['From', 'Subject']);
  assert.equal(block, 'From: a@example.com\nSubject: hi');
  assert.ok(!block.includes('secret'));
});

test('splitHeaders keeps reading across a blank line when a transport header follows it', () => {
  const { headers } = C.splitHeaders('Received: by mx.example.net; Tue, 10 Nov 2026 09:00:00 +0000\n\nX-Gateway-Id: 42\nReceived: from a by b; Tue, 10 Nov 2026 08:59:00 +0000');
  assert.deepEqual(headers.map(h => h.name), ['Received', 'X-Gateway-Id', 'Received']);
});

test('splitHeaders does not treat From/Subject after a blank line as headers (a forwarded block in a body)', () => {
  const { headers } = C.splitHeaders('From: a@example.com\n\nFrom: b@example.org\nSubject: forwarded');
  assert.equal(headers.length, 1);
});

test('splitHeaders handles CRLF and leading blank lines', () => {
  const { headers, block } = C.splitHeaders('\r\n\r\nFrom: a@example.com\r\nTo: b@example.com\r\n\r\nbody');
  assert.equal(headers.length, 2);
  assert.ok(!block.includes('\r'));
});

test('text that does not start with a header analyzes to null', () => {
  assert.equal(C.analyze('hello there\nthis is not a header block'), null);
  assert.equal(C.analyze(''), null);
  assert.equal(C.analyze('   \n\n  '), null);
});

test('decodeWords decodes B and Q encoded words and joins adjacent ones', () => {
  assert.equal(C.decodeWords('=?UTF-8?B?SGVsbG8gd29ybGQ=?='), 'Hello world');
  assert.equal(C.decodeWords('=?UTF-8?Q?Invoice_10482_=E2=80=93_due?='), 'Invoice 10482 \u2013 due');
  assert.equal(C.decodeWords('=?UTF-8?Q?a?= =?UTF-8?Q?b?='), 'ab');
  assert.equal(C.decodeWords('=?iso-8859-1?q?caf=E9?='), 'caf\u00E9');
  assert.equal(C.decodeWords('=?utf-8*en?Q?hi?='), 'hi');
});

test('decodeWords leaves broken or unknown encoded words as they were', () => {
  assert.equal(C.decodeWords('=?UTF-8?B?***?='), '=?UTF-8?B?***?=');
  assert.equal(C.decodeWords('=?x-no-such-charset?Q?hi?='), '=?x-no-such-charset?Q?hi?=');
  assert.equal(C.decodeWords('plain text'), 'plain text');
});

test('parseMailboxes reads names, angle addresses, comments and lists', () => {
  assert.deepEqual(C.parseMailboxes('"Doe, Jane" <jane@example.com>'), [{ name: 'Doe, Jane', addr: 'jane@example.com' }]);
  assert.deepEqual(C.parseMailboxes('jane@example.com (Jane Doe)'), [{ name: 'Jane Doe', addr: 'jane@example.com' }]);
  assert.deepEqual(C.parseMailboxes('jane@example.com'), [{ name: '', addr: 'jane@example.com' }]);
  assert.deepEqual(C.parseMailboxes('A <a@example.com>, b@example.org').map(m => m.addr), ['a@example.com', 'b@example.org']);
  assert.deepEqual(C.parseMailboxes('<>'), []);
  assert.equal(C.parseAddress('=?UTF-8?Q?J=C3=B6rg?= <jorg@example.com>').name, 'J\u00F6rg');
});

test('a quoted display name containing an address can never become the From address', () => {
  const m = C.parseAddress('"Support <support@microsoft.com>" <billing@example-vendor.com>');
  assert.equal(m.addr, 'billing@example-vendor.com');
  assert.equal(m.name, 'Support <support@microsoft.com>');
});

test('an encoded display name that decodes to an address can never become the From address', () => {
  const enc = Buffer.from('Microsoft <support@microsoft.com>').toString('base64');
  const m = C.parseAddress(`=?UTF-8?B?${enc}?= <billing@example-vendor.com>`);
  assert.equal(m.addr, 'billing@example-vendor.com');
  assert.equal(m.name, 'Microsoft <support@microsoft.com>');
});

test('a quoted mailbox name containing @ belongs to the real domain after it (review finding 1)', () => {
  assert.deepEqual(C.parseAddress('"service@paypal.com"@evil.example'), { name: '', addr: '"service@paypal.com"@evil.example' });
  assert.equal(C.domainOf(C.parseAddress('"service@paypal.com"@evil.example').addr), 'evil.example');
  assert.equal(C.parseAddress('"a"@evil.example').addr, '"a"@evil.example');
  assert.equal(C.parseAddress('<"service@paypal.com"@evil.example>').addr, '"service@paypal.com"@evil.example');
  assert.equal(C.parseAddress('first."quoted part"@example.com (Name)').addr, 'first."quoted part"@example.com');
});

test('the connecting IP comes from the server\'s own note, not from a bracket in the sender\'s HELO (review finding 2)', () => {
  const h = C.parseReceived({ idx: 0, value: 'from [10.0.0.1]relay.example.com (unknown [203.0.113.66]) by mx.example.com (Postfix) with ESMTP; Tue, 10 Nov 2026 09:00:05 +0000' });
  assert.equal(h.ip, '203.0.113.66');
  assert.equal(C.parseReceived({ idx: 0, value: 'from [192.0.2.7] (helo=x) by mx.example.net; Tue, 10 Nov 2026 09:00:05 +0000' }).ip, '192.0.2.7');
  assert.equal(C.parseReceived({ idx: 0, value: 'from [10.0.0.1]x.example by mx.example.net; Tue, 10 Nov 2026 09:00:05 +0000' }).ip, '');
  assert.equal(C.parseReceived({ idx: 0, value: 'from SA1PR10MB0001.namprd10.prod.outlook.com (2603:10b6:806:1::1) by SA1PR10MB0002.namprd10.prod.outlook.com with HTTPS; Tue, 10 Nov 2026 09:00:05 +0000' }).ip, '2603:10b6:806:1::1');
});

test('after a blank line, a line that is not a header ends the block at that blank line (review finding 7)', () => {
  const { headers, block } = C.splitHeaders('From: a@example.com\nSubject: hi\n\nX-Note: hello\nBody paragraph with private text.\nMore text.');
  assert.deepEqual(headers.map(h => h.name), ['From', 'Subject']);
  assert.equal(block, 'From: a@example.com\nSubject: hi');
  const kept = C.splitHeaders('Received: by mx.example.net; Tue, 10 Nov 2026 09:00:00 +0000\n\nX-Gateway: 1\n  folded part\nX-Other: 2');
  assert.deepEqual(kept.headers.map(h => h.name), ['Received', 'X-Gateway', 'X-Other']);
});

test('an encoded word is read whole, so a raw "<" inside one cannot start an address', () => {
  const m = C.parseAddress('=?UTF-8?Q?Microsoft_<support@microsoft.com>?= <billing@example-vendor.com>');
  assert.equal(m.addr, 'billing@example-vendor.com');
  assert.equal(m.name, 'Microsoft <support@microsoft.com>');
});

test('parseMailDate reads RFC 5322 dates with numeric and named zones', () => {
  assert.equal(C.parseMailDate('Tue, 10 Nov 2026 09:00:00 +0000'), Date.UTC(2026, 10, 10, 9, 0, 0));
  assert.equal(C.parseMailDate('Tue, 10 Nov 2026 09:00:00 -0800 (PST)'), Date.UTC(2026, 10, 10, 17, 0, 0));
  assert.equal(C.parseMailDate('10 Nov 2026 09:00:00 +0530'), Date.UTC(2026, 10, 10, 3, 30, 0));
  assert.equal(C.parseMailDate('Tue, 10 Nov 2026 09:00:00 EST'), Date.UTC(2026, 10, 10, 14, 0, 0));
  assert.equal(C.parseMailDate('Tue, 10 Nov 2026 09:00:00 GMT'), Date.UTC(2026, 10, 10, 9, 0, 0));
  assert.equal(C.parseMailDate('26 Oct 2026 14:08:17.8123 (UTC)'), Date.UTC(2026, 9, 26, 14, 8, 17));
  assert.equal(C.parseMailDate('Tue, 3 Nov 26 9:05 +0000'), Date.UTC(2026, 10, 3, 9, 5, 0));
  assert.equal(C.parseMailDate('2026-11-10T09:00:00Z'), Date.UTC(2026, 10, 10, 9, 0, 0));
});

test('parseMailDate reads a date with no zone as UTC, not as the viewer\'s local time', () => {
  const saved = process.env.TZ;
  process.env.TZ = 'America/Los_Angeles';
  try { assert.equal(C.parseMailDate('Tue, 10 Nov 2026 09:00:00'), Date.UTC(2026, 10, 10, 9, 0, 0)); } finally { process.env.TZ = saved; }
});

test('parseMailDate rejects impossible and garbage dates', () => {
  assert.equal(C.parseMailDate('Tue, 31 Feb 2026 09:00:00 +0000'), null);
  assert.equal(C.parseMailDate('Tue, 10 Nov 2026 25:00:00 +0000'), null);
  assert.equal(C.parseMailDate('Tue, 10 Foo 2026 09:00:00 +0000'), null);
  assert.equal(C.parseMailDate('yesterday'), null);
  assert.equal(C.parseMailDate(''), null);
});

test('parseReceived reads from, by, protocol, id, recipient, IP, TLS and time', () => {
  const h = C.parseReceived({ idx: 0, value: 'from mail.example.com (mail.example.com [192.0.2.5]) by mx.example.net with ESMTPS id ab12 for <x@example.net> (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256); Tue, 10 Nov 2026 09:00:00 +0000' });
  assert.equal(h.from, 'mail.example.com');
  assert.equal(h.by, 'mx.example.net');
  assert.equal(h.with, 'ESMTPS');
  assert.equal(h.id, 'ab12');
  assert.equal(h.for, 'x@example.net');
  assert.equal(h.ip, '192.0.2.5');
  assert.equal(h.tls, true);
  assert.equal(h.tlsVer, 'TLS 1.3');
  assert.equal(h.t, Date.UTC(2026, 10, 10, 9, 0, 0));
  const plain = C.parseReceived({ idx: 1, value: 'from a.example.com (198.51.100.7) by b.example.net with SMTP; Tue, 10 Nov 2026 09:00:00 +0000' });
  assert.equal(plain.tls, false);
  assert.equal(plain.ip, '198.51.100.7');
});

test('parseAuthResults reads the server id, each method and its properties', () => {
  const a = C.parseAuthResults('mx.example.net; spf=pass (example.net: domain of b@example.com designates 192.0.2.5 as permitted sender) smtp.mailfrom=b@example.com; dkim=pass header.d=example.com header.s=s1; dmarc=fail (p=REJECT) header.from=example.com');
  assert.equal(a.servid, 'mx.example.net');
  assert.deepEqual(a.methods.map(m => `${m.method}=${m.result}`), ['spf=pass', 'dkim=pass', 'dmarc=fail']);
  assert.equal(a.methods[0].props['smtp.mailfrom'], 'b@example.com');
  assert.match(a.methods[0].comment, /designates 192\.0\.2\.5/);
  assert.equal(a.methods[1].props['header.s'], 's1');
});

test('a semicolon inside a comment or quoted string does not split a result', () => {
  const a = C.parseAuthResults('spf=pass (sender IP is 192.0.2.5; dmarc=fail) smtp.mailfrom="a;dmarc=fail"@example.com; dmarc=pass header.from=example.com');
  assert.deepEqual(a.methods.map(m => `${m.method}=${m.result}`), ['spf=pass', 'dmarc=pass']);
  assert.equal(a.methods[0].comment, 'sender IP is 192.0.2.5; dmarc=fail');
});

test('orgDomain handles two-part country suffixes and shared hosting suffixes', () => {
  assert.equal(C.orgDomain('mail.example.co.uk'), 'example.co.uk');
  assert.equal(C.orgDomain('a.b.example.com'), 'example.com');
  assert.equal(C.orgDomain('alice.github.io'), 'alice.github.io');
  assert.notEqual(C.orgDomain('alice.github.io'), C.orgDomain('mallory.github.io'));
});

test('visible spells out direction overrides and invisible characters but keeps newlines', () => {
  assert.equal(C.visible('a\u202Eb\u200Bc\nd'), 'a[U+202E]b[U+200B]c\nd');
  assert.equal(C.visible('emoji \u{1F468}\u200D\u{1F469}'), 'emoji \u{1F468}\u200D\u{1F469}');
});
