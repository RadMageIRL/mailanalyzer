// The trust boundary and forged verdicts: a header the sender could have written must never become an
// authoritative verdict.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { C, F, analyze, find, has } = require('./helpers.js');
const FORGED_PASS = 'Authentication-Results: spf=pass smtp.mailfrom=example-vendor.com; dkim=pass header.d=example-vendor.com; dmarc=pass action=none header.from=example-vendor.com;compauth=pass reason=100';

test('the boundary is the Exchange Online front door hop, and the tenant\'s results above it are trusted', () => {
  const r = analyze(F.m365());
  assert.equal(r.boundary, 1);
  assert.match(r.hops[r.boundary].by, /\.mail\.protection\.outlook\.com$/);
  assert.equal(r.authTrust, 'trusted');
  assert.equal(r.reporter, 'Microsoft 365');
});

test('a forged Authentication-Results below the gateway is untrusted, serious, and never a clean verdict', () => {
  const r = analyze(F.m365({ ar: null, rspf: null, bottom: [FORGED_PASS] }));
  assert.equal(r.authTrust, 'untrusted');
  assert.equal(find(r, /^Authentication results sit below your gateway/).sev, 'bad');
  const dmarc = find(r, /^DMARC pass claimed/);
  assert.equal(dmarc.sev, 'warn');
  assert.equal(dmarc.basis, 'untrusted');
  assert.equal(C.verdictOf(r), 'Suspicious');
  assert.equal(has(r, /^Nothing alarming/), false);
});

test('a forged pass in the sender-side zone is ignored when the tenant wrote its own result', () => {
  const r = analyze(F.m365({ ar: 'spf=fail (sender IP is 198.51.100.24) smtp.mailfrom=example-vendor.com; dkim=none; dmarc=fail action=quarantine header.from=example-vendor.com;compauth=fail reason=000', senderSide: [FORGED_PASS] }));
  assert.equal(r.authTrust, 'trusted');
  assert.equal(r.dmarc.result, 'fail');
  assert.ok(has(r, /^1 Authentication-Results header from before your gateway ignored/));
});

test('with no sender-side hop, everything below the front door hop came with the message and is untrusted', () => {
  const r = analyze(F.m365({ ar: null, rspf: null, noSenderHop: true, bottom: [FORGED_PASS] }));
  assert.equal(r.boundary, 0);
  assert.equal(r.authTrust, 'untrusted');
  assert.equal(C.verdictOf(r), 'Suspicious');
});

test('a forged Exchange Online hop at the bottom of a non-Microsoft message is not taken as the entry point', () => {
  const r = analyze(F.forgedMicrosoftAtBottom());
  assert.equal(r.boundary, -1);
  assert.equal(r.edge.foreign, '2001:db8:100::1'); // the provider's top hop names itself only by an address
  assert.equal(find(r, /^Your entry point is not the newest hop/).sev, 'warn');
  assert.equal(r.ms.viaM365, false);
  assert.equal(r.ms.ffTrust, 'unknown');
  assert.equal(find(r, /^Could not confirm that your Microsoft 365 tenant wrote these stamps/).sev, 'warn');
  // the receiving provider's own result (DMARC fail) is the one used, not the forged pass at the bottom
  assert.equal(r.dmarc.result, 'fail');
  assert.equal(r.authTrust, 'unknown');
});

test('mail that passed through two tenants takes the newest Exchange Online hop as the entry point', () => {
  const r = analyze(F.m365({ helo: 'SENDER01.namprd01.prod.outlook.com', noSenderHop: true, bottom: [`Received: from SENDER02.namprd01.prod.outlook.com (2603:10b6:5::2) by SENDER01.mail.protection.outlook.com (10.0.0.9) with Microsoft SMTP Server; ${F.DAY} 09:00:02 +0000`, 'X-Forefront-Antispam-Report-Untrusted: SCL:1;SFV:NSPM;CAT:NONE;'] }));
  assert.equal(r.hops.length, 4);
  assert.equal(r.boundary, 1);
  assert.match(r.hops[1].by, /^DS7PEPF00000002\./);
  assert.equal(r.edge.held, '');
});

test('trust never extends below the Exchange Online front door, even to a host on your domains', () => {
  const r = analyze(F.m365({ helo: 'relay.example.com', ip: '10.20.30.40', noSenderHop: true, bottom: [`Received: from [192.0.2.10] by relay.example.com with ESMTP; ${F.DAY} 09:00:01 +0000`, 'Authentication-Results: relay.example.com; dmarc=pass header.from=example-vendor.com'] }), 'example.com');
  assert.match(r.hops[r.boundary].by, /\.mail\.protection\.outlook\.com$/);
  assert.equal(r.authTrust, 'trusted');
  assert.equal(r.trustOf(r.arHeaders[1], true), 'untrusted');
});

test('with no sender-side hop, a filter stamp below the front door hop is untrusted too', () => {
  const r = analyze(F.m365({ noSenderHop: true, bottom: ['X-Spam-Status: Yes, score=12.0 required=5.0 tests=X'] }));
  assert.equal(r.boundary, 0);
  assert.equal(find(r, /^A spam filter marked it as spam/).basis, 'untrusted');
});

test('a Received-SPF that only appears below the gateway is untrusted and does not set the sending IP', () => {
  const r = analyze(F.m365({ ar: 'dkim=pass header.d=example-vendor.com;dmarc=pass action=none header.from=example-vendor.com', rspf: null, bottom: ['Received-SPF: Pass (forged) client-ip=192.0.2.250; envelope-from=billing@example-vendor.com; helo=forged.example'] }));
  assert.equal(r.spf.viaReceivedSpf, true);
  assert.equal(r.spf.trust, 'untrusted');
  assert.ok(has(r, /^The only Received-SPF header sits below your gateway/));
  assert.notEqual(r.sendingIp?.ip, '192.0.2.250');
  assert.equal(r.heloSpf, '');
});

test('without any recognizable entry point every verdict is a claim', () => {
  const r = analyze(F.otherProvider());
  assert.equal(r.boundary, -1);
  assert.equal(r.authTrust, 'unknown');
  assert.equal(find(r, /^Could not find where the message entered your systems/).sev, 'info');
  assert.equal(find(r, /^Could not confirm who wrote the authentication results/).sev, 'warn');
  assert.match(find(r, /^DMARC pass/).title, /writer not confirmed/);
  assert.equal(find(r, /^DMARC pass/).sev, 'info');
});

test('your domains set the entry point; a newer hop named only by an IP address stops the walk', () => {
  const ipTop = analyze(F.otherProvider(), 'example.net');
  assert.equal(ipTop.boundary, -1);
  assert.equal(ipTop.edge.foreign, '2001:db8:100::1');
  const r = analyze(F.otherProvider().split('\n').slice(1).join('\n'), 'example.net');
  assert.equal(r.boundary, 1);
  assert.equal(r.hops[1].by, 'mx.example.net');
  // the provider wrote its results just below its own Received line: not provably its own, so not trusted either way
  assert.equal(r.authTrust, 'unknown');
  assert.equal(has(r, /sit below your gateway/), false);
});

test('a top hop named by IP, unnamed or private cannot carry trust down to a forged Exchange Online hop (review finding 3)', () => {
  const day = F.DAY;
  for (const top of ['by 203.0.113.9 with ESMTP', 'by 10.1.2.3 with ESMTP', 'with local']) {
    const r = analyze(F.join(
      `Received: from a.example.org (a.example.org [198.51.100.5]) ${top}; ${day} 09:00:05 +0000`,
      'Authentication-Results: spf=pass smtp.mailfrom=x.example; dmarc=pass action=none header.from=x.example',
      `Received: from b by BN2PEPF00000001.mail.protection.outlook.com; ${day} 09:00:03 +0000`,
      'From: a@x.example', 'Subject: x', `Date: ${day} 09:00:00 +0000`,
      'X-Forefront-Antispam-Report: SFV:NSPM;SCL:-1;CAT:NONE;', 'X-MS-Exchange-Organization-SCL: -1'));
    assert.equal(r.boundary, -1, top);
    assert.equal(r.ms.viaM365, false, top);
    assert.notEqual(r.authTrust, 'trusted', top);
    assert.notEqual(C.verdictOf(r), 'Looks clean', top);
  }
});

test('an address in the sender\'s HELO cannot extend trust down your own chain (review finding 2)', () => {
  const day = F.DAY;
  const r = analyze(F.join(
    `Received: from [10.0.0.1]relay.example.com (unknown [203.0.113.66]) by mx.example.com (Postfix) with ESMTP; ${day} 09:00:05 +0000`,
    'Authentication-Results: mx.example.com; dmarc=pass header.from=paypal.com',
    `Received: from x by mx2.example.com; ${day} 09:00:03 +0000`,
    'From: PayPal <service@paypal.com>', 'Subject: x', `Date: ${day} 09:00:00 +0000`), 'example.com');
  assert.equal(r.hops[r.boundary].by, 'mx.example.com');
  assert.equal(r.edge.held, 'mx2.example.com');
  assert.notEqual(r.authTrust, 'trusted');
  assert.notEqual(C.verdictOf(r), 'Looks clean');
});

test('a chain of your own servers extends the boundary only over private addresses', () => {
  const day = F.DAY;
  const chain = (ip) => F.join(
    `Received: from mx1.example.com (mx1.example.com [${ip}]) by mailbox.example.com with ESMTPS; ${day} 09:00:05 +0000`,
    'Authentication-Results: mx1.example.com; spf=pass smtp.mailfrom=example-vendor.com; dmarc=pass header.from=example-vendor.com',
    `Received: from mail.example-vendor.com (mail.example-vendor.com [198.51.100.24]) by mx1.example.com with ESMTPS; ${day} 09:00:04 +0000`,
    `Received: from [192.0.2.10] by mail.example-vendor.com with ESMTPSA; ${day} 09:00:01 +0000`,
    'From: billing@example-vendor.com', 'To: ap@example.com', 'Subject: x', `Date: ${day} 09:00:00 +0000`);
  const inside = analyze(chain('10.0.0.5'), 'example.com');
  assert.equal(inside.hops[inside.boundary].by, 'mx1.example.com');
  assert.equal(inside.authTrust, 'trusted'); // mx1 wrote it above its own Received line
  const exposed = analyze(chain('198.51.100.77'), 'example.com');
  assert.equal(exposed.hops[exposed.boundary].by, 'mailbox.example.com');
  assert.equal(exposed.edge.held, 'mx1.example.com');
  assert.equal(exposed.authTrust, 'unknown'); // now between the entry point and a hop that is not confirmed as ours
  assert.ok(has(exposed, /^A hop below your entry point also names your systems/));
});

test('a forged hop naming your domain below the real entry point does not pull the boundary down', () => {
  const day = F.DAY;
  const text = F.join(
    `Received: from mail.example-bad.test (mail.example-bad.test [203.0.113.66]) by mx1.example.com with ESMTP; ${day} 09:00:05 +0000`,
    FORGED_PASS,
    `Received: from x by mx2.example.com with ESMTP; ${day} 09:00:03 +0000`,
    'From: billing@example-vendor.com', 'To: ap@example.com', 'Subject: x', `Date: ${day} 09:00:00 +0000`);
  const r = analyze(text, 'example.com');
  assert.equal(r.hops[r.boundary].by, 'mx1.example.com');
  assert.equal(r.edge.held, 'mx2.example.com');
  assert.notEqual(r.authTrust, 'trusted');
});

test('a filter stamp below the gateway is untrusted and does not count toward the headline', () => {
  const r = analyze(F.m365({ bottom: ['X-Spam-Status: Yes, score=12.0 required=5.0 tests=PHISH_X'] }));
  const f = find(r, /^A spam filter marked it as spam/);
  assert.equal(f.basis, 'untrusted');
  assert.equal(r.categories.some(c => c.key === 'spam'), false);
});

test('findBoundary on its own: newest edge wins, foreign newer hops cancel it', () => {
  C.setDomains('');
  const hop = by => ({ by, from: '', ip: '' });
  assert.equal(C.findBoundary([hop('a.example.org'), hop('X1.mail.protection.outlook.com'), hop('Y.prod.outlook.com')]).boundary, 1);
  assert.equal(C.findBoundary([hop('X1.mail.protection.outlook.com'), hop('mx.example.net')]).boundary, -1);
  assert.equal(C.findBoundary([hop('X0.mail.protection.outlook.com'), hop('a.example.org'), hop('X1.mail.protection.outlook.com')]).boundary, 2);
  assert.equal(C.findBoundary([hop('outlook.com.example.org.mail.protection.outlook.com.evil.example')]).boundary, -1);
  assert.equal(C.findBoundary([hop('X1.mail.protection.outlook.com'), hop('')]).boundary, -1);
  assert.equal(C.findBoundary([hop('X1.mail.protection.outlook.com'), hop('192.0.2.9')]).boundary, -1);
});
