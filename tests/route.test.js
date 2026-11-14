// The Received chain: order, delays, total transit, clock skew, the Date header and TLS notes.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { F, analyze, find, has } = require('./helpers.js');

test('hops are listed oldest first with the delay since the previous hop', () => {
  const r = analyze(F.m365());
  assert.deepEqual(r.hops.map(h => h.by), ['mail.example-vendor.com', 'DS7PEPF00000002.mail.protection.outlook.com', 'SA1PR10MB0001.namprd10.prod.outlook.com', 'SA1PR10MB0002.namprd10.prod.outlook.com']);
  assert.deepEqual(r.hops.map(h => h.delay), [null, 2000, 1000, 1000]);
});

test('total transit over 2 minutes is a warning, over 15 minutes serious; exactly 2 minutes is fine', () => {
  const at = (t2, t3, t4) => analyze(F.m365({ t2, t3, t4 }));
  assert.equal(has(at('09:02:00', '09:02:01', '09:02:01'), /^Delivery took/), false); // 09:00:01 -> 09:02:01 is 120 s
  assert.equal(find(at('09:02:00', '09:02:01', '09:02:02'), /^Delivery took 2m 01s/).sev, 'warn');
  assert.equal(find(at('09:15:00', '09:15:01', '09:15:01'), /^Delivery took/).sev, 'warn'); // 900 s
  assert.equal(find(at('09:15:00', '09:15:01', '09:15:02'), /^Delivery took/).sev, 'bad'); // 901 s
});

test('the longest gap names where the message sat', () => {
  const f = find(analyze(F.m365({ t2: '09:20:03', t3: '09:20:04', t4: '09:20:05' })), /^Delivery took/);
  assert.match(f.detail, /sitting at mail\.example-vendor\.com before it reached DS7PEPF00000002/);
});

test('a hop stamped more than 5 seconds before the previous one is clock skew; 4 seconds is not', () => {
  assert.ok(has(analyze(F.m365({ t2: '08:59:55' })), /^Clock skew between servers/)); // 09:00:01 -> 08:59:55, -6 s
  assert.equal(has(analyze(F.m365({ t2: '08:59:57' })), /^Clock skew/), false); // -4 s
});

test('hops in different time zones are compared in absolute time', () => {
  const r = analyze(F.m365({ t2: '09:00:03 +0000', date: 'Tue, 10 Nov 2026 01:00:00 -0800' }).replace('09:00:01 +0000', '04:00:01 -0500'));
  assert.equal(r.hops[1].delay, 2000);
  assert.equal(has(r, /after the Date header|later than the first hop/), false);
});

test('a first hop more than an hour after the Date header is a warning; a Date an hour ahead is a note', () => {
  assert.equal(find(analyze(F.m365({ date: 'Tue, 10 Nov 2026 07:59:00 +0000' })), /^First hop is .* after the Date header/).sev, 'warn');
  assert.equal(has(analyze(F.m365({ date: 'Tue, 10 Nov 2026 08:01:00 +0000' })), /after the Date header/), false);
  assert.equal(find(analyze(F.m365({ date: 'Tue, 10 Nov 2026 10:01:00 +0000' })), /^Date header is later than the first hop/).sev, 'info');
});

test('a public hop with no TLS marker is a note; private hops are not counted', () => {
  const plain = analyze(F.m365().replace('with Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.1.1 via Frontend Transport', 'with SMTP'));
  assert.match(find(plain, /public hop with no TLS noted/).title, /^1 public hop/);
  assert.equal(has(analyze(F.m365()), /no TLS noted/), false);
});

test('a hop with an unreadable date has no timestamp and breaks only its own delay', () => {
  const r = analyze(F.m365().replace(`${F.DAY} 09:00:04 +0000`, 'sometime'));
  assert.equal(r.hops[2].t, null);
  assert.equal(r.hops[2].delay, null);
  assert.equal(r.hops[3].delay, null);
  assert.equal(r.timed.length, 3);
});
