// Microsoft 365 / Exchange Online Protection stamps: SFV, SCL, CAT, BCL, PCL, SFTY, SRV, mailbox delivery.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { C, F, analyze, find, has } = require('./helpers.js');
const ff = parts => `CIP:198.51.100.24;CTRY:US;LANG:en;${parts}DIR:INB;`;

test('a bad CAT code is serious, reported by Microsoft 365, and names its category', () => {
  const cases = { PHSH: 'phish', HPHSH: 'phish', MALW: 'malware', SAP: 'malware', AMP: 'malware', SPOOF: 'impersonation', BIMP: 'impersonation', UIMP: 'impersonation', HSPM: 'spam', SPM: 'spam' };
  for (const [code, cat] of Object.entries(cases)) {
    const f = find(analyze(F.m365({ forefront: ff(`SCL:9;SFV:SPM;CAT:${code};`) })), /^Microsoft classified it as/);
    assert.ok(f, code);
    assert.equal(f.sev, 'bad', code);
    assert.equal(f.cat, cat, code);
    assert.equal(f.basis, 'reported', code);
    assert.equal(f.by, 'Microsoft 365', code);
  }
});

test('the headline names a Microsoft verdict as reported', () => {
  const r = analyze(F.m365({ forefront: ff('SCL:9;SFV:SPM;CAT:PHSH;') }));
  assert.equal(r.categories[0].key, 'phish');
  assert.equal(r.categories[0].basis, 'reported');
  assert.equal(r.categories[0].title, 'Phishing');
});

test('SFV:SPM or SCL 5 and up is spam; SCL 4 is not', () => {
  assert.equal(find(analyze(F.m365({ scl: 5, forefront: ff('SCL:5;SFV:NSPM;CAT:NONE;') })), /^Microsoft marked it as spam/).sev, 'warn');
  assert.ok(has(analyze(F.m365({ scl: 1, forefront: ff('SCL:1;SFV:SPM;CAT:NONE;') })), /^Microsoft marked it as spam/));
  assert.equal(has(analyze(F.m365({ scl: 4, forefront: ff('SCL:4;SFV:NSPM;CAT:NONE;') })), /^Microsoft marked it as spam/), false);
});

test('an allow-list bypass (SFV:SKA) is a note, never a clean verdict on its own', () => {
  const f = find(analyze(F.m365({ scl: -1, forefront: ff('SCL:-1;SFV:SKA;CAT:NONE;') })), /bypassed \(SKA\)/);
  assert.equal(f.sev, 'info');
  assert.match(f.detail, /allow list/);
});

test('safety tips: 9.1 is a phishing warning, 9.19 an impersonation warning, 9.25 a note', () => {
  const t91 = find(analyze(F.m365({ forefront: ff('SCL:1;SFV:NSPM;CAT:NONE;SFTY:9.1;') })), /SFTY:9\.1$/);
  assert.equal(t91.sev, 'warn');
  assert.equal(t91.cat, 'phish');
  assert.equal(find(analyze(F.m365({ forefront: ff('SCL:1;SFV:NSPM;CAT:NONE;SFTY:9.19;') })), /SFTY:9\.19/).cat, 'impersonation');
  assert.equal(find(analyze(F.m365({ forefront: ff('SCL:1;SFV:NSPM;CAT:NONE;SFTY:9.25;') })), /SFTY:9\.25/).sev, 'info');
});

test('BCL 7 and above is a bulk warning; BCL 6 is not', () => {
  assert.equal(find(analyze(F.m365({ antispam: 'BCL:7;' })), /High bulk complaint level \(BCL 7\)/).cat, 'bulk');
  assert.equal(has(analyze(F.m365({ antispam: 'BCL:6;' })), /High bulk complaint level/), false);
});

test('PCL 4 and above is a phishing warning; PCL 3 is not', () => {
  assert.equal(find(analyze(F.m365({ antispam: 'BCL:0;PCL:4;' })), /Phishing confidence level 4/).cat, 'phish');
  assert.equal(has(analyze(F.m365({ antispam: 'BCL:0;PCL:3;' })), /Phishing confidence level/), false);
});

test('SRV:BULK is a bulk note', () => {
  assert.equal(find(analyze(F.m365({ forefront: ff('SCL:1;SRV:BULK;SFV:NSPM;CAT:NONE;'), antispam: 'BCL:5;' })), /SRV:BULK/).cat, 'bulk');
});

test('Mailbox-Delivery dest:J is a junk warning; dest:I a note; an unknown code says it is unrecognized', () => {
  assert.equal(find(analyze(F.m365({ mbx: 'ucf:0;jmr:0;auth:0;dest:J;OFR:SpamFilterAuthJ;' })), /Junk Email folder/).sev, 'warn');
  assert.equal(find(analyze(F.m365({ mbx: 'dest:I;' })), /Delivered to the Inbox/).sev, 'info');
  assert.match(find(analyze(F.m365({ mbx: 'dest:Q;' })), /folder code "Q"/).detail, /does not recognize/);
});

test('Microsoft antispam headers renamed -Untrusted are set aside, not used as the verdict', () => {
  const r = analyze(F.m365({ bottom: ['X-Forefront-Antispam-Report-Untrusted: CIP:192.0.2.1;SCL:9;SFV:SPM;CAT:PHSH;', 'X-Microsoft-Antispam-Untrusted: BCL:9;PCL:8;'] }));
  assert.ok(has(r, /from before your tenant were set aside/));
  assert.equal(has(r, /classified it as/), false);
  assert.equal(r.forefront.CAT, 'NONE');
});

test('SCL, BCL and PCL meanings', () => {
  assert.equal(C.sclMeaning('-1'), 'filtering skipped (trusted sender or bypass)');
  assert.equal(C.sclMeaning('1'), 'not spam');
  assert.equal(C.sclMeaning('5'), 'spam: junk folder by default');
  assert.equal(C.sclMeaning('9'), 'high-confidence spam');
  assert.equal(C.sclMeaning(''), '');
  assert.equal(C.bclMeaning('0'), 'not from a bulk sender');
  assert.match(C.bclMeaning('8'), /many complaints/);
  assert.match(C.pclMeaning('4'), /likely to be phishing/);
});

test('Microsoft stamps in an Exchange Online message are trusted by name, even at the bottom', () => {
  const r = analyze(F.m365());
  assert.equal(r.ms.ffTrust, 'trusted');
  assert.equal(r.ms.viaM365, true);
});
