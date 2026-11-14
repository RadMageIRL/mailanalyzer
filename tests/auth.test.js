// SPF, DKIM, DMARC, alignment and Microsoft's composite authentication, as reported in the headers.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { C, F, analyze, find, has } = require('./helpers.js');

const AR = (spf, dkim, dmarc, extra = '') => `spf=${spf} (sender IP is 198.51.100.24) smtp.mailfrom=${spf.includes('@') ? '' : 'bounce.example-vendor.com'}; dkim=${dkim} header.d=example-vendor.com;dmarc=${dmarc} action=none header.from=example-vendor.com${extra}`;

test('an SPF pass for a subdomain of the From domain is aligned (relaxed) and carries DMARC', () => {
  const r = analyze(F.m365({ ar: AR('pass', 'none', 'pass') }));
  assert.equal(r.spf.result, 'pass');
  assert.equal(r.spfDomain, 'bounce.example-vendor.com');
  assert.equal(r.spfAligned, true);
  assert.equal(r.dkimAligned, false);
  assert.match(find(r, /^DMARC pass/).detail, /Carried by SPF\./);
});

test('an SPF pass for another organization is not aligned; an aligned DKIM pass carries DMARC instead', () => {
  const r = analyze(F.m365({ ar: 'spf=pass (sender IP is 198.51.100.24) smtp.mailfrom=bounces.example-esp.net; dkim=pass header.d=example-vendor.com;dmarc=pass action=none header.from=example-vendor.com' }));
  assert.equal(r.spfAligned, false);
  assert.equal(r.spfAlignedDomain, false);
  assert.equal(r.dkimAligned, true);
  assert.match(find(r, /^DMARC pass/).detail, /Carried by DKIM\./);
  assert.match(Object.fromEntries(C.spfExplain(r)).alignment, /different organization/);
});

test('an SPF fail with no aligned DKIM is serious; with an aligned DKIM pass it is only a warning', () => {
  const alone = analyze(F.m365({ ar: AR('fail', 'none', 'fail') }));
  assert.equal(find(alone, /^SPF fail/).sev, 'bad');
  const rescued = analyze(F.m365({ ar: AR('fail', 'pass', 'pass') }));
  assert.equal(find(rescued, /^SPF fail/).sev, 'warn');
});

test('SPF softfail, permerror and temperror are warnings; neutral and none raise no SPF finding', () => {
  for (const res of ['softfail', 'permerror', 'temperror']) assert.equal(find(analyze(F.m365({ ar: AR(res, 'pass', 'pass') })), new RegExp(`^SPF ${res}`)).sev, 'warn', res);
  for (const res of ['neutral', 'none']) assert.equal(has(analyze(F.m365({ ar: AR(res, 'pass', 'pass') })), /^SPF /), false, res);
});

test('a DKIM fail is serious when nothing else is aligned, and a warning when SPF carries DMARC', () => {
  assert.equal(find(analyze(F.m365({ ar: 'spf=fail smtp.mailfrom=example-esp.net; dkim=fail header.d=example-vendor.com;dmarc=fail action=quarantine header.from=example-vendor.com' })), /^DKIM fail/).sev, 'bad');
  assert.equal(find(analyze(F.m365({ ar: AR('pass', 'fail', 'pass') })), /^DKIM fail/).sev, 'warn');
});

test('a DKIM-Signature with no recorded verdict is shown as unverified, never as a pass', () => {
  const r = analyze(F.m365({ ar: 'spf=pass smtp.mailfrom=example-vendor.com;dmarc=pass action=none header.from=example-vendor.com', bottom: ['DKIM-Signature: v=1; a=rsa-sha256; d=example-vendor.com; s=s1; h=from:to:subject; bh=x; b=y'] }));
  const rows = C.dkimRows(r);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].result, 'unverified');
  assert.match(Object.fromEntries(rows[0].rows).meaning, /does not verify signatures/);
});

test('a DKIM signature with l= or without From in h= is flagged, as a warning only when it passed', () => {
  const sig = 'DKIM-Signature: v=1; a=rsa-sha256; d=example-vendor.com; s=s1; l=120; h=to:subject; bh=x; b=y';
  const passed = analyze(F.m365({ bottom: [sig] }));
  assert.equal(find(passed, /covers only part of the body \(l=120\)/).sev, 'warn');
  assert.equal(find(passed, /does not cover the From header/).sev, 'warn');
  const unchecked = analyze(F.m365({ ar: AR('pass', 'none', 'pass').replace('header.d=example-vendor.com', ''), bottom: [sig] }));
  assert.equal(find(unchecked, /covers only part of the body/).sev, 'info');
});

test('a DMARC fail is serious and supports impersonation; a pass in a trusted position is good', () => {
  const fail = analyze(F.m365({ ar: AR('fail', 'fail', 'fail') }));
  const f = find(fail, /^DMARC fail/);
  assert.equal(f.sev, 'bad');
  assert.equal(f.cat, 'impersonation');
  assert.equal(f.basis, 'reported');
  assert.equal(find(analyze(F.m365()), /^DMARC pass/).sev, 'good');
});

test('DMARC none and permerror are warnings; bestguesspass is a note', () => {
  assert.equal(find(analyze(F.m365({ ar: AR('pass', 'pass', 'none') })), /^DMARC none/).sev, 'warn');
  assert.equal(find(analyze(F.m365({ ar: AR('pass', 'pass', 'permerror') })), /^DMARC permerror/).sev, 'warn');
  assert.equal(find(analyze(F.m365({ ar: AR('pass', 'pass', 'bestguesspass') })), /^DMARC best-guess pass/).sev, 'info');
});

test('with no DMARC result recorded, the computed outcome is labeled inferred', () => {
  const pass = find(analyze(F.m365({ ar: 'spf=pass smtp.mailfrom=example-vendor.com; dkim=none' })), /^No DMARC verdict recorded/);
  assert.equal(pass.basis, 'inferred');
  assert.match(pass.detail, /would pass/);
  assert.match(find(analyze(F.m365({ ar: 'spf=pass smtp.mailfrom=example-esp.net; dkim=none' })), /^No DMARC verdict recorded/).detail, /would fail/);
});

test('headers with no Authentication-Results at all get a warning, not a clean bill', () => {
  const r = analyze(F.m365({ ar: null, rspf: null }));
  assert.equal(find(r, /^No Authentication-Results header/).sev, 'warn');
  assert.notEqual(C.verdictOf(r), 'Looks clean');
});

test('Microsoft composite authentication: fail is serious, softpass a warning, with the reason explained', () => {
  const fail = find(analyze(F.m365({ ar: AR('fail', 'none', 'fail', ';compauth=fail reason=000') })), /^Microsoft composite authentication failed \(reason 000\)/);
  assert.equal(fail.sev, 'bad');
  assert.match(fail.detail, /Explicit fail/);
  assert.equal(find(analyze(F.m365({ ar: AR('pass', 'pass', 'pass', ';compauth=softpass reason=201') })), /soft-pass/).sev, 'warn');
  assert.match(C.compauthReason('001'), /Implicit fail/);
  assert.match(C.compauthReason('130'), /^Pass/);
  assert.match(C.compauthReason('905'), /Bypassed/);
  assert.match(C.compauthReason('abc'), /not in Microsoft's published ranges/);
});

test('a message with no DKIM signature at all gets a note', () => {
  assert.ok(has(analyze(F.m365({ ar: 'spf=pass smtp.mailfrom=example-vendor.com;dmarc=pass action=none header.from=example-vendor.com' })), /^Message is not DKIM-signed/));
  assert.equal(has(analyze(F.m365()), /^Message is not DKIM-signed/), false);
});
