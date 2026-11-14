// Sender identity: display names, lookalike and international domains, brands, free webmail, Reply-To, hidden
// characters and repeated headers. These are heuristics, labeled inferred or observed.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { C, F, analyze, find, has } = require('./helpers.js');
const ALIGNED = d => `spf=pass (sender IP is 198.51.100.24) smtp.mailfrom=${d}; dkim=pass header.d=${d};dmarc=pass action=none header.from=${d};compauth=pass reason=100`;
const from = (line, d) => F.m365({ from: `From: ${line}`, ar: ALIGNED(d) });

test('a display name showing a different address is serious impersonation, and the real address is used', () => {
  const r = analyze(from('"support@microsoft.com" <billing@example-vendor.com>', 'example-vendor.com'));
  assert.equal(r.from.addr, 'billing@example-vendor.com');
  const f = find(r, /^Display name shows a different address/);
  assert.equal(f.sev, 'bad');
  assert.equal(f.cat, 'impersonation');
});

test('a quoted mailbox name holding a brand address is judged by its real domain and flagged (review finding 1)', () => {
  const r = analyze(F.m365({ from: 'From: "service@paypal.com"@evil.example', ar: ALIGNED('evil.example') }));
  assert.equal(r.fromDomain, 'evil.example');
  const f = find(r, /^The From mailbox name contains another address/);
  assert.equal(f.sev, 'bad');
  assert.equal(f.cat, 'impersonation');
  assert.equal(C.verdictOf(r), 'Suspicious');
});

test('an encoded display name hiding an address is caught after decoding', () => {
  const enc = Buffer.from('Microsoft <support@microsoft.com>').toString('base64');
  const r = analyze(from(`=?UTF-8?B?${enc}?= <billing@example-vendor.com>`, 'example-vendor.com'));
  assert.equal(r.fromDomain, 'example-vendor.com');
  assert.ok(has(r, /^Display name shows a different address/));
  assert.ok(has(r, /^Sender name says Microsoft, but the address is not Microsoft's/));
});

test('a From with two addresses is a warning; two different From headers are serious', () => {
  assert.equal(find(analyze(from('a@example-vendor.com, b@example.org', 'example-vendor.com')), /^From lists more than one address/).sev, 'warn');
  const two = analyze(F.m365({ extra: ['From: Someone Else <ceo@example.org>'] }));
  assert.equal(find(two, /^From header appears 2 times with different values/).sev, 'bad');
  const same = analyze(F.m365({ extra: ['From: "Example Vendor" <billing@example-vendor.com>'] }));
  assert.equal(find(same, /^Headers repeated with identical values/).sev, 'info');
});

test('a brand in the sender name from another domain is a phishing warning; from the brand itself it is fine', () => {
  const r = analyze(from('"PayPal Service" <service@example-vendor.com>', 'example-vendor.com'));
  const f = find(r, /^Sender name says PayPal/);
  assert.equal(f.sev, 'warn');
  assert.equal(f.cat, 'phish');
  assert.equal(f.basis, 'inferred');
  assert.equal(has(analyze(from('"PayPal" <service@paypal.com>', 'paypal.com')), /^Sender name says/), false);
});

test('a brand spelled with Cyrillic letters in the sender name is serious', () => {
  const r = analyze(from('"P\u0430yP\u0430l" <service@example-vendor.com>', 'example-vendor.com'));
  assert.equal(find(r, /^Sender name says PayPal/).sev, 'bad');
  assert.ok(has(r, /^Sender name mixes alphabets/));
});

test('lookalike brand domains: letter pairs, digits and punycode', () => {
  assert.equal(find(analyze(from('Support <help@rnicrosoft.test>', 'rnicrosoft.test')), /^From domain imitates Microsoft/).sev, 'bad');
  assert.ok(has(analyze(from('Billing <bill@paypa1.test>', 'paypa1.test')), /^From domain imitates PayPal/));
  const puny = analyze(from('Service <service@xn--pypal-4ve.test>', 'xn--pypal-4ve.test'));
  const f = find(puny, /^From domain imitates PayPal/);
  assert.equal(f.cat, 'phish');
  assert.match(f.detail, /sent as xn--pypal-4ve.test/);
  assert.equal(C.skeleton(C.toUnicode('xn--pypal-4ve.test')), 'paypal.test');
});

test('lookalikes of your own domains: characters, a different ending and a cousin name', () => {
  assert.equal(find(analyze(from('A <a@examp1e.com>', 'examp1e.com'), 'example.com'), /^From domain imitates your domain example\.com/).sev, 'bad');
  assert.equal(find(analyze(from('A <a@example.net>', 'example.net'), 'example.com'), /imitates your domain/).sev, 'warn');
  assert.equal(find(analyze(from('A <a@example-billing.com>', 'example-billing.com'), 'example.com'), /^From domain borrows your name/).sev, 'warn');
  assert.equal(has(analyze(from('A <a@mail.example.com>', 'example.com'), 'example.com'), /imitates|borrows/), false);
});

test('a mixed-alphabet domain is serious; an all non-Latin international domain is a note', () => {
  const mixed = analyze(from('A <a@xn--exmple-shop-v8i.test>', 'xn--exmple-shop-v8i.test'));
  assert.ok(/[^\x00-\x7f]/.test(C.toUnicode('xn--exmple-shop-v8i.test')));
  assert.equal(find(mixed, /^From domain (mixes alphabets|is spelled with lookalike letters)/).sev, 'bad');
  const intl = analyze(from('A <a@xn--e1afmkfd.test>', 'xn--e1afmkfd.test'));
  assert.equal(find(intl, /^From domain uses international characters/).sev, 'info');
});

test('hidden characters in the sender or subject are warnings; a zero-width joiner in an emoji is not', () => {
  assert.equal(find(analyze(from('"Pay\u200BPal" <a@example-vendor.com>', 'example-vendor.com')), /^Hidden characters in the sender/).sev, 'warn');
  assert.equal(find(analyze(F.m365({ subject: 'Inv\u00ADoice due' })), /^Hidden characters in the subject/).sev, 'warn');
  assert.equal(has(analyze(F.m365({ subject: 'Team \u{1F468}\u200D\u{1F469}\u200D\u{1F467}' })), /^Hidden characters/), false);
});

test('a business or role name on free webmail is a warning; a personal name is not', () => {
  const r = analyze(from('"Accounts Payable" <ap.dept@gmail.com>', 'gmail.com'));
  assert.equal(find(r, /^Free webmail account using a business or role name/).cat, 'impersonation');
  assert.equal(has(analyze(from('"Jane Doe" <jane.doe@gmail.com>', 'gmail.com')), /^Free webmail/), false);
});

test('Reply-To: lookalike, free webmail, cousin, other domain, in that order of strength', () => {
  const rt = line => analyze(F.m365({ replyTo: `Reply-To: ${line}` }));
  assert.equal(find(rt('<billing@examp1e-vendor.test>'), /^Reply-To imitates the From domain/).sev, 'bad');
  assert.equal(find(rt('<payments.example@gmail.com>'), /^Replies go to a free webmail account/).sev, 'warn');
  assert.equal(find(rt('<accounts@example-vendor-payments.net>'), /^Reply-To uses a cousin of the From domain/).sev, 'warn');
  assert.equal(find(rt('<help@example.org>'), /^Reply-To goes to a different domain/).sev, 'warn');
  assert.equal(has(rt('<help@support.example-vendor.com>'), /Reply-To|Replies go/), false);
});

test('an IT-support sender name from outside your domains is flagged only when your domains are set', () => {
  const text = from('"IT Help Desk" <helpdesk@example-vendor.com>', 'example-vendor.com');
  assert.equal(find(analyze(text, 'example.com'), /^Sender name poses as IT or mail support/).cat, 'phish');
  assert.equal(has(analyze(text), /poses as IT/), false);
});

test('the sample headlines as possible impersonation because of its cousin Reply-To', () => {
  const r = analyze(C.SAMPLE);
  assert.equal(r.categories[0].title, 'Possible impersonation');
  assert.equal(r.categories[0].basis, 'inferred');
  assert.match(r.categories[0].support[0].title, /cousin of the From domain/);
});
