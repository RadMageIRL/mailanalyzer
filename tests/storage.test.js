// Browser storage: carrying settings over from the app's earlier names, without touching anyone else's data, and
// cleaning the recent list.
// SPDX-License-Identifier: MIT
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { C, F } = require('./helpers.js');

function store(init = {}) {
  const m = new Map(Object.entries(init));
  return { map: m, getItem: k => (m.has(k) ? m.get(k) : null), setItem: (k, v) => m.set(k, String(v)), removeItem: k => m.delete(k) };
}
const entry = (text, extra = {}) => ({ id: 'x', source: 'pasted', name: '', at: 1790000000000, from: 'a@example.com', subject: 's', text, ...extra });

test('settings saved under mops_ move to the new keys and the old keys are removed', () => {
  const s = store({ mops_theme: 'dark', mops_report: '{"redact":false}', mops_domains: 'example.com, mail*', mops_recent: JSON.stringify([entry('From: a@example.com\nSubject: s')]) });
  const moved = C.migrateStorage(s);
  assert.deepEqual(moved.sort(), ['mops_domains', 'mops_recent', 'mops_report', 'mops_theme']);
  assert.equal(s.getItem(C.KEYS.theme), 'dark');
  assert.deepEqual(JSON.parse(s.getItem(C.KEYS.report)), { redact: false, subject: false, notes: true, raw: false });
  assert.equal(s.getItem(C.KEYS.domains), 'example.com, mail*');
  assert.equal(JSON.parse(s.getItem(C.KEYS.recent)).length, 1);
  for (const k of ['mops_theme', 'mops_report', 'mops_domains', 'mops_recent']) assert.equal(s.getItem(k), null, k);
});

test('the older hops_ keys move too, and mops_ wins when both exist', () => {
  const s = store({ hops_theme: 'light', mops_theme: 'dark', hops_report: '{"notes":false}' });
  C.migrateStorage(s);
  assert.equal(s.getItem(C.KEYS.theme), 'dark');
  assert.equal(JSON.parse(s.getItem(C.KEYS.report)).notes, false);
  assert.equal(s.getItem('hops_theme'), null);
  assert.equal(s.getItem('mops_theme'), null);
});

test('a value already under the new key is kept, and the matching old key is cleared', () => {
  const s = store({ [C.KEYS.theme]: 'light', mops_theme: 'dark' });
  assert.deepEqual(C.migrateStorage(s), []);
  assert.equal(s.getItem(C.KEYS.theme), 'light');
  assert.equal(s.getItem('mops_theme'), null);
});

test('values that do not look like this app\'s are neither imported nor removed', () => {
  const foreign = { hops_theme: 'purple', mops_report: '{"fontSize":12}', hops_recent: '{"not":"a list"}', mops_recent: '[{"title":"someone else"}]', mops_domains: '<script>' };
  const s = store(foreign);
  assert.deepEqual(C.migrateStorage(s), []);
  for (const k of Object.values(C.KEYS)) assert.equal(s.getItem(k), null, k);
  for (const [k, v] of Object.entries(foreign)) assert.equal(s.getItem(k), v, k);
});

test('old recent entries are rebuilt from their header block, so a pasted body is dropped', () => {
  const s = store({ mops_recent: JSON.stringify([entry('From: a@example.com\nSubject: hi\n\nDear customer, your password is hunter2')]) });
  C.migrateStorage(s);
  const [item] = JSON.parse(s.getItem(C.KEYS.recent));
  assert.equal(item.text, 'From: a@example.com\nSubject: hi');
  assert.equal(item.id, C.hashText(item.text));
});

test('storage that throws on every call does not break the migration', () => {
  const broken = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); }, removeItem() { throw new Error('denied'); } };
  assert.doesNotThrow(() => C.migrateStorage(broken));
});

test('cleanRecent keeps valid entries, drops duplicates and junk, and caps the list', () => {
  const block = F.m365();
  const list = [entry(block), entry(block, { at: 1 }), { junk: true }, null, 'text', entry('not headers'), ...Array.from({ length: 40 }, (_, i) => entry(`X-N: ${i}`))];
  const clean = C.cleanRecent(list);
  assert.equal(clean.length, C.LIMITS.recentMax);
  assert.equal(clean[0].text, C.headerBlock(block));
  assert.equal(new Set(clean.map(x => x.id)).size, clean.length);
  assert.deepEqual(C.cleanRecent('nope'), []);
});

test('an entry with an unknown source is shown as pasted, and long strings are clipped', () => {
  const [x] = C.cleanRecent([entry('From: a@example.com', { source: '<img>', name: 'n'.repeat(1000), subject: 's'.repeat(5000) })]);
  assert.equal(x.source, 'pasted');
  assert.equal(x.name.length, 260);
  assert.equal(x.subject.length, 500);
});
